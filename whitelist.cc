/* ---------------------------------------------------------------------------
 *  couriergrey - Greylisting filter for Courier
 *  Copyright (C) 2007-2012  Matthias Wimmer <m@tthias.eu>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU Library General Public
 *  License along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301,
 *  USA.
 * ---------------------------------------------------------------------------
 * vi: sw=4:tabstop=8
 */

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "whitelist.h"
#include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <cstdio>
#include <poll.h>
#include <glibmm.h>
#include <sstream>
#include <fstream>
#include <list>
#include <syslog.h>
#include <netinet/in.h>
#include <stdexcept>

namespace couriergrey {
    void whitelist::dump() const {
	std::clog << "Dumping parsed whitelist:" << std::endl;
	for (std::list<std::pair<struct ::in6_addr, int> >::const_iterator p = whitelisted_addresses.begin(); p!= whitelisted_addresses.end(); ++p) {
	    char address[INET6_ADDRSTRLEN];

	    ::inet_ntop(AF_INET6, &(p->first), address, sizeof(address));

	    std::clog << address << "/" << (p->second) << std::endl;
	}

	std::clog << "***** END *****" << std::endl;
    }

    whitelist::whitelist(std::string const& whitelistfile) : whitelistfile(whitelistfile) {
	parse_whitelist();
    }

    bool whitelist::is_whitelisted(Glib::ustring const& address) const {
	// convert address
	struct ::in6_addr parsed_address = parse_address(address);

	// check if any whitelist entry matches
	for (std::list<std::pair<struct ::in6_addr, int> >::const_iterator p = whitelisted_addresses.begin(); p!= whitelisted_addresses.end(); ++p) {
	    if (is_in_same_net(parsed_address, p->first, p->second))
		return true;
	}

	return false;
    }

    bool whitelist::is_in_same_net(struct ::in6_addr const& addr1, struct ::in6_addr const& addr2, int netsize) const {
	int i = 0;

	if (netsize > 128 || netsize < 0)
	    throw std::invalid_argument("invalid netsize");

	for (i = 0; i < netsize/8; i++) {
	    if (addr1.s6_addr[i] != addr2.s6_addr[i])
		return false;
	}

	if (netsize%8 == 0)
	    return true;

	u_int8_t mask = 0xff << (8 - netsize%8);

	return ((addr1.s6_addr[i]&mask) == (addr2.s6_addr[i]&mask));
    }

    struct ::in6_addr whitelist::parse_address (Glib::ustring const& address) const {
	// first try to parse as IPv6 address
	struct ::in6_addr parsed_address;
	if (::inet_pton(AF_INET6, address.c_str(), &parsed_address) <= 0) {
	    // not an IPv6 address, try as IPv4 address
	    Glib::ustring mapped_ipv4 = "::ffff:";
	    mapped_ipv4 += address;
	    if (::inet_pton(AF_INET6, mapped_ipv4.c_str(), &parsed_address) <= 0) {
		throw std::invalid_argument("not a valid IPv4 or IPv6 address");
	    }
	}

	return parsed_address;
    }

    void whitelist::parse_whitelist() {
	std::ifstream wlfile(whitelistfile.c_str());

	while (wlfile) {
	    // get a line from the whitelist file
	    std::string line;
	    std::getline(wlfile, line);

	    // remove comments
	    std::string::size_type comment_start;
	    comment_start = line.find('#');
	    if (comment_start != std::string::npos) {
		line.erase(comment_start, std::string::npos);
	    }

	    // trim
	    std::string::size_type first_nws = line.find_first_not_of(" \t");
	    if (first_nws == std::string::npos)
		continue;
	    line.erase(0, first_nws);
	    std::string::size_type last_nws = line.find_last_not_of(" \t");
	    if (last_nws == std::string::npos)
		continue;
	    line.erase(last_nws+1, std::string::npos);

	    // address or net? Calculate netsize ...
	    int netsize = 128;
	    std::string::size_type netsize_pos = line.find('/');
	    if (netsize_pos != std::string::npos) {
		// parse network size
		std::istringstream netsize_stream(line.substr(netsize_pos+1));
		netsize_stream >> netsize;

		// remove network size for further processing
		line.erase(netsize_pos);
	    }

	    // shortened form of IPv4 class A, B or C networks? (only if no IPv6 address an no netsize given)
	    if (netsize_pos == std::string::npos && line.find(':') == std::string::npos) {
		int separator_count = 0;
		for (std::string::size_type temp_pos = line.find('.'); temp_pos != std::string::npos; temp_pos = line.find('.', temp_pos+1)) {
		    separator_count++;
		}

		// extend to full IPv4 address and update network size
		if (separator_count >= 0 && separator_count < 3) {
		    netsize -= 8*(3-separator_count);

		    for (int i=separator_count; i<3; i++) {
			line += ".0";
		    }
		}
	    }

	    // line should now be an address
	    try {
		struct ::in6_addr parsed_address = parse_address(line);

		// we may have to correct the netsize for IPv4 addresses if they have been specified in the range 0 ... 32
		if (IN6_IS_ADDR_V4MAPPED(&parsed_address)) {
		    if (netsize <= 32) {
			netsize += 128-32;
		    }
		}

		// limit valid range of netsizes
		if (netsize < 0)
		    netsize = 0;
		if (netsize > 128)
		    netsize = 128;

		// remember the address
		std::pair<struct ::in6_addr, int> new_address_mask_pair(parsed_address, netsize);
		whitelisted_addresses.push_back(new_address_mask_pair);
	    } catch (std::invalid_argument iae) {
		::syslog(LOG_INFO, "read whitelist line, which could not be parsed as address, skipping: %s", line.c_str());
	    }
	}

	wlfile.close();
    }
}
