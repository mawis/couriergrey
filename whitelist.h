/* ---------------------------------------------------------------------------
 *  couriergrey - Greylisting filter for Courier
 *  Copyright (C) 2007  Matthias Wimmer <m@tthias.eu>
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
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 * ---------------------------------------------------------------------------
 */

#ifndef WHITELIST_H
#define WHITELIST_H

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <stddef.h>
#include <string>
#include <glibmm.h>
#include <list>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef N_
#   define N_(n) (n)
#endif

namespace couriergrey {
    /**
     * class storing IP address ranges, that are whitelisted
     */
    class whitelist {
	public:
	    /**
	     * create a whitelist instance
	     */
	    whitelist(std::string const& whitelistfile);

	    /**
	     * check if an address is whitelisted
	     */
	    bool is_whitelisted(Glib::ustring const& address) const;

	    /**
	     * dump the whitelist to std::clog
	     */
	    void dump() const;

	private:
	    /**
	     * filename of the whitelist
	     */
	    std::string whitelistfile;

	    /**
	     * list of whitelisted addresses
	     */
	    std::list< std::pair<struct ::in6_addr, int> > whitelisted_addresses;

	    /**
	     * compare two IPv6 addresses if they are in the same network
	     */
	    bool is_in_same_net(struct ::in6_addr const& addr1, struct ::in6_addr const& addr2, int netsize) const;

	    /**
	     * convert textual address to IPv6 binary address
	     *
	     * @throws std::invalid_argument if address is not valid
	     */
	    struct ::in6_addr parse_address(Glib::ustring const& address) const;

	    /**
	     * parse the whitelist
	     */
	    void parse_whitelist();
    };
}

#endif // WHITELIST_H
