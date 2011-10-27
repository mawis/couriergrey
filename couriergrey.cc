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

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "couriergrey.h"
#include <iostream>
#include <cstring>
#include <cerrno>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <cstdio>
#include <poll.h>
#include <glibmm.h>
#include <sstream>
#include <fstream>
#include <list>
#include <gdbm.h>
#include <ctime>
#include <syslog.h>
#include <netinet/in.h>
#include <stdexcept>

#define SOCKET_BACKLOG_SIZE 10

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

    void mail_processor::read_mail(const std::string& filename) {
	std::ifstream mail(filename.c_str());

	std::string header_value;
	bool first_received_header = true;
	while (std::getline(mail, header_value)) {
	    // check for end of header
	    if (header_value.length() == 0) {
		// empty line is end of header
		break;
	    }

	    // check if the header is continued in the next line
	    while (mail) {
		int peeked_character = mail.peek();

		if (peeked_character != ' ' and peeked_character != '\t') {
		    break;
		}

		std::string continuing_line;
		std::getline(mail, continuing_line);
		header_value += continuing_line;
	    }

	    // check if we got the first received header
	    if (first_received_header && header_value.substr(0, 9) == "Received:") {
		// has the message been received authenticated?
		if (header_value.find("(AUTH: ") != std::string::npos) {
		    authed = true;
		}

		// the next one isn't the first one anymore
		first_received_header = false;
	    }

	    // check if it's the SPF header we are looking for
	    // Note: normally we would have to do case-insensitve matching, but as the header is always
	    //       created by Courier we can just check for the casing that Courier uses.
	    //       Case-sensitve matching is faster ...
	    if (header_value.substr(0, 13) == "Received-SPF:" && header_value.find("SPF=MAILFROM;") != std::string::npos) {
		// okay ... we have to extract the SPF state
		std::istringstream header_stream(header_value.substr(13));
		std::string spf_state_string;
		header_stream >> spf_state_string;

		if (spf_state_string == "pass") {
		    spf_envelope_sender_state = pass;
		} else if (spf_state_string == "fail") {
		    spf_envelope_sender_state = fail;
		} else if (spf_state_string == "softfail") {
		    spf_envelope_sender_state = softfail;
		} else if (spf_state_string == "neutral") {
		    spf_envelope_sender_state = neutral;
		} else if (spf_state_string == "none") {
		    spf_envelope_sender_state = none;
		} else if (spf_state_string == "temperror") {	// seems not to be created by courier
		    spf_envelope_sender_state = temperror;
		} else if (spf_state_string == "permerror") {	// seems not to be created by courier
		    spf_envelope_sender_state = permerror;
		}
	    }
	}
    }

    message_processor::message_processor(int fd, whitelist const& used_whitelist) : fd(fd), used_whitelist(used_whitelist) {}

    void message_processor::do_process() {
	std::string data_from_socket;

	// read the filenames from the socket
	while (data_from_socket.find("\n\n") == std::string::npos) {
	    char buffer[1024];
	    ssize_t bytes_read = ::read(fd, buffer, sizeof(buffer));
	    if (bytes_read <= 0) {
		break;
	    }

	    data_from_socket += std::string(buffer, bytes_read);
	}

	// process the message
	std::istringstream files(data_from_socket);
	int filenum = 0;
	std::string one_file;
	bool authenticated_sender = false;
	std::string sender_address;
	std::string sending_mta;
	std::list<std::string> recipients;
	mail_processor mail;
	while (std::getline(files, one_file)) {
	    // the first line is the filename of the message file
	    if (!filenum++) {
		mail.read_mail(one_file);
		if (mail.is_authed()) {
		    authenticated_sender = true;
		}
		continue;
	    }

	    // skip the empty line at the end
	    if (one_file == "") {
		continue;
	    }

	    // if we reach here it's a control file, open it ...
	    std::ifstream infile(one_file.c_str());

	    // read the control file line by line
	    std::string one_line;
	    while (std::getline(infile, one_line)) {
		std::string linetype = one_line.substr(0, 1);

		// is this line indicating that the sender has had an authenticated connection?
		if (linetype == "i") {
		    authenticated_sender = true;
		    continue;
		}

		// is this line indicating the sender (envelope) address?
		if (linetype == "s") {
		    sender_address = one_line.substr(1);
		    continue;
		}

		// is this line the MTA the message has been received from?
		if (linetype == "f") {
		    sending_mta = one_line.substr(1);
		    continue;
		}

		// is this line indicating a recipient of the message?
		if (linetype == "r") {
		    recipients.push_back(one_line.substr(1));
		    continue;
		}
	    }

	    // we're done with this control file, close it ...
	    infile.close();
	}

	// is sender whitelisted?
	bool whitelisted = false;
        try {
            std::string address = sending_mta;
            std::string::size_type pos = address.find('[');
            if (pos != std::string::npos)
                address.erase(0, pos+1);
            pos = address.find(']');
            if (pos != std::string::npos)
                address.erase(pos, std::string::npos);
            whitelisted = used_whitelist.is_whitelisted(address);
        } catch (std::invalid_argument) {
            ::syslog(LOG_NOTICE, "Cannot parse sending MTA's address: %s", sending_mta.c_str());
        }

	// we should no have all data we need to check this message
	std::string response = "451 Default Response";

	// check if we can accept the message or if we should delay it
	if (authenticated_sender) {
	    // accept authenticated mails always
	    response = "200 Accepting authenticated mail";
	} else if (mail.get_spf_envelope_sender_state() == mail_processor::pass) {
	    // accept SPF authenticated senders
	    response = "200 Accepting this mail by SPF";
	} else if (sending_mta == "") {
	    // this should not be possible, if it happens courier's interface might have changed
	    response = "435 " PACKAGE " could not get the sending MTA's address.";
	} else if (whitelisted) {
	    // the sender has been whitelisted
	    response = "200 Whitelisted sender";
	} else if (recipients.size() < 1) {
	    // this should not be possible, if it happens courier's interface might have changed
	    response = "435 " PACKAGE " could not get the envelope recipient.";
	} else {
	    // do our actual magic of greylisting
	    
	    // extract the IP address from the sending_mta
	    std::string::size_type pos = sending_mta.rfind("(");
	    if (pos != std::string::npos) {
		sending_mta.erase(0, pos+1);
	    }
	    pos = sending_mta.find(")");
	    if (pos != std::string::npos) {
		sending_mta.erase(pos);
	    }
	    pos = sending_mta.rfind("[");
	    if (pos != std::string::npos) {
		sending_mta.erase(0, pos+1);
	    }
	    pos = sending_mta.find("]");
	    if (pos != std::string::npos) {
		sending_mta.erase(pos);
	    }
	    if (sending_mta.substr(0, 7) == "::ffff:") {
		sending_mta.erase(0, 7);
	    }

	    // calculate identifier for this connection
	    std::ostringstream mail_identifier;
	    mail_identifier << sender_address << "/" << sending_mta;
	    std::list<std::string>::const_iterator p;
	    for (p=recipients.begin(); p!=recipients.end(); ++p) {
		mail_identifier << "/" << *p;
	    }

	    // open the database (10 tries)
	    ::GDBM_FILE db = NULL;
	    for (int retry = 0; db == NULL && retry < 10; retry++) {
		db = ::gdbm_open(LOCALSTATEDIR "/cache/" PACKAGE "/deliveryattempts.gdbm", 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR | S_IRGRP, 0);

		if (db == NULL && retry < 9) {
		    ::sleep(1);
		}
	    }

	    // database open?
	    if (db == NULL) {
		// XXX log error

		response = "430 Greylisting DB could not be opened currently. Please try again later: ";
		response += ::gdbm_strerror(::gdbm_errno);
	    } else {
		::datum key;
		std::string mail_identifier_string = mail_identifier.str();
		key.dptr = const_cast<char*>(mail_identifier_string.c_str());
		key.dsize = mail_identifier_string.length();

		// check if we have an entry for this delivery attempt in the database
		::datum value = ::gdbm_fetch(db, key);

		// check when there has been the first delivery attempt for this mail
		std::time_t first_delivery = 0;
		if (value.dptr == NULL) {
		    // new mail, first attempt is now ...
		    first_delivery = std::time(NULL);
		} else {
		    // mail is already in the database, read first attempt from there
		    std::string value_string(value.dptr, value.dsize);
		    std::free(value.dptr);

		    std::istringstream value_stream(value_string);
		    value_stream >> first_delivery;
		}

		// write the new value (first attempt + last access for cleanup) to the database
		std::ostringstream value_stream;
		value_stream << first_delivery << " " << std::time(NULL);
		std::string value_string = value_stream.str();
		value.dptr = const_cast<char*>(value_string.c_str());
		value.dsize = value_string.length();
		::gdbm_store(db, key, value, GDBM_INSERT);

		// close the database again
		::gdbm_close(db);

		// check if the first attempt for this mail is old enough so that we can accept the mail
		std::time_t seconds_to_wait = (first_delivery + 120) - std::time(NULL);
		if (seconds_to_wait <= 0) {
		    response = "200 Thank you, we accept this e-mail.";
		} else {
		    std::ostringstream response_stream;
		    response_stream << "451 You are greylisted, please try again in " << seconds_to_wait << " s.";
		    response = response_stream.str();
		}
	    }
	}

	// append a linefeed to the result
	response += "\n";

	// write the result
	::write(fd, response.c_str(), response.length());

	// close the socket
	::close(fd);

	// free our instance again
	delete this;
    }
}

int main(int argc, char const** argv) {
    int do_version = 0;
    int dump_whitelist = 0;
    int ret = 0;
    char const* socket_location = LOCALSTATEDIR "/lib/courier/allfilters/couriergrey";
    char const* whitelist_location = CONFIG_DIR "/whitelist_ip";

    struct poptOption options[] = {
	{ "version", 'v', POPT_ARG_NONE, &do_version, 0, N_("print server version"), NULL},
	{ "socket", 's', POPT_ARG_STRING, &socket_location, 0, N_("location of the filter domain socket"), "path"},
	{ "whitelist", 'w', POPT_ARG_STRING, &whitelist_location, 0, N_("location of the whitelist file"), "path"},
	{ "dumpwhitelist", 0, POPT_ARG_NONE, &dump_whitelist, 0, N_("dump the content of the parsed whitelist"), NULL},
	POPT_AUTOHELP
	POPT_TABLEEND
    };

    // Init multithreading
    Glib::thread_init();

    // Open Logging
    ::openlog(PACKAGE, LOG_PID, LOG_MAIL);

    // parse command line options
    poptContext pCtx = poptGetContext(NULL, argc, argv, options, 0);
    while ((ret = poptGetNextOpt(pCtx)) >= 0) {
	switch (ret) {
	    // access argument by poptGetOptArg(pCtx)
	}
    }

    // error parsing command line?
    if (ret < -1) {
	std::cout << poptBadOption(pCtx, POPT_BADOPTION_NOALIAS) << ": " << poptStrerror(ret) << std::endl;
	::closelog();
	return 1;
    }

    // anything left?
    if (poptPeekArg(pCtx) != NULL) {
	// XXX i20n
	std::cout << N_("Invalid argument: ") << poptGetArg(pCtx) << std::endl;
	::closelog();
	return 1;
    }

    // print version information?
    if (do_version) {
	// XXX i20n
	std::cout << PACKAGE << N_(" version ") << VERSION << std::endl << std::endl;
	std::cout << N_("Used filter socket is: ") << socket_location << std::endl;
	std::cout << N_("Used whitelist is: ") << whitelist_location << std::endl;
	std::cout << N_("Database is: ") << LOCALSTATEDIR "/cache/" PACKAGE "/deliveryattempts.gdbm" << std::endl;
	::closelog();
	return 0;
    }

    // read whitelist
    couriergrey::whitelist used_whitelist(whitelist_location);

    // dump whitelist if requested
    if (dump_whitelist) {
	used_whitelist.dump();
	::closelog();
	return 0;
    }

    // open the domain socket
    int domain_socket = -1;
    {
	struct sockaddr_un addr;

	// calculate the temporary location where we create the socket
	std::string temp_location = socket_location;
	std::string::size_type last_slash = temp_location.rfind("/");
	if (last_slash == std::string::npos) {
	    temp_location.insert(0, ".");
	} else {
	    temp_location.insert(last_slash+1, ".");
	}

	// check length of the socket location
	if (temp_location.length() >= sizeof(addr.sun_path)) {
	    std::cerr << N_("Socket name to long: ") << temp_location << std::endl;
	    ::closelog();
	    return 1;
	}

	// unlink previously existing socket at the temp_location
	ret = ::unlink(temp_location.c_str());
	if (ret && errno != ENOENT) {
	    std::cerr << N_("Problem creating domain socket at location ") << temp_location << ": " << std::strerror(errno) << std::endl;
	    ::closelog();
	    return 1;
	}

	// create the domain socket
	domain_socket = ::socket(PF_UNIX, SOCK_STREAM, 0);
	if (domain_socket == -1) {
	    std::cerr << N_("Problem creating a unix domain socket: ") << std::strerror(errno) << std::endl;
	    ::closelog();
	    return 1;
	}

	// if we opened the socket on fd#3 we have not been called as courierfilter
	if (domain_socket == 3) {
	    ::close(domain_socket);
	    std::cerr << N_("This file is not intended to be called directly.") << std::endl;
	    ::closelog();
	    return 1;
	}

	// bind to the location
	std::memset(&addr, 0, sizeof(addr));
	addr.sun_family = AF_UNIX;
	std::strncpy(addr.sun_path, temp_location.c_str(), sizeof(addr.sun_path)-1);
	ret = ::bind(domain_socket, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
	if (ret) {
	    std::cerr << N_("Could not bind to socket ") << temp_location << ": " << std::strerror(errno) << std::endl;
	    ::closelog();
	    return 1;
	}

	// start listening on the socket
	ret = ::listen(domain_socket, SOCKET_BACKLOG_SIZE);
	if (ret) {
	    std::cerr << N_("Could not listen on socket ") << temp_location << ": " << std::strerror(errno) << std::endl;
	    ::closelog();
	    return 1;
	}

	// move socket to final location
	ret = std::rename(temp_location.c_str(), socket_location);
	if (ret) {
	    std::cerr << N_("Cannot move socket to its operating location ") << socket_location << ": " << std::strerror(errno) << std::endl;
	    ::closelog();
	    return 1;
	}
    }

    // close fd #3 to signal that we are ready
    ::close(3);

    // log that we are up
    ::syslog(LOG_INFO, "%s started and ready", PACKAGE);

    // start waiting for something to happen
    for (;;) {
	struct pollfd fds[2];

	for (int c=0; c<2; c++) {
	    std::memset(&fds[c], 0, sizeof(struct pollfd));
	}
	fds[0].fd = 0;
	fds[1].fd = domain_socket;
	fds[1].events = POLLIN;

	ret = ::poll(fds, 2, -1);
	if (ret < 0) {
	    std::cerr << N_("Error waiting for I/O events: ") << std::strerror(errno) << std::endl;
	    break;
	} else if (ret > 0) {
	    if (fds[0].revents & POLLHUP) {
		// stdin closed, we have to shutdown
		break;
	    }

	    if (fds[1].revents & POLLIN) {
		// new connection, accept it
		int accepted_connection = ::accept(domain_socket, NULL, 0);

		couriergrey::message_processor* processor = new couriergrey::message_processor(accepted_connection, used_whitelist);
		Glib::Thread::create(sigc::mem_fun(*processor, &couriergrey::message_processor::do_process), false);
	    }
	} else {
	    std::clog << "XXX Returned without event ..." << std::endl;
	}

    }

    // cleanup
    ::close(domain_socket);
    ::unlink(socket_location);

    // log that we are done
    ::syslog(LOG_INFO, "%s shut down", PACKAGE);

    // we're done
    ::closelog();
    return 0;
}
