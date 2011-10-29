/* ---------------------------------------------------------------------------
 *  couriergrey - Greylisting filter for Courier
 *  Copyright (C) 2007-2011  Matthias Wimmer <m@tthias.eu>
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
#include <cstring>
#include <cerrno>
#include <iostream>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <cstdio>
#include <poll.h>
#include <glibmm.h>
#include <list>
#include <syslog.h>
#include <netinet/in.h>
#include <popt.h>

#define SOCKET_BACKLOG_SIZE 10

int main(int argc, char const** argv) {
    int do_version = 0;
    int dump_whitelist = 0;
    int dump_database = 0;
    int ret = 0;
    char const* socket_location = LOCALSTATEDIR "/lib/courier/allfilters/couriergrey";
    char const* whitelist_location = CONFIG_DIR "/whitelist_ip";

    struct poptOption options[] = {
	{ "version", 'v', POPT_ARG_NONE, &do_version, 0, N_("print server version"), NULL},
	{ "socket", 's', POPT_ARG_STRING, &socket_location, 0, N_("location of the filter domain socket"), "path"},
	{ "whitelist", 'w', POPT_ARG_STRING, &whitelist_location, 0, N_("location of the whitelist file"), "path"},
	{ "dumpwhitelist", 0, POPT_ARG_NONE, &dump_whitelist, 0, N_("dump the content of the parsed whitelist"), NULL},
	{ "dumpdatabase", 0, POPT_ARG_NONE, &dump_database, 0, N_("dump the content of the greylisting database"), NULL},
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

    // dump database if requested
    if (dump_database) {
	try {
	    couriergrey::timestore db;

	    std::cout << N_("Content of the greylist database:") << std::endl;

	    std::list<std::string> keys = db.get_keys();
	    for (std::list<std::string>::const_iterator p = keys.begin(); p != keys.end(); ++p) {
		std::cout << *p << std::endl;
		std::pair<std::time_t, std::time_t> times = db.fetch(*p);
		struct std::tm first_time_tm;
		gmtime_r(&times.first, &first_time_tm);
		struct std::tm last_time_tm;
		gmtime_r(&times.second, &last_time_tm);
		char first_time[128];
		char last_time[128];
		std::size_t first_time_size = strftime(first_time, sizeof(first_time), "%Y-%m-%dT%H:%M:%SZ", &first_time_tm);
		std::size_t last_time_size = strftime(last_time, sizeof(last_time), "%Y-%m-%dT%H:%M:%SZ", &last_time_tm);
		std::cout << "\t";
		if (first_time_size > 0) {
		    std::cout << first_time << " ";
		}
		if (last_time_size > 0) {
		    std::cout << last_time;
		}
		std::cout << std::endl;
	    }
	    return 0;
	} catch (Glib::ustring msg) {
	    std::cerr << msg << std::endl;
	    return 1;
	}
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
