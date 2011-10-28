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

#ifndef COURIERGREY_H
#define COURIERGREY_H

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <stddef.h>
#include <string>
#include <glibmm.h>
#include <list>

#include <popt.h>
#include <gdbm.h>

#include <netinet/in.h>

#ifndef N_
#   define N_(n) (n)
#endif

namespace couriergrey {
    /**
     * class storing the learned data
     */
    class database {
	public:
	    /**
	     * create a database instance
	     */
	    database();

	    /**
	     * destruct a database instance
	     */
	    ~database();

	    /**
	     * fetch a value from a key
	     */
	    std::string fetch(std::string const& key) const;

	    /**
	     * store a value to a key
	     */
	    void store(std::string const& key, std::string const& value);

	    /**
	     * get all the keys in the database
	     */
	    std::list<std::string> get_keys();
	private:
	    /**
	     * The GDMB database handle
	     */
	    ::GDBM_FILE db;
    };

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

    /**
     * a message_processor reads the filenames of a message from an accepted socket,
     * checks the message and gives back the greylisting response code on the socket
     *
     * @note you have to instantiate this class using the new operator as the
     * do_process() method will delete the instance using the delete operator when
     * finished.
     */
    class message_processor {
	public:
	    /**
	     * create a message_processor for an accepted domain socket
	     *
	     * @param fd the handle of the accepted domain socket
	     */
	    message_processor(int fd, whitelist const& used_whitelist);

	    /**
	     * do the actual processing
	     *
	     * This can be run in its own thread
	     */
	    void do_process();
	private:
	    /**
	     * the handle of the socket to process
	     */
	    int fd;

	    /**
	     * whitelist to use
	     */
	    whitelist const& used_whitelist;
    };

    /**
     * a mail_processor reads an email and searches for data that we are interested in
     *
     * This currently checks for the SPF state of the envelope sender
     */
    class mail_processor {
	public:
	    /**
	     * constructor
	     */
	    mail_processor() : spf_envelope_sender_state(none), authed(false) {}

	    /**
	     * the possible SPF states that could have been found
	     */
	    enum spf_state {
		pass,
		fail,
		softfail,
		neutral,
		none,
		temperror,
		permerror
	    };

	    /**
	     * read a mail from a file
	     */
	    void read_mail(const std::string& filename);

	    /**
	     * get the SPF state for the envelope sender
	     */
	    spf_state get_spf_envelope_sender_state() { return spf_envelope_sender_state; }

	    /**
	     * check if the mail has been received authenticated
	     */
	    bool is_authed() { return authed; }
	private:
	    /**
	     * the SPF state for the envelope sender we have read
	     */
	    spf_state spf_envelope_sender_state;

	    /**
	     * if the mail has been received on an authenticated connection
	     */
	    bool authed;
    };
}

#endif // COURIERGREY_H
