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

#include "message_processor.h"
#include "timestore.h"
#include "mail_processor.h"
#include <iostream>
#include <cstring>
#include <unistd.h>
#include <cstdio>
#include <glibmm.h>
#include <sstream>
#include <fstream>
#include <list>
#include <ctime>
#include <syslog.h>
#include <stdexcept>

namespace couriergrey {
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

	    // open the database
	    try {
		timestore db;

		std::string mail_identifier_string = mail_identifier.str();

		// check when there has been the first delivery attempt for this mail
		std::pair<std::time_t, std::time_t> value = db.fetch(mail_identifier_string);
		std::time_t first_delivery = value.first;

		// update the content (first attempt + last access for cleanup) in the database
		db.store(mail_identifier_string, first_delivery, std::time(NULL));

		// check if the first attempt for this mail is old enought so that we can accept the mail
		std::time_t seconds_to_wait = (first_delivery + 120) - std::time(NULL);
		if (seconds_to_wait <= 0) {
		    response = "200 Thank you, we accept this e-mail.";
		} else {
		    std::ostringstream response_stream;
		    response_stream << "451 You are greylisted, please try again in " << seconds_to_wait << " s.";
		    response = response_stream.str();
		}
	    } catch (Glib::ustring msg) {
		response = "430 Greylisting DB could not be opened currently. Please try again later: ";
		response += msg;
	    }
	}

	// append a linefeed to the result
	response += "\n";

	// write the result
	ssize_t written = ::write(fd, response.c_str(), response.length());

	// close the socket
	::close(fd);

	// free our instance again
	delete this;
    }
}
