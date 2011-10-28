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

#include "mail_processor.h"
#include <cstring>
#include <sstream>
#include <fstream>

namespace couriergrey {
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
}
