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

#ifndef MAIL_PROCESSOR_H
#define MAIL_PROCESSOR_H

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <string>

#ifndef N_
#   define N_(n) (n)
#endif

namespace couriergrey {
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

#endif // MAIL_PROCESSOR_H
