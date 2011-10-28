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

#ifndef MESSAGE_PROCESSOR_H
#define MESSAGE_PROCESSOR_H

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <whitelist.h>

#ifndef N_
#   define N_(n) (n)
#endif

namespace couriergrey {
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
}

#endif // MESSAGE_PROCESSOR_H
