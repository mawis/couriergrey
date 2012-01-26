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

#ifndef TIMESTORE_H
#define TIMESTORE_H

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <string>
#include <list>
#include <ctime>

#include <database.h>

#ifndef N_
#   define N_(n) (n)
#endif

namespace couriergrey {
    /**
     * class storing the learned data
     */
    class timestore {
	public:
	    /**
	     * create a timestore instance
	     */
	    timestore();

	    /**
	     * destruct a timestore instance
	     */
	    ~timestore();

	    /**
	     * fetch a value from a key
	     */
	    std::pair<std::time_t, std::time_t> fetch(std::string const& key) const;

	    /**
	     * store a value to a key
	     */
	    void store(std::string const& key, std::time_t first_connect, std::time_t last_connect);

	    /**
	     * expire old entires in the timestamp
	     *
	     * @param days number of days to keep
	     */
	    void expire(int days);

	    /**
	     * get all the keys in the timestore
	     */
	    std::list<std::string> get_keys();
	private:
	    /**
	     * The database we use
	     */
	    database db;
    };
}

#endif // TIMESTORE_H
