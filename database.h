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

#ifndef DATABASE_H
#define DATABASE_H

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include <string>
#include <list>

#include <gdbm.h>

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
	     * delete the value of a key
	     *
	     * @param key the key to delete
	     */
	    void del(std::string const& key);

	    /**
	     * reorganize (compact) the database
	     */
	    void reorganize();

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
}

#endif // DATABASE_H
