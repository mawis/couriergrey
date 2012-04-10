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

#include "database.h"
#include <iostream>
#include <sys/stat.h>
#include <cstdio>
#include <stdexcept>
#include <glibmm.h>
#include <unistd.h>

namespace couriergrey {
    database::database() : db(NULL) {
	for (int retry = 0; db == NULL && retry < 10; retry++) {
	    db = ::gdbm_open(LOCALSTATEDIR "/cache/" PACKAGE "/deliveryattempts.gdbm", 0, GDBM_WRCREAT, S_IRUSR | S_IWUSR | S_IRGRP, 0);

	    if (db == NULL && retry < 9) {
		::sleep(1);
	    }
	}

	if (!db) {
	    throw Glib::ustring(N_("Could not open database at " LOCALSTATEDIR "/cache/" PACKAGE "/deliveryattempts.gdbm"));
	}
    }

    database::~database() {
	// close the database again
	if (db) {
	    ::gdbm_close(db);
	    db = NULL;
	}
    }

    std::string database::fetch(std::string const& key) const {
	// generate key
	::datum key_datum;
	key_datum.dptr = const_cast<char*>(key.c_str());
	key_datum.dsize = key.length();

	// get the entry for this key
	::datum value = ::gdbm_fetch(db, key_datum);

	// anything found?
	if (!value.dptr) {
	    return std::string();
	}

	// convert to string
	std::string result = std::string(value.dptr, value.dsize);

	// free memory
	std::free(value.dptr);

	// return result
	return result;
    }

    void database::store(std::string const& key, std::string const& value) {
	// generate key
	::datum key_datum;
	key_datum.dptr = const_cast<char*>(key.c_str());
	key_datum.dsize = key.length();

	// generate value
	::datum value_datum;
	value_datum.dptr = const_cast<char*>(value.c_str());
	value_datum.dsize = value.length();
	::gdbm_store(db, key_datum, value_datum, GDBM_REPLACE);
    }

    void database::reorganize() {
	::gdbm_reorganize(db);
    }

    void database::del(std::string const& key) {
	// generate key
	::datum key_datum;
	key_datum.dptr = const_cast<char*>(key.c_str());
	key_datum.dsize = key.length();

	// delete database entry
	::gdbm_delete(db, key_datum);
    }

    std::list<std::string> database::get_keys() {
	std::list<std::string> result;

	for (::datum key = ::gdbm_firstkey(db); key.dptr; key = ::gdbm_nextkey(db, key)) {
	    try {
		result.push_back(std::string(key.dptr, key.dsize));
	    } catch (std::length_error len_err) {
		std::cerr << "Length error!" << std::endl;
		std::cerr << "Length is: " << key.dsize << std::endl;
		std::cerr << "Key is: " << key.dptr << std::endl;
	    }
	}

	return result;
    }
}
