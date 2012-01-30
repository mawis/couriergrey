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

#include "timestore.h"
#include <iostream>
#include <sstream>

namespace couriergrey {
 
    timestore::timestore() {
    }

    timestore::~timestore() {
    }

    std::pair<std::time_t, std::time_t> timestore::fetch(std::string const& key) const {
	std::string database_value = db.fetch(key);

	if (database_value.empty()) {
	    std::time_t now = std::time(NULL);
	    return std::pair<std::time_t, std::time_t>(now, now);
	}

	std::istringstream value_stream(database_value);
	
	std::time_t first_connect;
	std::time_t last_connect;

	value_stream >> first_connect;
	value_stream >> last_connect;

	return std::pair<std::time_t, std::time_t>(first_connect, last_connect);
    }

    void timestore::store(std::string const& key, std::time_t first_connect, std::time_t last_connect) {
	std::ostringstream value_stream;
	value_stream << first_connect << ' ' << last_connect;
	db.store(key, value_stream.str());
    }

    std::list<std::string> timestore::get_keys() {
	return db.get_keys();
    }

    void timestore::expire(int days) {
	std::time_t now = std::time(NULL);

	std::list<std::string> const keys = get_keys();
	for (std::list<std::string>::const_iterator p = keys.begin(); p != keys.end(); ++p) {
	    std::pair<std::time_t, std::time_t> times = fetch(*p);

	    if (now - times.second > days * 86400) {
		std::cout << "Expiring: " << *p << std::endl;
		db.del(*p);
	    }
	}

	db.reorganize();
    }
}
