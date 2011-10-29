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

#ifdef HAVE_CONFIG_H
#   include <config.h>
#endif

#include "timestore.h"
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
}
