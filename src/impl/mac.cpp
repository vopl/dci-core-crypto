/* This file is part of the the dci project. Copyright (C) 2013-2021 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include "mac.hpp"
#include <utility>

namespace dci::crypto::impl
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Mac::Mac(std::size_t digestSize)
        : Hash{digestSize}
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Mac::Mac(const Mac& from)
        : Hash{from}
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Mac::Mac(Mac&& from)
        : Hash{std::move(from)}
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Mac::~Mac()
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Mac& Mac::operator=(const Mac& from)
    {
        Hash::operator=(from);
        return *this;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Mac& Mac::operator=(Mac&& from)
    {
        Hash::operator=(std::move(from));
        return *this;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Mac::setKey(const void* key, std::size_t len)
    {
        (void)key;
        (void)len;
        //ok
    }
}
