/* This file is part of the the dci project. Copyright (C) 2013-2023 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include "std.hpp"
#include "../../instance.hpp"

namespace dci::crypto::rnd::entropy::source
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    bool Std::available()
    {
        return true;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    const std::string_view Std::name()
    {
        return std::string_view("std::random_device{}");
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Std::Std(Instance* instance)
        : Source{instance}
        , _rd{}
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Std::~Std()
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Std::flush()
    {
        std::random_device::result_type buf[32 / sizeof(std::random_device::result_type)];

        for(std::random_device::result_type& part : buf)
            part = _rd();

        _instance->addEntropy(buf, sizeof(buf), _rd.entropy() ? sizeof(buf) : 0);
    }
}
