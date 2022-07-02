/* This file is part of the the dci project. Copyright (C) 2013-2022 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include "devRandom.hpp"
#include "../../instance.hpp"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

namespace dci::crypto::rnd::entropy::source
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    bool DevRandom::available()
    {
        int fd = ::open(name().data(), O_RDONLY|O_NONBLOCK|O_CLOEXEC);

        if(0 <= fd)
        {
            while(0!=::close(fd) && EINTR == errno);

            return true;
        }

        return false;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    const std::string_view DevRandom::name()
    {
        return std::string_view("/dev/random");
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    DevRandom::DevRandom(Instance* instance)
        : Source{instance}
    {
        _fd = ::open(name().data(), O_RDONLY|O_NONBLOCK|O_CLOEXEC);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    DevRandom::~DevRandom()
    {
        if(0 <= _fd)
        {
            while(0!=::close(_fd) && EINTR == errno);
        }
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void DevRandom::flush()
    {
        std::uint8_t buf[32];

        ssize_t sreaded = read(_fd, buf, sizeof(buf));
        if(sreaded<=0)
        {
            return;
        }

        std::size_t readed = static_cast<std::size_t>(sreaded);
        _instance->addEntropy(buf, readed, readed);
    }
}
