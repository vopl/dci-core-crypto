/* This file is part of the the dci project. Copyright (C) 2013-2021 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include <dci/crypto/hash.hpp>
#include "impl/hash.hpp"

namespace dci::crypto
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Hash::Hash(himpl::FakeConstructionArg fc)
        : himpl::FaceLayout<Hash, impl::Hash>(fc)
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Hash::~Hash()
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    HashPtr Hash::clone()
    {
        return impl().clone();
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    std::size_t Hash::blockSize()
    {
        return impl().blockSize();
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    std::size_t Hash::digestSize()
    {
        return impl().digestSize();
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Hash::add(const void* data, std::size_t len)
    {
        return impl().add(data, len);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Hash::barrier()
    {
        return impl().barrier();
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Hash::finish(void* digest)
    {
        return impl().finish(digest);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Hash::finish(void* digest, std::size_t customDigestSize)
    {
        return impl().finish(digest, customDigestSize);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Hash::clear()
    {
        return impl().clear();
    }

}
