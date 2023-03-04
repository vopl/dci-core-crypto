/* This file is part of the the dci project. Copyright (C) 2013-2023 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include <dci/crypto/streamCipher.hpp>
#include "impl/streamCipher.hpp"

namespace dci::crypto
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    StreamCipher::StreamCipher(himpl::FakeConstructionArg fc)
        : himpl::FaceLayout<StreamCipher, impl::StreamCipher>(fc)
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    StreamCipher::~StreamCipher()
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void StreamCipher::setKey(const void* key, std::size_t len)
    {
        return impl().setKey(key, len);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void StreamCipher::setIv(const void* iv, std::size_t len)
    {
        return impl().setIv(iv, len);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void StreamCipher::cipher(const void* in, void* out, std::size_t len)
    {
        return impl().cipher(in, out, len);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void StreamCipher::seek(std::uint64_t offset)
    {
        return impl().seek(offset);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void StreamCipher::clear()
    {
        return impl().clear();
    }
}
