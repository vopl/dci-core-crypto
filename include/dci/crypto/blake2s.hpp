/* This file is part of the the dci project. Copyright (C) 2013-2023 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#pragma once

#include <dci/himpl.hpp>
#include <dci/crypto/implMetaInfo.hpp>
#include "api.hpp"
#include "hash.hpp"

namespace dci::crypto
{
    class API_DCI_CRYPTO Blake2s
        : public himpl::FaceLayout<Blake2s, impl::Blake2s, Hash>
    {
    public:
        static HashPtr alloc(std::size_t digestSize = 32);

    public:
        Blake2s(std::size_t digestSize = 32);
        Blake2s(const Blake2s&);
        Blake2s(Blake2s&&);
        ~Blake2s();

        Blake2s& operator=(const Blake2s&);
        Blake2s& operator=(Blake2s&&);

        HashPtr clone();

        std::size_t blockSize();
        std::size_t digestSize();
        using Hash::add;
        void add(const void* data, std::size_t len);
        void barrier();
        void finish(void* digest);
        void finish(void* digest, std::size_t customDigestSize);
        void clear();
    };

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void API_DCI_CRYPTO blake2s(const void* data, std::size_t len, void* digest, std::size_t digestSize = 32);
}
