/* This file is part of the the dci project. Copyright (C) 2013-2023 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#pragma once

#include <cstdint>
#include "hash.hpp"
#include <array>

namespace dci::crypto::impl
{
    class Sha2_256 final
        : public Hash
    {
    public:
        Sha2_256(std::size_t digestSize);
        Sha2_256(const Sha2_256&);
        Sha2_256(Sha2_256&&);
        ~Sha2_256() override;

        Sha2_256& operator=(const Sha2_256&);
        Sha2_256& operator=(Sha2_256&&);

        HashPtr clone() override;

        std::size_t blockSize() override;
        void add(const void* data, std::size_t len) override;
        void barrier() override;
        void finish(void* digest) override;
        void finish(void* digest, std::size_t customDigestSize) override;
        void clear() override;

    private:
        void transform(const void* data);
        void transform(const std::uint32_t* data);

        std::array<std::uint32_t, 8>    _state;
        std::uint64_t                   _bitcount;
        std::array<std::uint8_t, 64>    _buffer;
    };
}
