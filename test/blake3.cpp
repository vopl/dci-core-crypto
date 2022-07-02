/* This file is part of the the dci project. Copyright (C) 2013-2022 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include <dci/test.hpp>
#include <dci/crypto.hpp>
#include <dci/utils/h2b.hpp>
#include <dci/utils/b2h.hpp>

#include <iostream>

using namespace dci::crypto;
using namespace dci::utils;

/////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
TEST(crypto, blake3)
{
    std::vector<uint8_t> digest(32);

    {
        Blake3 h;
        h.finish(digest.data());
        EXPECT_EQ(digest, h2b("fa31949b5f9f1a6a0a04d4ae63cd9c94b9bc529cda1c217bcca939ac4ef12326"));
    }

    {
        Blake3 h;
        h.add("The quick brown fox jumps over the lazy dog");
        h.finish(digest.data());
        EXPECT_EQ(digest, h2b("f2514181a1dacc9d31ba9dc4af9572105a86a62bf3d81ffd1f7b7401efcbd6a4"));
    }
}
