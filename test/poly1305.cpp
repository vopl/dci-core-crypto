/* This file is part of the the dci project. Copyright (C) 2013-2021 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include <dci/test.hpp>
#include <dci/crypto.hpp>
#include <dci/utils/h2b.hpp>

using namespace dci::crypto;
using namespace dci::utils;

/////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
TEST(crypto, poly1305)
{
    std::vector<uint8_t> digest(16);

    {
        Poly1305 h;
        h.setKey("", 0);
        h.add(h2b("00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        h.finish(digest.data());
        EXPECT_EQ(digest, h2b("00000000000000000000000000000000"));
    }

    {
        Poly1305 h;
        h.setKey("key", 3);
        h.add("The quick brown fox jumps over the lazy dog");
        h.finish(digest.data());
        EXPECT_EQ(digest, h2b("f690f6fdc3f27b60b12fbf2423fc21ad"));
    }
}
