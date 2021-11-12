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
TEST(crypto, ed25519)
{
    char secret[32] = "0123456789012345678901234567890";
    char pub[32];
    char msg[] = "The quick brown fox jumps over the lazy dog";
    char signature[64];

    ed25519::mkPublic(secret, pub);

    ed25519::sign(msg, sizeof(msg), pub, secret, signature);

    msg[0] = ~msg[0];
    EXPECT_FALSE(ed25519::verify(msg, sizeof(msg), pub, signature));
    msg[0] = ~msg[0];


    pub[0] = ~pub[0];
    EXPECT_FALSE(ed25519::verify(msg, sizeof(msg), pub, signature));
    pub[0] = ~pub[0];

    signature[0] = ~signature[0];
    EXPECT_FALSE(ed25519::verify(msg, sizeof(msg), pub, signature));
    signature[0] = ~signature[0];

    EXPECT_TRUE(ed25519::verify(msg, sizeof(msg), pub, signature));
}