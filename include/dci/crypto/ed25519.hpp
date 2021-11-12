/* This file is part of the the dci project. Copyright (C) 2013-2021 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#pragma once

#include "api.hpp"
#include <cstdint>

namespace dci::crypto::ed25519
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void API_DCI_CRYPTO mkPublic(
            const void* sk,
            void* pk);

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void API_DCI_CRYPTO sign(
            const void* message, std::uint32_t messageLen,
            const void* pk, const void* sk,
            void* signature);

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    bool API_DCI_CRYPTO verify(
            const void* message, std::uint32_t messageLen,
            const void* pk,
            const void* signature);
}
