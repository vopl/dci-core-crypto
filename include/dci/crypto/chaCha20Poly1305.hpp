/* This file is part of the the dci project. Copyright (C) 2013-2022 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#pragma once

#include <dci/himpl.hpp>
#include <dci/crypto/implMetaInfo.hpp>
#include "api.hpp"

namespace dci::crypto
{
    class API_DCI_CRYPTO ChaCha20Poly1305
        : public himpl::FaceLayout<ChaCha20Poly1305, impl::ChaCha20Poly1305>
    {
    public:
        ChaCha20Poly1305();
        ChaCha20Poly1305(const ChaCha20Poly1305&);
        ChaCha20Poly1305(ChaCha20Poly1305&&);

        ChaCha20Poly1305& operator=(const ChaCha20Poly1305&);
        ChaCha20Poly1305& operator=(ChaCha20Poly1305&&);

        ~ChaCha20Poly1305();

    public:
        void setKey(const void* key, std::size_t len);
        void setAd(const void* ad, std::size_t len);

        void start(const void* nonce, std::size_t len);

        void encipher(const void* in, void* out, std::size_t len);
        void encipherFinish(void* macOut);

        void decipher(const void* in, void* out, std::size_t len);
        bool decipherFinish(const void* macIn);

        void clear();
    };
}
