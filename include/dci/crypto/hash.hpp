/* This file is part of the the dci project. Copyright (C) 2013-2021 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#pragma once

#include <dci/himpl.hpp>
#include <dci/crypto/implMetaInfo.hpp>
#include "api.hpp"
#include "hashPtr.hpp"
#include <string>
#include <vector>
#include <cstring>
#include <cstdint>

namespace dci::crypto
{
    class API_DCI_CRYPTO Hash
        : public himpl::FaceLayout<Hash, impl::Hash>
    {
    protected:
        Hash() = delete;
        Hash(const Hash&) = delete;
        Hash(Hash&&) = delete;

        Hash& operator=(const Hash&) = delete;
        Hash& operator=(Hash&&) = delete;

    public:
        Hash(himpl::FakeConstructionArg fc);
        ~Hash();

        HashPtr clone();

    public:
        std::size_t blockSize();
        std::size_t digestSize();
        void add(const void* data, std::size_t len);
        void barrier();
        void finish(void* digest);
        void finish(void* digest, std::size_t customDigestSize);
        void clear();

    public:

        template <class Char>
        requires(std::is_same_v<Char, char> || std::is_same_v<Char, unsigned char> || std::is_same_v<Char, signed char>)
        void add(const Char* csz);

        template<class Char, class... Params>
        requires(std::is_trivially_copyable_v<Char>)
        void add(const std::basic_string<Char, Params...>& v);

        template<class T, class... Params>
        requires(std::is_trivially_copyable_v<T>)
        void add(const std::vector<T, Params...>& v);

        template <class Pod>
        requires(std::is_trivially_copyable_v<Pod>)
        void add(const Pod& v);
    };

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    template <class Char>
    requires(std::is_same_v<Char, char> || std::is_same_v<Char, unsigned char> || std::is_same_v<Char, signed char>)
    void Hash::add(const Char* csz)
    {
        add(csz, std::strlen(csz));
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    template<class Char, class... Params>
    requires(std::is_trivially_copyable_v<Char>)
    void Hash::add(const std::basic_string<Char, Params...>& v)
    {
        return add(v.data(), v.size()*sizeof(Char));
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    template<class T, class... Params>
    requires(std::is_trivially_copyable_v<T>)
    void Hash::add(const std::vector<T, Params...>& v)
    {
        return add(v.data(), v.size()*sizeof(T));
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    template <class Pod>
    requires(std::is_trivially_copyable_v<Pod>)
    void Hash::add(const Pod& v)
    {
        return add(&v, sizeof(v));
    }

}
