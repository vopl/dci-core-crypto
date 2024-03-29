/* This file is part of the the dci project. Copyright (C) 2013-2023 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include "rdrand.hpp"
#include "../../instance.hpp"
#include <cpuid.h>
#include <immintrin.h>

namespace dci::crypto::rnd::entropy::source
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    bool RDRAND::available()
    {
        std::uint32_t eax, ebx, ecx, edx;
        __cpuid (1, eax, ebx, ecx, edx);
        return ecx & bit_RDRND;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    const std::string_view RDRAND::name()
    {
        return std::string_view("RDRAND");
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void RDRAND::flush()
    {
        std::uint64_t buf[4];
        std::size_t cnt = 0;
        std::size_t fails = 0;
        while(cnt<4)
        {
            char ok = 0;
            asm volatile ("rdrand %0; setc %b1" : "=r"(buf[cnt]), "=qm"(ok) :: "cc");

            if(ok)
            {
                cnt++;
                fails = 0;
            }
            else
            {
                fails++;
                if(fails > 10)
                {
                    break;
                }
            }
        }

        if(cnt)
        {
            _instance->addEntropy(buf, sizeof(buf[0])*cnt, 1);
        }
    }
}
