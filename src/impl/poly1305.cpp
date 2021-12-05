/* This file is part of the the dci project. Copyright (C) 2013-2021 vopl, shtoba.
   This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public
   License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
   This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty
   of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.
   You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>. */

#include "poly1305.hpp"
#include <dci/crypto/poly1305.hpp>
#include <dci/utils/endian.hpp>
#include <dci/utils/dbg.hpp>

namespace dci::crypto::impl
{
    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Poly1305::Poly1305()
        : Mac{16}
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Poly1305::Poly1305(const Poly1305& from)
        : Mac{from}
    {
        _poly = from._poly;
        _buf = from._buf;
        _bufPos = from._bufPos;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Poly1305::Poly1305(Poly1305&& from)
        : Mac{std::move(from)}
    {
        _poly = from._poly;
        _buf = from._buf;
        _bufPos = from._bufPos;
        from.clear();
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Poly1305::~Poly1305()
    {
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Poly1305& Poly1305::operator=(const Poly1305& from)
    {
        Mac::operator=(from);
        _poly = from._poly;
        _buf = from._buf;
        _bufPos = from._bufPos;
        return *this;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    Poly1305& Poly1305::operator=(Poly1305&& from)
    {
        Mac::operator=(std::move(from));
        _poly = from._poly;
        _buf = from._buf;
        _bufPos = from._bufPos;
        from.clear();
        return *this;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    HashPtr Poly1305::clone()
    {
        return HashPtr
        {
            new crypto::Poly1305{himpl::impl2Face<crypto::Poly1305>(*this)},
            [](crypto::Hash* p){delete static_cast<crypto::Poly1305*>(p);}
        };
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    std::size_t Poly1305::blockSize()
    {
        return 64;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Poly1305::setKey(const void* key, std::size_t len)
    {
        _bufPos = 0;

        uint64_t key8[4] = {};
        memcpy(key8, key, std::min(len, std::size_t{32}));

        /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
        const uint64_t t0 = dci::utils::endian::n2l(key8[0]);
        const uint64_t t1 = dci::utils::endian::n2l(key8[1]);

        _poly[0] = ( t0                    ) & 0xffc0fffffff;
        _poly[1] = ((t0 >> 44) | (t1 << 20)) & 0xfffffc0ffff;
        _poly[2] = ((t1 >> 24)             ) & 0x00ffffffc0f;

        /* h = 0 */
        _poly[3] = 0;
        _poly[4] = 0;
        _poly[5] = 0;

        /* save pad for later */
        _poly[6] = dci::utils::endian::n2l(key8[2]);
        _poly[7] = dci::utils::endian::n2l(key8[3]);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Poly1305::add(const void* data, std::size_t len)
    {
        const uint8_t* input = static_cast<const uint8_t*>(data);

        if(_bufPos)
        {
            std::size_t toCopy = std::min(_buf.size()-_bufPos, len);
            memcpy(_buf.data()+_bufPos, input, toCopy);
            _bufPos += toCopy;
            input += toCopy;
            len -= toCopy;

            if(_bufPos >= _buf.size())
            {
                blocks(_buf.data(), 1);
                input += (_buf.size() - _bufPos);
                len -= (_buf.size() - _bufPos);
                _bufPos = 0;
            }
        }

        const size_t fullBlocks = len / _buf.size();
        const size_t remaining   = len % _buf.size();

        if(fullBlocks)
        {
            blocks(input, fullBlocks);
        }

        memcpy(_buf.data()+_bufPos, input + fullBlocks * _buf.size(), remaining);
        _bufPos += remaining;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Poly1305::barrier()
    {
        std::array<uint8_t, 16> digest;

        {
            Poly1305 clone = *this;
            clone.finish(digest.data());
        }

        add(digest.data(), digest.size());
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Poly1305::finish(void* digest)
    {
        finish(digest, _digestSize);
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Poly1305::finish(void* digest, std::size_t customDigestSize)
    {
        if(_bufPos != 0)
        {
            _buf[_bufPos] = 1;
            const size_t len = _buf.size() - _bufPos - 1;
            if(len > 0)
            {
                memset(&_buf[_bufPos+1], 0, len);
            }
            blocks(_buf.data(), 1, true);
        }

        const uint64_t M44 = 0xFFFFFFFFFFF;
        const uint64_t M42 = 0x3FFFFFFFFFF;

        /* fully carry h */
        uint64_t h0 = _poly[3+0];
        uint64_t h1 = _poly[3+1];
        uint64_t h2 = _poly[3+2];

        uint64_t c;
                     c = (h1 >> 44); h1 &= M44;
        h2 += c;     c = (h2 >> 42); h2 &= M42;
        h0 += c * 5; c = (h0 >> 44); h0 &= M44;
        h1 += c;     c = (h1 >> 44); h1 &= M44;
        h2 += c;     c = (h2 >> 42); h2 &= M42;
        h0 += c * 5; c = (h0 >> 44); h0 &= M44;
        h1 += c;

        /* compute h + -p */
        uint64_t g0 = h0 + 5; c = (g0 >> 44); g0 &= M44;
        uint64_t g1 = h1 + c; c = (g1 >> 44); g1 &= M44;
        uint64_t g2 = h2 + c - (static_cast<uint64_t>(1) << 42);

        /* select h if h < p, or h + -p if h >= p */
        c = (g2 >> ((sizeof(unsigned long long) * 8) - 1)) - 1;
        g0 &= c;
        g1 &= c;
        g2 &= c;
        c = ~c;
        h0 = (h0 & c) | g0;
        h1 = (h1 & c) | g1;
        h2 = (h2 & c) | g2;

        /* h = (h + pad) */
        const uint64_t t0 = _poly[6];
        const uint64_t t1 = _poly[7];

        h0 += (( t0                    ) & M44)    ; c = (h0 >> 44); h0 &= M44;
        h1 += (((t0 >> 44) | (t1 << 20)) & M44) + c; c = (h1 >> 44); h1 &= M44;
        h2 += (((t1 >> 24)             ) & M42) + c;                 h2 &= M42;

        /* mac = h % (2^128) */
        h0 = ((h0      ) | (h1 << 44));
        h1 = ((h1 >> 20) | (h2 << 24));

        std::uint64_t result[2];
        result[0] = dci::utils::endian::n2l(h0);
        result[1] = dci::utils::endian::n2l(h1);

        memcpy(digest, result, std::min(customDigestSize, _digestSize));

        clear();
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Poly1305::clear()
    {
        _poly = std::array<uint64_t, 8>{};
        _buf = std::array<uint8_t, 16>{};
        _bufPos = 0;
    }

    /////////0/////////1/////////2/////////3/////////4/////////5/////////6/////////7
    void Poly1305::blocks(const void* m, std::size_t blocks, bool is_final)
    {
        const uint64_t* m8 = static_cast<const uint64_t*>(m);

        typedef unsigned uint128_t __attribute__((mode(TI)));

        const uint64_t hibit = is_final ? 0 : (static_cast<uint64_t>(1) << 40); /* 1 << 128 */

        const uint64_t r0 = _poly[0];
        const uint64_t r1 = _poly[1];
        const uint64_t r2 = _poly[2];

        const uint64_t M44 = 0xFFFFFFFFFFF;
        const uint64_t M42 = 0x3FFFFFFFFFF;

        uint64_t h0 = _poly[3+0];
        uint64_t h1 = _poly[3+1];
        uint64_t h2 = _poly[3+2];

        const uint64_t s1 = r1 * 20;
        const uint64_t s2 = r2 * 20;

        for(size_t i = 0; i != blocks; ++i)
        {
            const uint64_t t0 = dci::utils::endian::n2l(m8[0]);
            const uint64_t t1 = dci::utils::endian::n2l(m8[1]);

            h0 += (( t0                    ) & M44);
            h1 += (((t0 >> 44) | (t1 << 20)) & M44);
            h2 += (((t1 >> 24)             ) & M42) | hibit;

            const uint128_t d0 = uint128_t(h0) * r0 + uint128_t(h1) * s2 + uint128_t(h2) * s1;
            const uint64_t c0 = static_cast<uint64_t>(d0 >> 44);

            const uint128_t d1 = uint128_t(h0) * r1 + uint128_t(h1) * r0 + uint128_t(h2) * s2 + c0;
            const uint64_t c1 = static_cast<uint64_t>(d1 >> 44);

            const uint128_t d2 = uint128_t(h0) * r2 + uint128_t(h1) * r1 + uint128_t(h2) * r0 + c1;
            const uint64_t c2 = static_cast<uint64_t>(d2 >> 42);

            h0 = d0 & M44;
            h1 = d1 & M44;
            h2 = d2 & M42;

            h0 += c2 * 5;
            h1 += uint128_t{h0} >> 44;
            h0 = h0 & M44;
            m8 += 2;
        }

        _poly[3+0] = h0;
        _poly[3+1] = h1;
        _poly[3+2] = h2;
    }
}

/*
☀	9728	☀	2600	 	BLACK SUN WITH RAYS
☁	9729	☁	2601	 	CLOUD
☂	9730	☂	2602	 	UMBRELLA
☃	9731	☃	2603	 	SNOWMAN
☄	9732	☄	2604	 	COMET
★	9733	★	2605	 	BLACK STAR
☆	9734	☆	2606	 	WHITE STAR
☇	9735	☇	2607	 	LIGHTNING
☈	9736	☈	2608	 	THUNDERSTORM
☉	9737	☉	2609	 	SUN
☊	9738	☊	260A	 	ASCENDING NODE
☋	9739	☋	260B	 	DESCENDING NODE
☌	9740	☌	260C	 	CONJUNCTION
☍	9741	☍	260D	 	OPPOSITION
☎	9742	☎	260E	 	BLACK TELEPHONE
☏	9743	☏	260F	 	WHITE TELEPHONE
☐	9744	☐	2610	 	BALLOT BOX
☑	9745	☑	2611	 	BALLOT BOX WITH CHECK
☒	9746	☒	2612	 	BALLOT BOX WITH X
☓	9747	☓	2613	 	SALTIRE
☔	9748	☔	2614	 	UMBRELLA WITH RAIN DROPS
☕	9749	☕	2615	 	HOT BEVERAGE
☖	9750	☖	2616	 	WHITE SHOGI PIECE
☗	9751	☗	2617	 	BLACK SHOGI PIECE
☘	9752	☘	2618	 	SHAMROCK
☙	9753	☙	2619	 	REVERSED ROTATED FLORAL HEART BULLET
☚	9754	☚	261A	 	BLACK LEFT POINTING INDEX
☛	9755	☛	261B	 	BLACK RIGHT POINTING INDEX
☜	9756	☜	261C	 	WHITE LEFT POINTING INDEX
☝	9757	☝	261D	 	WHITE UP POINTING INDEX
☞	9758	☞	261E	 	WHITE RIGHT POINTING INDEX
☟	9759	☟	261F	 	WHITE DOWN POINTING INDEX
☠	9760	☠	2620	 	SKULL AND CROSSBONES
☡	9761	☡	2621	 	CAUTION SIGN
☢	9762	☢	2622	 	RADIOACTIVE SIGN
☣	9763	☣	2623	 	BIOHAZARD SIGN
☤	9764	☤	2624	 	CADUCEUS
☥	9765	☥	2625	 	ANKH
☦	9766	☦	2626	 	ORTHODOX CROSS
☧	9767	☧	2627	 	CHI RHO
☨	9768	☨	2628	 	CROSS OF LORRAINE
☩	9769	☩	2629	 	CROSS OF JERUSALEM
☪	9770	☪	262A	 	STAR AND CRESCENT
☫	9771	☫	262B	 	FARSI SYMBOL
☬	9772	☬	262C	 	ADI SHAKTI
☭	9773	☭	262D	 	HAMMER AND SICKLE
☮	9774	☮	262E	 	PEACE SYMBOL
☯	9775	☯	262F	 	YIN YANG
☰	9776	☰	2630	 	TRIGRAM FOR HEAVEN
☱	9777	☱	2631	 	TRIGRAM FOR LAKE
☲	9778	☲	2632	 	TRIGRAM FOR FIRE
☳	9779	☳	2633	 	TRIGRAM FOR THUNDER
☴	9780	☴	2634	 	TRIGRAM FOR WIND
☵	9781	☵	2635	 	TRIGRAM FOR WATER
☶	9782	☶	2636	 	TRIGRAM FOR MOUNTAIN
☷	9783	☷	2637	 	TRIGRAM FOR EARTH
☸	9784	☸	2638	 	WHEEL OF DHARMA
☹	9785	☹	2639	 	WHITE FROWNING FACE
☺	9786	☺	263A	 	WHITE SMILING FACE (present in WGL4)
☻	9787	☻	263B	 	BLACK SMILING FACE (present in WGL4)
☼	9788	☼	263C	 	WHITE SUN WITH RAYS (present in WGL4)
☽	9789	☽	263D	 	FIRST QUARTER MOON
☾	9790	☾	263E	 	LAST QUARTER MOON
☿	9791	☿	263F	 	MERCURY
♀	9792	♀	2640	 	FEMALE SIGN (present in WGL4)
♁	9793	♁	2641	 	EARTH
♂	9794	♂	2642	 	MALE SIGN (present in WGL4)
♃	9795	♃	2643	 	JUPITER
♄	9796	♄	2644	 	SATURN
♅	9797	♅	2645	 	URANUS
♆	9798	♆	2646	 	NEPTUNE
♇	9799	♇	2647	 	PLUTO
♈	9800	♈	2648	 	ARIES
♉	9801	♉	2649	 	TAURUS
♊	9802	♊	264A	 	GEMINI
♋	9803	♋	264B	 	CANCER
♌	9804	♌	264C	 	LEO
♍	9805	♍	264D	 	VIRGO
♎	9806	♎	264E	 	LIBRA
♏	9807	♏	264F	 	SCORPIUS
♐	9808	♐	2650	 	SAGITTARIUS
♑	9809	♑	2651	 	CAPRICORN
♒	9810	♒	2652	 	AQUARIUS
♓	9811	♓	2653	 	PISCES
♔	9812	♔	2654	 	WHITE CHESS KING
♕	9813	♕	2655	 	WHITE CHESS QUEEN
♖	9814	♖	2656	 	WHITE CHESS ROOK
♗	9815	♗	2657	 	WHITE CHESS BISHOP
♘	9816	♘	2658	 	WHITE CHESS KNIGHT
♙	9817	♙	2659	 	WHITE CHESS PAWN
♚	9818	♚	265A	 	BLACK CHESS KING
♛	9819	♛	265B	 	BLACK CHESS QUEEN
♜	9820	♜	265C	 	BLACK CHESS ROOK
♝	9821	♝	265D	 	BLACK CHESS BISHOP
♞	9822	♞	265E	 	BLACK CHESS KNIGHT
♟	9823	♟	265F	 	BLACK CHESS PAWN
♠	9824	♠	2660	&spades; (♠)	BLACK SPADE SUIT (present in WGL4 and in Symbol font)
♡	9825	♡	2661	 	WHITE HEART SUIT
♢	9826	♢	2662	 	WHITE DIAMOND SUIT
♣	9827	♣	2663	&clubs; (♣)	BLACK CLUB SUIT (present in WGL4 and in Symbol font)
♤	9828	♤	2664	 	WHITE SPADE SUIT
♥	9829	♥	2665	&hearts; (♥)	BLACK HEART SUIT (present in WGL4 and in Symbol font)
♦	9830	♦	2666	&diams; (♦)	BLACK DIAMOND SUIT (present in WGL4 and in Symbol font)
♧	9831	♧	2667	 	WHITE CLUB SUIT
♨	9832	♨	2668	 	HOT SPRINGS
♩	9833	♩	2669	 	QUARTER NOTE
♪	9834	♪	266A	 	EIGHTH NOTE (present in WGL4)
♫	9835	♫	266B	 	BEAMED EIGHTH NOTES (present in WGL4)
♬	9836	♬	266C	 	BEAMED SIXTEENTH NOTES
♭	9837	♭	266D	 	MUSIC FLAT SIGN
♮	9838	♮	266E	 	MUSIC NATURAL SIGN
♯	9839	♯	266F	 	MUSIC SHARP SIGN
♰	9840	♰	2670	 	WEST SYRIAC CROSS
♱	9841	♱	2671	 	EAST SYRIAC CROSS
♲	9842	♲	2672	 	UNIVERSAL RECYCLING SYMBOL
♳	9843	♳	2673	 	RECYCLING SYMBOL FOR TYPE-1 PLASTICS
♴	9844	♴	2674	 	RECYCLING SYMBOL FOR TYPE-2 PLASTICS
♵	9845	♵	2675	 	RECYCLING SYMBOL FOR TYPE-3 PLASTICS
♶	9846	♶	2676	 	RECYCLING SYMBOL FOR TYPE-4 PLASTICS
♷	9847	♷	2677	 	RECYCLING SYMBOL FOR TYPE-5 PLASTICS
♸	9848	♸	2678	 	RECYCLING SYMBOL FOR TYPE-6 PLASTICS
♹	9849	♹	2679	 	RECYCLING SYMBOL FOR TYPE-7 PLASTICS
♺	9850	♺	267A	 	RECYCLING SYMBOL FOR GENERIC MATERIALS
♻	9851	♻	267B	 	BLACK UNIVERSAL RECYCLING SYMBOL
♼	9852	♼	267C	 	RECYCLED PAPER SYMBOL
♽	9853	♽	267D	 	PARTIALLY-RECYCLED PAPER SYMBOL
♾	9854	♾	267E	 	PERMANENT PAPER SIGN
♿	9855	♿	267F	 	WHEELCHAIR SYMBOL
⚀	9856	⚀	2680	 	DIE FACE-1
⚁	9857	⚁	2681	 	DIE FACE-2
⚂	9858	⚂	2682	 	DIE FACE-3
⚃	9859	⚃	2683	 	DIE FACE-4
⚄	9860	⚄	2684	 	DIE FACE-5
⚅	9861	⚅	2685	 	DIE FACE-6
⚆	9862	⚆	2686	 	WHITE CIRCLE WITH DOT RIGHT
⚇	9863	⚇	2687	 	WHITE CIRCLE WITH TWO DOTS
⚈	9864	⚈	2688	 	BLACK CIRCLE WITH WHITE DOT RIGHT
⚉	9865	⚉	2689	 	BLACK CIRCLE WITH TWO WHITE DOTS
⚊	9866	⚊	268A	 	MONOGRAM FOR YANG
⚋	9867	⚋	268B	 	MONOGRAM FOR YIN
⚌	9868	⚌	268C	 	DIGRAM FOR GREATER YANG
⚍	9869	⚍	268D	 	DIGRAM FOR LESSER YIN
⚎	9870	⚎	268E	 	DIGRAM FOR LESSER YANG
⚏	9871	⚏	268F	 	DIGRAM FOR GREATER YIN
⚐	9872	⚐	2690	 	WHITE FLAG
⚑	9873	⚑	2691	 	BLACK FLAG
⚒	9874	⚒	2692	 	HAMMER AND PICK
⚓	9875	⚓	2693	 	ANCHOR
⚔	9876	⚔	2694	 	CROSSED SWORDS
⚕	9877	⚕	2695	 	STAFF OF AESCULAPIUS
⚖	9878	⚖	2696	 	SCALES
⚗	9879	⚗	2697	 	ALEMBIC
⚘	9880	⚘	2698	 	FLOWER
⚙	9881	⚙	2699	 	GEAR
⚚	9882	⚚	269A	 	STAFF OF HERMES
⚛	9883	⚛	269B	 	ATOM SYMBOL
⚜	9884	⚜	269C	 	FLEUR-DE-LIS
⚝	9885	⚝	269D	 	OUTLINED WHITE STAR
⚞	9886	⚞	269E	 	THREE LINES CONVERGING RIGHT
⚟	9887	⚟	269F	 	THREE LINES CONVERGING LEFT
⚠	9888	⚠	26A0	 	WARNING SIGN
⚡	9889	⚡	26A1	 	HIGH VOLTAGE SIGN
⚢	9890	⚢	26A2	 	DOUBLED FEMALE SIGN
⚣	9891	⚣	26A3	 	DOUBLED MALE SIGN
⚤	9892	⚤	26A4	 	INTERLOCKED FEMALE AND MALE SIGN
⚥	9893	⚥	26A5	 	MALE AND FEMALE SIGN
⚦	9894	⚦	26A6	 	MALE WITH STROKE SIGN
⚧	9895	⚧	26A7	 	MALE WITH STROKE AND MALE AND FEMALE SIGN
⚨	9896	⚨	26A8	 	VERTICAL MALE WITH STROKE SIGN
⚩	9897	⚩	26A9	 	HORIZONTAL MALE WITH STROKE SIGN
⚪	9898	⚪	26AA	 	MEDIUM WHITE CIRCLE
⚫	9899	⚫	26AB	 	MEDIUM BLACK CIRCLE
⚬	9900	⚬	26AC	 	MEDIUM SMALL WHITE CIRCLE
⚭	9901	⚭	26AD	 	MARRIAGE SYMBOL
⚮	9902	⚮	26AE	 	DIVORCE SYMBOL
⚯	9903	⚯	26AF	 	UNMARRIED PARTNERSHIP SYMBOL
⚰	9904	⚰	26B0	 	COFFIN
⚱	9905	⚱	26B1	 	FUNERAL URN
⚲	9906	⚲	26B2	 	NEUTER
⚳	9907	⚳	26B3	 	CERES
⚴	9908	⚴	26B4	 	PALLAS
⚵	9909	⚵	26B5	 	JUNO
⚶	9910	⚶	26B6	 	VESTA
⚷	9911	⚷	26B7	 	CHIRON
⚸	9912	⚸	26B8	 	BLACK MOON LILITH
⚹	9913	⚹	26B9	 	SEXTILE
⚺	9914	⚺	26BA	 	SEMISEXTILE
⚻	9915	⚻	26BB	 	QUINCUNX
⚼	9916	⚼	26BC	 	SESQUIQUADRATE
⚽	9917	⚽	26BD	 	SOCCER BALL
⚾	9918	⚾	26BE	 	BASEBALL
⚿	9919	⚿	26BF	 	SQUARED KEY
⛀	9920	⛀	26C0	 	WHITE DRAUGHTS MAN
⛁	9921	⛁	26C1	 	WHITE DRAUGHTS KING
⛂	9922	⛂	26C2	 	BLACK DRAUGHTS MAN
⛃	9923	⛃	26C3	 	BLACK DRAUGHTS KING
⛄	9924	⛄	26C4	 	SNOWMAN WITHOUT SNOW
⛅	9925	⛅	26C5	 	SUN BEHIND CLOUD
⛆	9926	⛆	26C6	 	RAIN
⛇	9927	⛇	26C7	 	BLACK SNOWMAN
⛈	9928	⛈	26C8	 	THUNDER CLOUD AND RAIN
⛉	9929	⛉	26C9	 	TURNED WHITE SHOGI PIECE
⛊	9930	⛊	26CA	 	TURNED BLACK SHOGI PIECE
⛋	9931	⛋	26CB	 	WHITE DIAMOND IN SQUARE
⛌	9932	⛌	26CC	 	CROSSING LANES
⛍	9933	⛍	26CD	 	DISABLED CAR
⛎	9934	⛎	26CE	 	OPHIUCHUS
⛏	9935	⛏	26CF	 	PICK
⛐	9936	⛐	26D0	 	CAR SLIDING
⛑	9937	⛑	26D1	 	HELMET WITH WHITE CROSS
⛒	9938	⛒	26D2	 	CIRCLED CROSSING LANES
⛓	9939	⛓	26D3	 	CHAINS
⛔	9940	⛔	26D4	 	NO ENTRY
⛕	9941	⛕	26D5	 	ALTERNATE ONE-WAY LEFT WAY TRAFFIC
⛖	9942	⛖	26D6	 	BLACK TWO-WAY LEFT WAY TRAFFIC
⛗	9943	⛗	26D7	 	WHITE TWO-WAY LEFT WAY TRAFFIC
⛘	9944	⛘	26D8	 	BLACK LEFT LANE MERGE
⛙	9945	⛙	26D9	 	WHITE LEFT LANE MERGE
⛚	9946	⛚	26DA	 	DRIVE SLOW SIGN
⛛	9947	⛛	26DB	 	HEAVY WHITE DOWN-POINTING TRIANGLE
⛜	9948	⛜	26DC	 	LEFT CLOSED ENTRY
⛝	9949	⛝	26DD	 	SQUARED SALTIRE
⛞	9950	⛞	26DE	 	FALLING DIAGONAL IN WHITE CIRCLE IN BLACK SQUARE
⛟	9951	⛟	26DF	 	BLACK TRUCK
⛠	9952	⛠	26E0	 	RESTRICTED LEFT ENTRY-1
⛡	9953	⛡	26E1	 	RESTRICTED LEFT ENTRY-2
⛢	9954	⛢	26E2	 	ASTRONOMICAL SYMBOL FOR URANUS
⛣	9955	⛣	26E3	 	HEAVY CIRCLE WITH STROKE AND TWO DOTS ABOVE
⛤	9956	⛤	26E4	 	PENTAGRAM
⛥	9957	⛥	26E5	 	RIGHT-HANDED INTERLACED PENTAGRAM
⛦	9958	⛦	26E6	 	LEFT-HANDED INTERLACED PENTAGRAM
⛧	9959	⛧	26E7	 	INVERTED PENTAGRAM
⛨	9960	⛨	26E8	 	BLACK CROSS ON SHIELD
⛩	9961	⛩	26E9	 	SHINTO SHRINE
⛪	9962	⛪	26EA	 	CHURCH
⛫	9963	⛫	26EB	 	CASTLE
⛬	9964	⛬	26EC	 	HISTORIC SITE
⛭	9965	⛭	26ED	 	GEAR WITHOUT HUB
⛮	9966	⛮	26EE	 	GEAR WITH HANDLES
⛯	9967	⛯	26EF	 	MAP SYMBOL FOR LIGHTHOUSE
⛰	9968	⛰	26F0	 	MOUNTAIN
⛱	9969	⛱	26F1	 	UMBRELLA ON GROUND
⛲	9970	⛲	26F2	 	FOUNTAIN
⛳	9971	⛳	26F3	 	FLAG IN HOLE
⛴	9972	⛴	26F4	 	FERRY
⛵	9973	⛵	26F5	 	SAILBOAT
⛶	9974	⛶	26F6	 	SQUARE FOUR CORNERS
⛷	9975	⛷	26F7	 	SKIER
⛸	9976	⛸	26F8	 	ICE SKATE
⛹	9977	⛹	26F9	 	PERSON WITH BALL
⛺	9978	⛺	26FA	 	TENT
⛻	9979	⛻	26FB	 	JAPANESE BANK SYMBOL
⛼	9980	⛼	26FC	 	HEADSTONE GRAVEYARD SYMBOL
⛽	9981	⛽	26FD	 	FUEL PUMP
⛾	9982	⛾	26FE	 	CUP ON BLACK SQUARE
⛿	9983	⛿	26FF	 	WHITE FLAG WITH HORIZONTAL MIDDLE BLACK STRIPE


*/
