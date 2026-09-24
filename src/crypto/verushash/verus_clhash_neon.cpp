/*
 * VerusHash 2.2 clhash step -- native AArch64 NEON/Crypto implementation.
 *
 * Same algorithm as __verusclmulwithoutreduction64alignedrepeatv2_2 in verus_clhash.cpp
 * (Apache-2.0, (c) 2018 Michael Toutonghi; clhash (c) 2017-2018 Daniel Lemire and Owen Kaser),
 * written directly with ARMv8 intrinsics instead of going through sse2neon. The approach follows
 * the ARM-optimized ccminer fork (Oink70/CCminer-ARM-optimized, NEON work by "Mixed-Nuts"):
 *
 *   - PMULL (vmull_p64) straight on the needed 64-bit lanes (no imm switch per call);
 *   - _mm_mulhrs_epi16 as SQRDMULH (1 instruction) instead of sse2neon's widen/round/narrow
 *     sequence. SQRDMULH differs from PMULHRSW for exactly one input pair (-32768 * -32768:
 *     it saturates to 0x7fff, PMULHRSW wraps to 0x8000). The ccminer fork ignores that; here the
 *     fast path runs with plain SQRDMULH, checks the sticky saturation flag (FPSR.QC) once at the
 *     end, and in that rare case (~1e-7 of hashes) undoes the key mutations and recomputes with a
 *     bit-exact mulhrs. Result is always identical to the reference;
 *   - AESE+AESMC for _mm_aesenc_si128, ZIP1/ZIP2 for the MIX2 unpacks, TBL for the reduction
 *     shuffle, lazyLengthHash(1024, 64) folded to its constant (0x10000).
 *
 * The ccminer fork also reordered the final two stores of cases 0x14 and 0x18; that breaks the
 * result whenever prand == prandex (~0.32% of hashes, measured). The store order here is the
 * reference one. See claude/estudo-ccminer-arm-oink.md in the project notes.
 *
 * Unlike verusclhashv2_2(), this does not save each mutated entry's old value into g_prand/
 * g_prandex on every iteration (64 extra stores per hash): the caller keeps a pristine copy of the
 * key table (`master`) and restores the 64 touched entries from it after the hash (FixKey), and
 * the saturation fallback below restores from it too. fixrand/fixrandex still record the indices.
 *
 * Built only for ARMv8 (AArch64) with the Crypto extension (see cmake/verushash.cmake);
 * everything else keeps using verus_clhash.cpp.
 */

#include <arm_neon.h>
#include <stdint.h>

#include "crypto/verushash/verus_clhash_neon.h"


namespace {

typedef uint8x16_t v128;


static inline v128 ld(const v128 *p)               { return vld1q_u8(reinterpret_cast<const uint8_t *>(p)); }
static inline void st(v128 *p, v128 v)             { vst1q_u8(reinterpret_cast<uint8_t *>(p), v); }
static inline v128 x(v128 a, v128 b)               { return veorq_u8(a, b); }
static inline uint64_t lo64(v128 a)                { return vgetq_lane_u64(vreinterpretq_u64_u8(a), 0); }


// _mm_clmulepi64_si128(a, a, 0x10): low qword of a times high qword of a.
static inline v128 clmul_self(v128 a)
{
    const uint64x2_t q = vreinterpretq_u64_u8(a);
    return vreinterpretq_u8_p128(vmull_p64(static_cast<poly64_t>(vgetq_lane_u64(q, 0)),
                                           static_cast<poly64_t>(vgetq_lane_u64(q, 1))));
}


// _mm_mulhrs_epi16: (a*b + 0x4000) >> 15 per signed 16-bit lane, truncated.
// Fast form: SQRDMULH alone (saturates -32768*-32768 to 0x7fff and sets FPSR.QC).
// Exact form: XOR 0xffff into exactly those lanes, turning 0x7fff into PMULHRSW's 0x8000.
template<bool kExact>
static inline v128 mulhrs(v128 a, v128 b)
{
    const int16x8_t sa = vreinterpretq_s16_u8(a);
    const int16x8_t sb = vreinterpretq_s16_u8(b);
    const int16x8_t r  = vqrdmulhq_s16(sa, sb);

    if (!kExact) {
        return vreinterpretq_u8_s16(r);
    }

    const int16x8_t  min = vdupq_n_s16(INT16_MIN);
    const uint16x8_t fix = vandq_u16(vceqq_s16(sa, min), vceqq_s16(sb, min));

    return vreinterpretq_u8_u16(veorq_u16(vreinterpretq_u16_s16(r), fix));
}


static constexpr uint64_t kFpsrQC = 1ULL << 27;

// The "memory" clobber keeps every key/scratch store (and so every SQRDMULH feeding one) on its
// side of these barriers; `acc` as an input ties the ones that only feed the accumulator.
static inline uint64_t fpsr_read(v128 dep)
{
    uint64_t v;
    __asm__ volatile("mrs %0, fpsr" : "=r"(v) : "w"(dep) : "memory");
    return v;
}

static inline void fpsr_write(uint64_t v)
{
    __asm__ volatile("msr fpsr, %0" : : "r"(v) : "memory");
}


// _mm_aesenc_si128(a, k) == AESMC(AESE(a, 0)) ^ k
static inline v128 aesenc(v128 a, v128 k)          { return x(vaesmcq_u8(vaeseq_u8(a, vdupq_n_u8(0))), k); }


#define VN_AES2(s0, s1, rc, rci) \
    s0 = aesenc(s0, ld((rc) + (rci)));     \
    s1 = aesenc(s1, ld((rc) + (rci) + 1)); \
    s0 = aesenc(s0, ld((rc) + (rci) + 2)); \
    s1 = aesenc(s1, ld((rc) + (rci) + 3));

// MIX2: tmp = unpacklo_epi32(s0, s1); s1 = unpackhi_epi32(s0, s1); s0 = tmp;
#define VN_MIX2(s0, s1) { \
    const uint32x4_t a_ = vreinterpretq_u32_u8(s0), b_ = vreinterpretq_u32_u8(s1); \
    s0 = vreinterpretq_u8_u32(vzip1q_u32(a_, b_)); \
    s1 = vreinterpretq_u8_u32(vzip2q_u32(a_, b_)); }


// _mm_cvtsi32_si128((int32_t)v): low dword = v, rest zero.
static inline v128 from_i32(int32_t v)
{
    return vreinterpretq_u8_s32(vsetq_lane_s32(v, vdupq_n_s32(0), 0));
}


// precompReduction64(A) from verus_clhash.h, returns the low 64 bits.
static inline uint64_t reduce64(v128 A)
{
    static const uint8_t tbl[16] = { 0, 27, 54, 45, 108, 119, 90, 65, 216, 195, 238, 245, 180, 175, 130, 153 };

    const uint64x2_t a = vreinterpretq_u64_u8(A);
    const v128 Q2 = vreinterpretq_u8_p128(vmull_p64(static_cast<poly64_t>(vgetq_lane_u64(a, 1)), static_cast<poly64_t>(27)));
    // _mm_shuffle_epi8(table, _mm_srli_si128(Q2, 8)): indices are the high 8 bytes of Q2 (< 16 for
    // this polynomial, so TBL's out-of-range-to-zero rule never differs from PSHUFB's).
    const v128 idx = vextq_u8(Q2, vdupq_n_u8(0), 8);
    const v128 Q3  = vqtbl1q_u8(vld1q_u8(tbl), idx);

    return lo64(x(Q3, x(Q2, A)));
}


template<bool kExact>
static inline v128 clmul_loop(v128 *randomsource, const unsigned char buf[64], uint64_t keyMask,
                              uint32_t *fixrand, uint32_t *fixrandex)
{
    const v128 *b = reinterpret_cast<const v128 *>(buf);

    const v128 b0 = ld(b), b1 = ld(b + 1), b2 = ld(b + 2), b3 = ld(b + 3);
    const v128 pbuf_copy[4] = { x(b0, b2), x(b1, b3), b2, b3 };

    v128 acc = ld(randomsource + (keyMask + 2));

    for (int i = 0; i < 32; i++) {
        const uint64_t selector = lo64(acc);

        const uint32_t prand_idx   = static_cast<uint32_t>((selector >> 5) & keyMask);
        const uint32_t prandex_idx = static_cast<uint32_t>((selector >> 32) & keyMask);
        v128 *prand   = randomsource + prand_idx;
        v128 *prandex = randomsource + prandex_idx;

        const v128 *pbuf  = pbuf_copy + (selector & 3);
        const v128 *pbufo = pbuf + ((selector & 1) ? -1 : 1);   // pbuf[(selector & 1) ? -1 : 1]

        fixrand[i]   = prand_idx;
        fixrandex[i] = prandex_idx;

        switch (selector & 0x1c) {
        case 0: {
            const v128 temp1 = ld(prandex);
            acc = x(clmul_self(x(temp1, ld(pbufo))), acc);

            const v128 tempa2 = x(mulhrs<kExact>(acc, temp1), temp1);

            const v128 temp12 = ld(prand);
            st(prand, tempa2);

            acc = x(clmul_self(x(temp12, ld(pbuf))), acc);
            st(prandex, x(mulhrs<kExact>(acc, temp12), temp12));
            break;
        }
        case 4: {
            const v128 temp1 = ld(prand);
            const v128 temp2 = ld(pbuf);
            acc = x(clmul_self(x(temp1, temp2)), acc);
            acc = x(clmul_self(temp2), acc);

            const v128 tempa2 = x(mulhrs<kExact>(acc, temp1), temp1);

            const v128 temp12 = ld(prandex);
            st(prandex, tempa2);

            acc = x(x(temp12, ld(pbufo)), acc);
            st(prand, x(mulhrs<kExact>(acc, temp12), temp12));
            break;
        }
        case 8: {
            const v128 temp1 = ld(prandex);
            acc = x(x(temp1, ld(pbuf)), acc);

            const v128 tempa2 = x(mulhrs<kExact>(acc, temp1), temp1);

            const v128 temp12 = ld(prand);
            st(prand, tempa2);

            const v128 temp22 = ld(pbufo);
            acc = x(clmul_self(x(temp12, temp22)), acc);
            acc = x(clmul_self(temp22), acc);

            st(prandex, x(mulhrs<kExact>(acc, temp12), temp12));
            break;
        }
        case 0xc: {
            const v128 temp1 = ld(prand);
            const int32_t divisor = static_cast<int32_t>(static_cast<uint32_t>(selector)); // cannot be zero here

            acc = x(x(temp1, ld(pbufo)), acc);

            const int64_t dividend = static_cast<int64_t>(lo64(acc));
            acc = x(from_i32(static_cast<int32_t>(dividend % divisor)), acc);

            const v128 tempa2 = x(mulhrs<kExact>(acc, temp1), temp1);

            if (dividend & 1) {
                const v128 temp12 = ld(prandex);
                st(prandex, tempa2);

                const v128 temp22 = ld(pbuf);
                acc = x(clmul_self(x(temp12, temp22)), acc);
                acc = x(clmul_self(temp22), acc);

                st(prand, x(mulhrs<kExact>(acc, temp12), temp12));
            }
            else {
                st(prand, ld(prandex));
                st(prandex, tempa2);
                acc = x(ld(pbuf), acc);
            }
            break;
        }
        case 0x10: {
            const v128 *rc = prand;
            v128 temp1 = ld(pbufo);
            v128 temp2 = ld(pbuf);

            VN_AES2(temp1, temp2, rc, 0);
            VN_MIX2(temp1, temp2);
            VN_AES2(temp1, temp2, rc, 4);
            VN_MIX2(temp1, temp2);
            VN_AES2(temp1, temp2, rc, 8);
            VN_MIX2(temp1, temp2);

            acc = x(temp2, x(temp1, acc));

            const v128 tempa1 = ld(prand);
            const v128 tempa2 = mulhrs<kExact>(acc, tempa1);

            st(prand, ld(prandex));
            st(prandex, x(tempa1, tempa2));
            break;
        }
        case 0x14: {
            // "monkins loop": 1..8 rounds of either CLMUL or AES+MIX over the key
            uint64_t rounds = selector >> 61;
            const v128 *rc = prand;
            uint64_t aesroundoffset = 0;

            do {
                if (selector & ((static_cast<uint64_t>(0x10000000)) << rounds)) {
                    const v128 temp2 = ld((rounds & 1) ? pbuf : pbufo);
                    acc = x(clmul_self(x(ld(rc), temp2)), acc);
                    rc++;
                }
                else {
                    v128 onekey = ld(rc++);
                    v128 temp2  = ld((rounds & 1) ? pbufo : pbuf);
                    VN_AES2(onekey, temp2, rc, aesroundoffset);   // rc already advanced, as in the reference
                    aesroundoffset += 4;
                    VN_MIX2(onekey, temp2);
                    acc = x(temp2, x(onekey, acc));
                }
            } while (rounds--);

            const v128 tempa1 = ld(prand);
            const v128 tempa3 = x(tempa1, mulhrs<kExact>(acc, tempa1));
            const v128 tempa4 = ld(prandex);

            // reference order: prandex first, then prand (matters when prand == prandex)
            st(prandex, tempa3);
            st(prand, tempa4);
            break;
        }
        case 0x18: {
            uint64_t rounds = selector >> 61;
            const v128 *rc = prand;
            v128 onekey = vdupq_n_u8(0);
            const int32_t divisor = static_cast<int32_t>(static_cast<uint32_t>(selector)); // cannot be zero here

            do {
                if (selector & ((static_cast<uint64_t>(0x10000000)) << rounds)) {
                    onekey = x(ld(rc), ld((rounds & 1) ? pbuf : pbufo));
                    rc++;
                    const int64_t dividend = static_cast<int64_t>(lo64(onekey));
                    acc = x(from_i32(static_cast<int32_t>(dividend % divisor)), acc);
                }
                else {
                    onekey = clmul_self(x(ld(rc), ld((rounds & 1) ? pbufo : pbuf)));
                    rc++;
                    acc = x(mulhrs<kExact>(acc, onekey), acc);
                }
            } while (rounds--);

            const v128 tempa3 = ld(prandex);

            // reference order: prandex first, then prand (matters when prand == prandex)
            st(prandex, onekey);
            st(prand, x(tempa3, acc));
            break;
        }
        default: { // 0x1c
            const v128 temp1 = ld(pbuf);
            const v128 temp2 = ld(prandex);
            acc = x(clmul_self(x(temp1, temp2)), acc);

            const v128 tempa2 = x(mulhrs<kExact>(acc, temp2), temp2);

            const v128 tempa3 = ld(prand);
            st(prand, tempa2);

            acc = x(x(tempa3, acc), ld(pbufo));
            st(prandex, x(mulhrs<kExact>(acc, tempa3), tempa3));
            break;
        }
        }
    }

    return acc;
}


} // namespace


uint64_t verusclhashv2_2_neon(void *random, const unsigned char buf[64], uint64_t keyMask,
                              uint32_t *fixrand, uint32_t *fixrandex, const void *master_)
{
    v128 *randomsource = static_cast<v128 *>(random);
    const v128 *master = static_cast<const v128 *>(master_);

    const uint64_t fpsr = fpsr_read(vdupq_n_u8(0));
    fpsr_write(fpsr & ~kFpsrQC);

    v128 acc = clmul_loop<false>(randomsource, buf, keyMask, fixrand, fixrandex);

    if (fpsr_read(acc) & kFpsrQC) {
        // A -32768*-32768 lane saturated somewhere: undo this attempt's key mutations from the
        // pristine copy and redo it with the bit-exact mulhrs.
        for (int i = 31; i > -1; i--) {
            st(randomsource + fixrandex[i], ld(master + fixrandex[i]));
            st(randomsource + fixrand[i], ld(master + fixrand[i]));
        }

        acc = clmul_loop<true>(randomsource, buf, keyMask, fixrand, fixrandex);
    }

    fpsr_write(fpsr);

    // lazyLengthHash(1024, 64) == clmul(1024, 64) == 0x10000
    acc = x(acc, from_i32(0x10000));

    return reduce64(acc);
}
