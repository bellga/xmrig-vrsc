/* XMRig
 * Copyright (c) 2024      MoneroOcean fork contributors
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include "crypto/verushash/verushash.h"

#include <cstdlib>
#include <cstring>

// verushash.cpp is the one file in this directory that didn't already have the ARM/x86 include
// branch the rest of src/crypto/verushash/ inherited from monkins1010/ccminer's verus/ tree (see
// haraka.h, haraka_portable.h, verus_clhash.h). It uses only SSE2/SSSE3-level intrinsics
// (_mm_load_si128, _mm_shuffle_epi8, _mm_xor_si128, _mm_setr_epi8, _mm_store_si128,
// _mm_loadl_epi64) plus haraka.h's AES-NI macros -- all covered by sse2neon on ARM builds. See
// sse2neon/README.md for how ARM builds get real AES/PMULL instructions here.
#ifdef ARM
#include "sse2neon/sse2neon.h"
#else
#include <immintrin.h>
#endif

extern "C" {
#include "crypto/verushash/haraka.h"
#include "crypto/verushash/haraka_portable.h"
}
#include "crypto/verushash/verus_clhash.h"


namespace xmrig {
namespace verushash {


namespace {

// VERUS_KEY_SIZE in ccminer/monkins1010's verusscan.cpp is a BYTE count, not a count of u128
// entries (GenNewCLKey below writes exactly this many bytes). 8832 bytes == 552 u128 entries
// (VERUS_KEY_SIZE128 in the original). Earlier drafts of claude/porte-verushash-spec.md
// mis-described this as "8832 u128 entries (~141 KB)" -- the real table is ~8.6 KB. The
// validated cross-check hash (see that doc) used a generously over-sized test buffer, so this
// correction changes nothing about that result, only the size documented for it.
constexpr size_t kKeyBytes      = 8832;
constexpr size_t kKeyEntries128 = kKeyBytes / sizeof(u128); // 552
// Matches ccminer's `malloc(VERUS_KEY_SIZE + 1024)`: the key table itself (552 u128 entries)
// plus two 32-entry restore-scratch regions (data_key_prand / data_key_prandex) that
// verusclhashv2_2/FixKey use to undo, entry by entry, whatever it mutated in the table on each
// nonce attempt -- 552*16 + 32*16 + 32*16 = 8832 + 512 + 512 = 9856 bytes == kKeyBytes + 1024.
constexpr size_t kAllocBytes = kKeyBytes + 1024;


// == ccminer/monkins1010's GenNewCLKey (verusscan.cpp), unmodified logic: chain-hashes
// Haraka256 to fill the key table from the 32-byte VerusHashHalf seed.
inline void genNewClKey(const unsigned char *seedBytes32, u128 *keyback)
{
    constexpr int n256blks    = static_cast<int>(kKeyBytes >> 5);
    constexpr int nbytesExtra = static_cast<int>(kKeyBytes & 0x1f);

    auto *pkey = reinterpret_cast<unsigned char *>(keyback);
    const unsigned char *psrc = seedBytes32;

    for (int i = 0; i < n256blks; i++) {
        haraka256(pkey, psrc);
        psrc = pkey;
        pkey += 32;
    }

    if (nbytesExtra) {
        unsigned char buf[32];
        haraka256(buf, psrc);
        memcpy(pkey, buf, nbytesExtra);
    }
}


// == ccminer/monkins1010's VerusHashHalf (verusscan.cpp), unmodified logic: folds `data` in
// complete 32-byte chunks via Haraka512, leaving whatever doesn't make a full chunk (here,
// exactly the trailing 15-byte nonce field, since kInputSize % 32 == 15) sitting unconsumed in
// the result's tail -- that's the whole reason per-nonce work doesn't need to redo this step.
inline void verusHashHalf(void *result2, const unsigned char *data, int len)
{
    alignas(32) unsigned char buf1[64] = { 0 }, buf2[64];
    unsigned char *curBuf = buf1, *result = buf2;
    int curPos = 0;
    unsigned char *tmp;

    for (int pos = 0; pos < len; ) {
        const int room = 32 - curPos;

        if (len - pos >= room) {
            memcpy(curBuf + 32 + curPos, data + pos, room);
            haraka512(result, curBuf);
            tmp    = curBuf;
            curBuf = result;
            result = tmp;
            pos    += room;
            curPos = 0;
        }
        else {
            memcpy(curBuf + 32 + curPos, data + pos, len - pos);
            curPos += len - pos;
            pos = len;
        }
    }

    memcpy(curBuf + 47, curBuf, 16);
    memcpy(curBuf + 63, curBuf, 1);
    memcpy(result2, curBuf, 64);
}


// Full-store reconstruction of haraka512_keyed (5x AES4+MIX4, plaintext XOR, full TRUNCSTORE),
// matching core/crypto/haraka.c's haraka512_keyed exactly. This fork's own production
// haraka512_keyed() (haraka.c) is deliberately truncated to only the top 32-bit word (a real
// mining hot-loop optimization for verusscan.cpp's own target pre-check, `vhash[7] <= Htarg` --
// see claude/porte-verushash-spec.md) and leaves the rest of `out` unwritten. XMRig's CpuWorker
// needs a complete, comparable 32-byte hash every call (its target check reads bytes 24-31 of
// the full hash, and a found share's full hash is what gets submitted), so this adapter always
// computes the full value. Cross-validated byte-for-byte against VerusCoin core's CVerusHashV2
// in this fork's development session (see claude/porte-verushash-spec.md).
inline void harakaKeyedFull(unsigned char *out, const unsigned char *in, const u128 *rc)
{
    u128 s[4], tmp;

    s[0] = LOAD(in);
    s[1] = LOAD(in + 16);
    s[2] = LOAD(in + 32);
    s[3] = LOAD(in + 48);

    AES4(s[0], s[1], s[2], s[3], 0);
    MIX4(s[0], s[1], s[2], s[3]);

    AES4(s[0], s[1], s[2], s[3], 8);
    MIX4(s[0], s[1], s[2], s[3]);

    AES4(s[0], s[1], s[2], s[3], 16);
    MIX4(s[0], s[1], s[2], s[3]);

    AES4(s[0], s[1], s[2], s[3], 24);
    MIX4(s[0], s[1], s[2], s[3]);

    AES4(s[0], s[1], s[2], s[3], 32);
    MIX4(s[0], s[1], s[2], s[3]);

    s[0] = _mm_xor_si128(s[0], LOAD(in));
    s[1] = _mm_xor_si128(s[1], LOAD(in + 16));
    s[2] = _mm_xor_si128(s[2], LOAD(in + 32));
    s[3] = _mm_xor_si128(s[3], LOAD(in + 48));

    TRUNCSTORE(out, s[0], s[1], s[2], s[3]);
}

} // namespace


struct Context
{
    u128 *data_key         = nullptr; // kAllocBytes worth: key table + two restore-scratch regions
    u128 *data_key_prand   = nullptr; // == data_key + kKeyEntries128
    u128 *data_key_prandex = nullptr; // == data_key + kKeyEntries128 + 32

    // 16-byte alignment is enough: this buffer is only ever memcpy'd, never accessed as a SIMD
    // register directly (the per-nonce __m128i work happens on the stack-local `curBuf` in
    // hash() below, which the compiler aligns itself). Using alignas(32) here would require
    // matching overaligned heap allocation for `Context`, which plain `new` does not guarantee.
    alignas(16) uint8_t blockhash_half[64] = { 0 };
    uint8_t cachedPrefix[kNonceOffset]     = { 0 }; // last-seen fixed (non-nonce) part of the blob
    bool    havePrefix                     = false;

    uint32_t fixrand[32]   = { 0 };
    uint32_t fixrandex[32] = { 0 };
};


Context *create()
{
    load_constants();

    auto *ctx = new Context();
    ctx->data_key = static_cast<u128 *>(malloc(kAllocBytes));
    memset(ctx->data_key, 0, kAllocBytes);
    ctx->data_key_prand   = ctx->data_key + kKeyEntries128;
    ctx->data_key_prandex = ctx->data_key + kKeyEntries128 + 32;

    return ctx;
}


void destroy(Context *ctx)
{
    if (ctx == nullptr) {
        return;
    }

    free(ctx->data_key);
    delete ctx;
}


void hash(const uint8_t *blob, size_t size, uint8_t *output, Context *ctx)
{
    if (size != kInputSize) {
        memset(output, 0, 32);
        return;
    }

    const bool jobChanged = !ctx->havePrefix || memcmp(ctx->cachedPrefix, blob, kNonceOffset) != 0;

    if (jobChanged) {
        verusHashHalf(ctx->blockhash_half, blob, static_cast<int>(kInputSize));
        genNewClKey(ctx->blockhash_half, ctx->data_key);

        memcpy(ctx->cachedPrefix, blob, kNonceOffset);
        ctx->havePrefix = true;
    }

    // Per-nonce step == ccminer/monkins1010's Verus2hash (verusscan.cpp), operating on a local
    // copy of blockhash_half so nothing here mutates the cached per-job state.
    alignas(32) unsigned char curBuf[64];
    memcpy(curBuf, ctx->blockhash_half, 64);

    static const __m128i shuf1 = _mm_setr_epi8(1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0);
    const __m128i fill1 = _mm_shuffle_epi8(_mm_load_si128(reinterpret_cast<const u128 *>(curBuf)), shuf1);
    static const __m128i shuf2 = _mm_setr_epi8(1, 2, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 0);
    const unsigned char ch = curBuf[0];
    _mm_store_si128(reinterpret_cast<u128 *>(&curBuf[32 + 16]), fill1);
    curBuf[32 + 15] = ch;

    memcpy(curBuf + 32, blob + kNonceOffset, kNonceFieldSize);

    uint64_t intermediate = verusclhashv2_2(ctx->data_key, curBuf, 511, ctx->fixrand, ctx->fixrandex, ctx->data_key_prand, ctx->data_key_prandex);

    const __m128i fill2 = _mm_shuffle_epi8(_mm_loadl_epi64(reinterpret_cast<const u128 *>(&intermediate)), shuf2);
    _mm_store_si128(reinterpret_cast<u128 *>(&curBuf[32 + 16]), fill2);
    curBuf[32 + 15] = *reinterpret_cast<unsigned char *>(&intermediate);
    intermediate &= 511;

    harakaKeyedFull(output, curBuf, ctx->data_key + intermediate);

    // FixKey: undo the ~32 entries verusclhashv2_2 mutated in data_key so the table is correct
    // again for the next nonce attempt without re-running GenNewCLKey.
    for (int i = 31; i > -1; i--) {
        ctx->data_key[ctx->fixrandex[i]] = ctx->data_key_prandex[i];
        ctx->data_key[ctx->fixrand[i]]   = ctx->data_key_prand[i];
    }
}


} // namespace verushash
} // namespace xmrig
