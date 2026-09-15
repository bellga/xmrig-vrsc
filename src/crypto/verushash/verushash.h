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

/*
 * VerusHash 2.2 (VRSC) adapter for XMRig's CpuWorker dispatch.
 *
 * The algorithm itself is ported from monkins1010/ccminer's verus/verusscan.cpp
 * (VerusHashHalf -> GenNewCLKey -> Verus2hash), cross-validated byte-for-byte against the
 * canonical VerusCoin core implementation -- see claude/porte-verushash-spec.md for the full
 * pipeline writeup, including why kNonceOffset below is 1472 and why the "full" (not the
 * production hot-loop's truncated) haraka512_keyed is required here.
 */

#ifndef XMRIG_VERUSHASH_H
#define XMRIG_VERUSHASH_H


#include <cstddef>
#include <cstdint>


namespace xmrig {
namespace verushash {


// Total job blob size VerusHash expects: 140-byte block header + 3-byte solution-size varint
// (0xfd 0x40 0x05, i.e. 1344 little-endian) + 1344-byte repurposed "Equihash solution" area.
constexpr size_t kInputSize = 1487;

// Offset of the 15-byte nonce/entropy field within that blob (== kInputSize - 15). Only the
// first 4 bytes of it are used as XMRig's incrementing nonce counter (see Job::nonceOffset());
// the rest keeps whatever the pool's job template put there.
constexpr size_t kNonceOffset = kInputSize - 15;
constexpr size_t kNonceFieldSize = 15;


// Opaque per-thread state: the ~8.6 KB pseudorandom key table (and its restore scratch) that
// GenNewCLKey produces once per job, plus the cached copy of the job's fixed (non-nonce) bytes
// used to detect when that expensive step needs to be redone. One Context per mining thread,
// created once and reused for every hash -- never reallocate per call.
struct Context;

Context *create();
void destroy(Context *ctx);

// Computes the VerusHash 2.2 of `blob` (must be exactly kInputSize bytes) into `output` (32
// bytes). Regenerates the per-job key table automatically when the non-nonce part of `blob`
// differs from the last call on this same `ctx`.
void hash(const uint8_t *blob, size_t size, uint8_t *output, Context *ctx);


} // namespace verushash
} // namespace xmrig


#endif /* XMRIG_VERUSHASH_H */
