/* XMRig
 * VerusHash 2.2 clhash step, native AArch64 NEON/Crypto implementation (verus_clhash_neon.cpp).
 * Drop-in replacement for verusclhashv2_2() with the same arguments and result; only built when
 * XMRIG_VERUS_NEON is defined (ARMv8 + Crypto extension, see cmake/verushash.cmake).
 */
#ifndef XMRIG_VERUS_CLHASH_NEON_H
#define XMRIG_VERUS_CLHASH_NEON_H

#include <stdint.h>

uint64_t verusclhashv2_2_neon(void *random, const unsigned char buf[64], uint64_t keyMask,
                              uint32_t *fixrand, uint32_t *fixrandex, void *g_prand, void *g_prandex);

#endif /* XMRIG_VERUS_CLHASH_NEON_H */
