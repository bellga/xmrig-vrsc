/* XMRig
 * VerusHash 2.2 clhash step, native AArch64 NEON/Crypto implementation (verus_clhash_neon.cpp).
 * Same result and same fixrand/fixrandex output as verusclhashv2_2(), but instead of filling
 * g_prand/g_prandex with the old values it takes `master`, a pristine copy of the key table: the
 * caller restores key[fixrand[i]] / key[fixrandex[i]] from master afterwards. Only built when
 * XMRIG_VERUS_NEON is defined (ARMv8 + Crypto extension, see cmake/verushash.cmake).
 */
#ifndef XMRIG_VERUS_CLHASH_NEON_H
#define XMRIG_VERUS_CLHASH_NEON_H

#include <stdint.h>

uint64_t verusclhashv2_2_neon(void *random, const unsigned char buf[64], uint64_t keyMask,
                              uint32_t *fixrand, uint32_t *fixrandex, const void *master);

#endif /* XMRIG_VERUS_CLHASH_NEON_H */
