# sse2neon (vendored)

Source: https://github.com/DLTcollab/sse2neon (master, fetched 2026-09-16)
License: MIT (see `LICENSE` in this directory)

This is a single-header library that translates x86 SSE/SSSE3/PCLMUL/AES-NI
intrinsics (`_mm_*`) to their ARM NEON / ARMv8 Crypto Extension equivalents.
It is included, unmodified, only so the existing VerusHash sources in
`src/crypto/verushash/` -- which already gate their `<immintrin.h>` include
behind `#ifdef ARM` (inherited from monkins1010/ccminer's verus/ tree) -- have
something to fall back to on ARM builds. None of the ported VerusHash files
were changed to use this: they already assumed a header at this exact path.

`_mm_aesenc_si128` and `_mm_clmulepi64_si128` (the two intrinsics VerusHash's
Haraka512 and clhash steps actually use) compile to real ARMv8 Crypto
Extension instructions (AES/PMULL) when `__ARM_FEATURE_CRYPTO` is defined --
i.e. when the translation unit is built with `-march=armv8-a+crypto` -- and
fall back to a portable software implementation otherwise. XMRig's own
`cmake/cpu.cmake` already detects `-march=armv8-a+crypto` support and applies
it tree-wide (`ARM8_CXX_FLAGS`, `XMRIG_ARM_CRYPTO`) for other algorithms, so
no extra flag plumbing was needed for VerusHash specifically -- see
`cmake/verushash.cmake`.
