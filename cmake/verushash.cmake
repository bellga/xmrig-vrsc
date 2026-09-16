if (WITH_VERUSHASH)
    add_definitions(/DXMRIG_ALGO_VERUSHASH)

    list(APPEND HEADERS_CRYPTO
        src/crypto/verushash/haraka.h
        src/crypto/verushash/haraka_portable.h
        src/crypto/verushash/verus_clhash.h
        src/crypto/verushash/verushash.h
    )

    list(APPEND SOURCES_CRYPTO
        src/crypto/verushash/haraka.c
        src/crypto/verushash/haraka_portable.c
        src/crypto/verushash/verus_clhash.cpp
        src/crypto/verushash/verus_clhash_portable.cpp
        src/crypto/verushash/verushash.cpp
    )

    if (XMRIG_ARM)
        # All five VerusHash source files branch on the bare `ARM` macro (inherited from
        # monkins1010/ccminer's verus/ tree -- see src/crypto/verushash/sse2neon/README.md) to
        # include the vendored sse2neon.h shim instead of <immintrin.h>, so their _mm_* calls
        # (AES-NI in haraka.h/haraka.c, PCLMUL in verus_clhash.cpp) compile to real ARMv8 Crypto
        # Extension instructions (AES/PMULL) instead. XMRig's own ARM macro is XMRIG_ARM, not the
        # bare `ARM` these files expect, so translate one into the other here -- scoped to just
        # these translation units, so nothing else in the tree sees a stray `ARM` define.
        #
        # No extra -march flags are needed here the way the x86 branch below needs them: unlike
        # x86 (where -maes is tree-wide but -mpclmul/-msse4.1 are not), cmake/cpu.cmake +
        # cmake/flags.cmake already apply -march=armv8-a+crypto tree-wide on ARM64 when the
        # toolchain supports it (ARM8_CXX_FLAGS/XMRIG_ARM_CRYPTO) -- the same flag GhostRider/
        # RandomX's own ARM AES paths in this fork already rely on. If the toolchain lacks crypto
        # extension support, sse2neon falls back to a portable software implementation on its own
        # (see its README) rather than failing to build; it will just be slow.
        set_source_files_properties(
            src/crypto/verushash/haraka.c
            src/crypto/verushash/haraka_portable.c
            src/crypto/verushash/verus_clhash.cpp
            src/crypto/verushash/verus_clhash_portable.cpp
            src/crypto/verushash/verushash.cpp
            PROPERTIES COMPILE_DEFINITIONS "ARM"
        )
    else()
        # verus_clhash.cpp uses _mm_clmulepi64_si128 (PCLMUL) directly, which is not implied by the
        # tree-wide -maes flag; verushash.cpp uses AES-NI intrinsics via haraka.h. GCC/Clang refuse to
        # inline these intrinsics without the matching -m flag enabled for the translation unit.
        set_source_files_properties(
            src/crypto/verushash/verus_clhash.cpp
            src/crypto/verushash/verushash.cpp
            PROPERTIES COMPILE_FLAGS "-maes -mpclmul -msse4.1"
        )
    endif()
else()
    remove_definitions(/DXMRIG_ALGO_VERUSHASH)
endif()
