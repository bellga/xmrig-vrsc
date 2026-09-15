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

    # verus_clhash.cpp uses _mm_clmulepi64_si128 (PCLMUL) directly, which is not implied by the
    # tree-wide -maes flag; verushash.cpp uses AES-NI intrinsics via haraka.h. GCC/Clang refuse to
    # inline these intrinsics without the matching -m flag enabled for the translation unit.
    set_source_files_properties(
        src/crypto/verushash/verus_clhash.cpp
        src/crypto/verushash/verushash.cpp
        PROPERTIES COMPILE_FLAGS "-maes -mpclmul -msse4.1"
    )
else()
    remove_definitions(/DXMRIG_ALGO_VERUSHASH)
endif()
