# ARMv8 per-microarchitecture tuning, opt-in via -DARM_CPU=<code>.
#
# Context: cpu.cmake's default ARM8_CXX_FLAGS is deliberately generic
# (-march=armv8-a+crypto) -- it only asks "does this core have the crypto
# extension (AES/PMULL)", the same yes/no split that matters for VerusHash's
# sse2neon path (see src/crypto/verushash/sse2neon/README.md). That's the
# right default for a build that has to run on whatever device it lands on.
#
# For a build targeting one known device (e.g. a Termux build script that
# already ran `cat /proc/cpuinfo` on the phone it's building on), -mcpu=<core>
# additionally tunes instruction scheduling/latencies for that exact core,
# which -march=armv8-a+crypto alone does not do. This is opt-in, not a
# replacement for the generic default: pass -DARM_CPU=<code> to ask for it.
#
# ARM_CPU accepts either one of the short codes below (loosely following the
# codenames pangz-lab/verus_miner-release uses for its own per-core Android
# builds, since that's the reference the user pointed at for mobile support)
# or a compiler -mcpu identifier directly (e.g. -DARM_CPU=cortex-a76 works
# the same as -DARM_CPU=ca76). Unrecognized short codes are tried verbatim as
# a -mcpu value -- this list intentionally does not try to be exhaustive.
#
# Every candidate is verified with CHECK_CXX_COMPILER_FLAG before use (the
# installed GCC/Clang has to actually recognize that specific core -- support
# varies a lot by toolchain version, especially for newer cores). If it's not
# recognized, or ARM_CPU isn't set at all, this falls back to cpu.cmake's
# normal generic ARM8_CXX_FLAGS -- an unrecognized -DARM_CPU value is a
# warning, never a hard build failure.
set(XMRIG_ARM_CPU_MAP_ca34   "cortex-a34")
set(XMRIG_ARM_CPU_MAP_ca35   "cortex-a35")
set(XMRIG_ARM_CPU_MAP_ca53   "cortex-a53")
set(XMRIG_ARM_CPU_MAP_ca55   "cortex-a55")
set(XMRIG_ARM_CPU_MAP_ca57   "cortex-a57")
set(XMRIG_ARM_CPU_MAP_ca65   "cortex-a65")
set(XMRIG_ARM_CPU_MAP_ca65ae "cortex-a65ae")
set(XMRIG_ARM_CPU_MAP_ca72   "cortex-a72")
set(XMRIG_ARM_CPU_MAP_ca73   "cortex-a73")
set(XMRIG_ARM_CPU_MAP_ca75   "cortex-a75")
set(XMRIG_ARM_CPU_MAP_ca76   "cortex-a76")
set(XMRIG_ARM_CPU_MAP_ca76ae "cortex-a76ae")
set(XMRIG_ARM_CPU_MAP_ca77   "cortex-a77")
set(XMRIG_ARM_CPU_MAP_ca78   "cortex-a78")
set(XMRIG_ARM_CPU_MAP_ca78ae "cortex-a78ae")
set(XMRIG_ARM_CPU_MAP_ca78c  "cortex-a78c")
set(XMRIG_ARM_CPU_MAP_ca510  "cortex-a510")
set(XMRIG_ARM_CPU_MAP_ca520  "cortex-a520")
set(XMRIG_ARM_CPU_MAP_ca710  "cortex-a710")
set(XMRIG_ARM_CPU_MAP_ca715  "cortex-a715")
set(XMRIG_ARM_CPU_MAP_ca720  "cortex-a720")
set(XMRIG_ARM_CPU_MAP_ca725  "cortex-a725")
set(XMRIG_ARM_CPU_MAP_kryo   "kryo")           # Qualcomm
set(XMRIG_ARM_CPU_MAP_exm3   "exynos-m3")      # Samsung
set(XMRIG_ARM_CPU_MAP_exm4   "exynos-m4")
set(XMRIG_ARM_CPU_MAP_exm5   "exynos-m5")
set(XMRIG_ARM_CPU_MAP_falkor "falkor")         # Qualcomm
set(XMRIG_ARM_CPU_MAP_saphira "saphira")       # Qualcomm
set(XMRIG_ARM_CPU_MAP_thunderx "thunderx")     # Marvell/Cavium, server
set(XMRIG_ARM_CPU_MAP_thunderx2t99 "thunderx2t99")
set(XMRIG_ARM_CPU_MAP_tsv110 "tsv110")         # HiSilicon
set(XMRIG_ARM_CPU_MAP_a64fx  "a64fx")          # Fujitsu, HPC
set(XMRIG_ARM_CPU_MAP_ampere1  "ampere1")      # Ampere Computing, server
set(XMRIG_ARM_CPU_MAP_ampere1a "ampere1a")
set(XMRIG_ARM_CPU_MAP_nve1   "neoverse-e1")    # ARM Neoverse, server
set(XMRIG_ARM_CPU_MAP_nvn1   "neoverse-n1")
set(XMRIG_ARM_CPU_MAP_nvn2   "neoverse-n2")
set(XMRIG_ARM_CPU_MAP_nvn3   "neoverse-n3")
set(XMRIG_ARM_CPU_MAP_nvv1   "neoverse-v1")
set(XMRIG_ARM_CPU_MAP_nvv2   "neoverse-v2")
set(XMRIG_ARM_CPU_MAP_nvv3   "neoverse-v3")
set(XMRIG_ARM_CPU_MAP_cx1    "cortex-x1")      # ARM "big" cores
set(XMRIG_ARM_CPU_MAP_cx2    "cortex-x2")
set(XMRIG_ARM_CPU_MAP_cx3    "cortex-x3")
set(XMRIG_ARM_CPU_MAP_cx4    "cortex-x4")
set(XMRIG_ARM_CPU_MAP_cx925  "cortex-x925")
# Deliberately NOT mapped: a few of pangz-lab/verus_miner-release's v6.0.0
# codenames (apa7, apa10, apa14, apm1, cr82, cx1c) don't have a confident,
# verifiable match to a real GCC/Clang -mcpu identifier -- guessing wrong
# here would silently build with the WRONG core's scheduling model instead
# of just falling back, which is worse than not mapping them at all. Passing
# one of those codes (or any other unmapped one) still works: it's tried
# verbatim as a -mcpu value, verified the same way, falls back to generic if
# the toolchain doesn't recognize it either.

# xmrig_resolve_arm_cpu(<requested> <out_flags_var> <out_crypto_var>)
#
# Resolves `requested` (a short code above, or a raw -mcpu value) against the
# installed compiler. Sets `<out_flags_var>` to the -mcpu (or -march) flags to
# use and `<out_crypto_var>` to whether the resolved flags include crypto
# extension support. Falls back to the generic -march=armv8-a[+crypto] (which
# the caller must already have computed and passed in as the current value of
# both out variables) if nothing about `requested` compiles.
function(xmrig_resolve_arm_cpu requested out_flags_var out_crypto_var)
    if (DEFINED XMRIG_ARM_CPU_MAP_${requested})
        set(mcpu_name "${XMRIG_ARM_CPU_MAP_${requested}}")
    else()
        set(mcpu_name "${requested}")
    endif()

    # Try with the crypto extension suffix first (AES/PMULL -- what VerusHash's
    # sse2neon path and this fork's other ARM AES paths actually need), then
    # without it (some -mcpu names already imply crypto and reject the
    # explicit suffix on certain compiler versions), before giving up.
    set(flag_with_crypto "-mcpu=${mcpu_name}+crypto")
    string(MAKE_C_IDENTIFIER "XMRIG_ARM_CPU_HAS_${mcpu_name}_crypto" check_var_1)
    CHECK_CXX_COMPILER_FLAG("${flag_with_crypto}" ${check_var_1})

    if (${check_var_1})
        message(STATUS "ARM_CPU=${requested}: using ${flag_with_crypto}")
        set(${out_flags_var} "${flag_with_crypto}" PARENT_SCOPE)
        set(${out_crypto_var} TRUE PARENT_SCOPE)
        return()
    endif()

    set(flag_plain "-mcpu=${mcpu_name}")
    string(MAKE_C_IDENTIFIER "XMRIG_ARM_CPU_HAS_${mcpu_name}" check_var_2)
    CHECK_CXX_COMPILER_FLAG("${flag_plain}" ${check_var_2})

    if (${check_var_2})
        message(STATUS "ARM_CPU=${requested}: using ${flag_plain} (compiler rejected the +crypto suffix for this core; verifying crypto extension separately)")
        # -mcpu accepted without +crypto doesn't tell us whether AES/PMULL are
        # actually on for this core -- re-check the tree-wide crypto flag
        # combined with this -mcpu so sse2neon still gets real instructions
        # when the core supports it.
        CHECK_CXX_COMPILER_FLAG("${flag_plain}+crypto" ${check_var_1}_retry)
        set(${out_flags_var} "${flag_plain}" PARENT_SCOPE)
        set(${out_crypto_var} ${${check_var_1}_retry} PARENT_SCOPE)
        return()
    endif()

    message(WARNING "ARM_CPU=${requested} (-mcpu=${mcpu_name}) is not recognized by this compiler (${CMAKE_CXX_COMPILER_ID} ${CMAKE_CXX_COMPILER_VERSION}) -- falling back to the generic ARM8_CXX_FLAGS (-march=armv8-a[+crypto]). This is not a build error; it just means no per-core tuning for this build.")
    # out_flags_var / out_crypto_var already hold the generic fallback the
    # caller passed in -- leave them untouched.
endfunction()
