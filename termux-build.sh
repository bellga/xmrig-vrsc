#!/usr/bin/env bash
# termux-build.sh -- build xmrig-vrsc natively on-device for Termux or UserLAnd (ARM64/ARMv7),
# with automatic per-core tuning (see cmake/arm-cpu-tiers.cmake, step 2 of the mobile/ARM work).
#
# This is step 3 of the mobile/ARM support work documented in the project's
# claude/estado-operacional-e-entregaveis.md: (1) VerusHash ported to ARM (sse2neon),
# (2) opt-in per-core -mcpu tuning via -DARM_CPU=<code>, (3) this script, which detects the
# device's CPU and environment and drives (1)+(2) automatically.
#
# Usage:
#   ./termux-build.sh                  # auto-detect everything
#   ./termux-build.sh cortex-a76       # force a specific -mcpu tier (skips detection)
#   ARM_CPU=ca76 ./termux-build.sh     # same, via env var
#   ARM_CPU=none ./termux-build.sh     # force the generic tier, skip per-core tuning entirely
#
# Env vars (all optional): REPO_URL, REPO_REF, BUILD_DIR, JOBS, ARM_CPU (mirrors
# build-from-source.sh's REPO_URL/REPO_REF/BUILD_DIR/JOBS convention).
#
# NOT validated on a real device or inside a real Termux/UserLAnd userland -- this was written
# and reviewed in a cloud sandbox with no ARM/Android hardware available. The CPU-detection table
# below is best-effort (see the comment above it); the actual xmrig build+run needs to be
# confirmed on-device. Please paste back the output if something looks wrong.

set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/bellga/xmrig-vrsc.git}"
REPO_REF="${REPO_REF:-master}"
BUILD_DIR="${BUILD_DIR:-$HOME/xmrig-vrsc}"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 2)}"
ARM_CPU_OVERRIDE="${1:-${ARM_CPU:-}}"

log()  { printf '\033[1;36m[termux-build]\033[0m %s\n' "$*" >&2; }
warn() { printf '\033[1;33m[termux-build] WARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[termux-build] ERROR:\033[0m %s\n' "$*" >&2; exit 1; }
# log/warn/die all write to stderr, not stdout, on purpose: detect_arm_cpu() below is called as
# RESOLVED_ARM_CPU="$(detect_arm_cpu)", which captures its ENTIRE stdout -- if log() wrote to
# stdout, that captured value would include the log line's text glued onto the actual detected
# code instead of just the code, silently corrupting the -DARM_CPU value passed to cmake. Found
# by testing this function standalone against a mocked /proc/cpuinfo before trusting it.

# ---------------------------------------------------------------------------
# 1. Environment detection: Termux (own package manager, own prefix) vs.
#    UserLAnd/proot-distro (a real Debian/Ubuntu userland running under Android,
#    apt-based, otherwise behaves like any normal Linux ARM system) vs. some
#    other generic Linux-on-ARM the script wasn't specifically asked for but
#    can probably still handle via apt.
# ---------------------------------------------------------------------------
IS_TERMUX=0
if [ -n "${PREFIX:-}" ] && [[ "$PREFIX" == *com.termux* ]] && command -v pkg >/dev/null 2>&1; then
    IS_TERMUX=1
fi

if [ "$IS_TERMUX" -eq 1 ]; then
    log "Detected Termux (PREFIX=$PREFIX)."
    PKG_INSTALL() { pkg install -y "$@"; }
elif command -v apt-get >/dev/null 2>&1; then
    log "Detected an apt-based userland (UserLAnd/proot-distro Debian or Ubuntu, or generic)."
    PKG_INSTALL() { sudo apt-get install -y "$@" 2>/dev/null || apt-get install -y "$@"; }
else
    die "Neither Termux's 'pkg' nor 'apt-get' found. This script only knows how to install dependencies on Termux or an apt-based userland (UserLAnd/proot-distro). Install git, cmake, a C/C++ compiler, libuv, OpenSSL and (optionally) hwloc dev packages by hand, then re-run with the corresponding install step skipped, or open an issue with your environment's package manager."
fi

ARCH="$(uname -m)"
case "$ARCH" in
    aarch64|arm64) ARM_CMAKE_FLAG="-DARM_V8=ON" ;;
    armv7l|armv8l) ARM_CMAKE_FLAG="-DARM_V7=ON" ; warn "32-bit ARM (${ARCH}) detected. VerusHash will build and run correctly (validated under 32-bit-equivalent emulation), but only with the software AES/PMULL fallback -- cmake/cpu.cmake's hardware crypto-extension detection (and this script's per-core tuning below) only applies to ARM_TARGET 8 (64-bit) today. It will work, just slower than on aarch64." ;;
    *) die "This script targets ARM (aarch64/armv7). Detected uname -m = '${ARCH}', which isn't ARM -- nothing to do here." ;;
esac

# ---------------------------------------------------------------------------
# 2. CPU core detection (best-effort -- see the note printed to the user above).
#    (CPU implementer, CPU part) pairs come from /proc/cpuinfo, one line pair per
#    core on a big.LITTLE/DynamIQ system; we take the *biggest* core we can identify,
#    since that's normally where a miner thread benefits most from correct tuning,
#    and it's also very likely one of the cores actually used for mining threads.
#    Table cross-checked against publicly documented ARM MIDR part-number
#    allocations; confidence is high for well-established cores (A53..A78, X1,
#    A510/A710, X2) and lower for the newest ones (X3/X4, A520/A720/A725, X925) and
#    for vendor-custom cores (Kryo/Exynos-M) whose exact ID varies by SoC generation
#    -- if this guesses wrong, override with the first argument or $ARM_CPU (see
#    usage above); a wrong-but-real -mcpu value only costs some tuning precision,
#    it never breaks correctness (cmake/arm-cpu-tiers.cmake falls back safely even
#    if you pass something the installed compiler doesn't recognize at all).
declare -A MIDR_PART_MAP=(
    ["0x41:0xd03"]="ca53"    ["0x41:0xd04"]="ca35"     ["0x41:0xd05"]="ca55"
    ["0x41:0xd07"]="ca57"    ["0x41:0xd08"]="ca72"     ["0x41:0xd09"]="ca73"
    ["0x41:0xd0a"]="ca75"    ["0x41:0xd0b"]="ca76"     ["0x41:0xd0d"]="ca77"
    ["0x41:0xd0e"]="ca76ae"  ["0x41:0xd41"]="ca78"     ["0x41:0xd42"]="ca78ae"
    ["0x41:0xd44"]="cx1"     ["0x41:0xd46"]="ca510"    ["0x41:0xd47"]="ca710"
    ["0x41:0xd48"]="cx2"     ["0x41:0xd4b"]="ca78c"    ["0x41:0xd4d"]="ca715"
    ["0x41:0xd4e"]="cx3"     ["0x41:0xd80"]="ca520"    ["0x41:0xd81"]="ca720"
    ["0x41:0xd82"]="cx4"     ["0x41:0xd87"]="ca725"
    ["0x51:0x800"]="kryo"    ["0x51:0x801"]="kryo"     ["0x51:0x802"]="kryo"
    ["0x51:0x803"]="kryo"    ["0x51:0x804"]="kryo"     ["0x51:0x805"]="kryo"
    ["0x53:0x001"]="exm3"    ["0x53:0x002"]="exm3"     ["0x53:0x003"]="exm4"
    ["0x53:0x004"]="exm5"
)

detect_arm_cpu() {
    [ -r /proc/cpuinfo ] || { warn "/proc/cpuinfo not readable, can't auto-detect the CPU core."; return; }

    # Collect every (implementer, part) pair seen (big.LITTLE lists several),
    # remember the numerically largest "part" per implementer as a crude proxy
    # for "the big core" -- not perfectly reliable across vendors, but a
    # reasonable default; the point of the override flag is to correct this
    # when it guesses wrong.
    local impl="" part="" best_impl="" best_part=""
    while IFS= read -r line; do
        case "$line" in
            "CPU implementer"*) impl="$(printf '%s' "$line" | grep -oE '0x[0-9a-fA-F]+')" ;;
            "CPU part"*)
                part="$(printf '%s' "$line" | grep -oE '0x[0-9a-fA-F]+')"
                if [ -n "$impl" ] && [ -n "$part" ]; then
                    if [ -z "$best_part" ] || [ $((part)) -gt $((best_part)) ]; then
                        best_impl="$impl"; best_part="$part"
                    fi
                fi
                ;;
        esac
    done < /proc/cpuinfo

    if [ -z "$best_impl" ]; then
        warn "Couldn't find 'CPU implementer'/'CPU part' lines in /proc/cpuinfo (some Android kernels hide these) -- no per-core tuning will be applied, only the generic ARMv8-A+crypto baseline."
        return
    fi

    local key="${best_impl}:${best_part}"
    local code="${MIDR_PART_MAP[$key]:-}"
    if [ -n "$code" ]; then
        log "Detected CPU: implementer=${best_impl} part=${best_part} -> tier '${code}' (${MIDR_PART_MAP[$key]})"
        printf '%s' "$code"
    else
        warn "Detected CPU implementer=${best_impl} part=${best_part}, but that pair isn't in this script's table (see the confidence note above the table). Building with the generic ARMv8-A+crypto baseline instead of per-core tuning. If you know your CPU model, re-run as: ./termux-build.sh <mcpu-name-or-short-code>"
    fi
}

# Crypto extension presence, independent of knowing the exact core: this is what
# actually determines whether VerusHash gets real AES/PMULL instructions (see
# src/crypto/verushash/sse2neon/README.md) -- printed for visibility even when we
# can't identify the exact core.
detect_crypto_ext() {
    if [ -r /proc/cpuinfo ] && grep -qE '^Features.*\baes\b' /proc/cpuinfo && grep -qE '^Features.*\b(pmull|pmul)\b' /proc/cpuinfo; then
        log "CPU Features line reports aes+pmull: hardware crypto extension should be available."
    else
        warn "Couldn't confirm aes+pmull in /proc/cpuinfo's Features line -- the build will still work via sse2neon's portable fallback, just slower. (This check is informational; cmake's own CHECK_CXX_COMPILER_FLAG at configure time is the real gate.)"
    fi
}

if [ -n "$ARM_CPU_OVERRIDE" ] && [ "$ARM_CPU_OVERRIDE" != "none" ]; then
    log "Using explicitly requested ARM_CPU='${ARM_CPU_OVERRIDE}' (skipping auto-detection)."
    RESOLVED_ARM_CPU="$ARM_CPU_OVERRIDE"
elif [ "$ARM_CPU_OVERRIDE" = "none" ]; then
    log "ARM_CPU=none requested: building with the generic tier only, no per-core tuning."
    RESOLVED_ARM_CPU=""
else
    detect_crypto_ext
    RESOLVED_ARM_CPU="$(detect_arm_cpu || true)"
fi

# ---------------------------------------------------------------------------
# 3. Dependencies
# ---------------------------------------------------------------------------
log "Installing build dependencies..."
if [ "$IS_TERMUX" -eq 1 ]; then
    # Termux ships headers alongside the runtime libs in a single package (no
    # separate -dev split like Debian/Ubuntu). hwloc is NOT confirmed available in
    # Termux's own repo as of this writing -- if the 'pkg install hwloc' below
    # fails, the script disables it (-DWITH_HWLOC=OFF) rather than aborting, since
    # hwloc (CPU topology/NUMA) matters far less on a phone SoC than on a
    # multi-socket server, which is what it's really for.
    pkg update -y || true
    PKG_INSTALL git cmake clang make libuv openssl
    if PKG_INSTALL hwloc; then
        WITH_HWLOC_FLAG="-DWITH_HWLOC=ON"
    else
        warn "hwloc not available via 'pkg' in this Termux install -- building with -DWITH_HWLOC=OFF."
        WITH_HWLOC_FLAG="-DWITH_HWLOC=OFF"
    fi
    export CC=clang CXX=clang++
else
    PKG_INSTALL git cmake build-essential libuv1-dev libssl-dev
    if PKG_INSTALL libhwloc-dev; then
        WITH_HWLOC_FLAG="-DWITH_HWLOC=ON"
    else
        warn "libhwloc-dev not available -- building with -DWITH_HWLOC=OFF."
        WITH_HWLOC_FLAG="-DWITH_HWLOC=OFF"
    fi
fi

# ---------------------------------------------------------------------------
# 4. Clone or update
# ---------------------------------------------------------------------------
# BUILD_DIR defaults to $HOME/xmrig-vrsc -- the same directory the README tells
# people to `mkdir` and `cd` into before downloading this script (so the file
# can be fetched with a plain relative-path curl/chmod/run). That means on a
# first run BUILD_DIR usually already exists and already contains
# termux-build.sh itself, so a plain `git clone` into it fails with
# "already exists and is not an empty directory". Handle that case by turning
# the existing directory into the checkout in place (git init + remote +
# fetch + checkout -f) instead of requiring an empty target -- this leaves any
# untracked files (like this script) alone, since checkout only touches
# tracked paths.
if [ -d "$BUILD_DIR/.git" ]; then
    log "Existing checkout found at $BUILD_DIR, updating..."
    git -C "$BUILD_DIR" fetch origin "$REPO_REF"
    git -C "$BUILD_DIR" checkout "$REPO_REF"
    git -C "$BUILD_DIR" pull --ff-only origin "$REPO_REF"
elif [ -d "$BUILD_DIR" ] && [ -n "$(ls -A "$BUILD_DIR" 2>/dev/null)" ]; then
    log "Non-empty, non-git directory found at $BUILD_DIR (e.g. from downloading this script into it, per the README) -- initializing the repo in place instead of cloning fresh."
    git -C "$BUILD_DIR" init -q
    if git -C "$BUILD_DIR" remote get-url origin >/dev/null 2>&1; then
        git -C "$BUILD_DIR" remote set-url origin "$REPO_URL"
    else
        git -C "$BUILD_DIR" remote add origin "$REPO_URL"
    fi
    git -C "$BUILD_DIR" fetch origin "$REPO_REF"
    git -C "$BUILD_DIR" checkout -f "$REPO_REF"
else
    log "Cloning $REPO_URL (ref: $REPO_REF) into $BUILD_DIR..."
    git clone --branch "$REPO_REF" "$REPO_URL" "$BUILD_DIR"
fi

# ---------------------------------------------------------------------------
# 5. Configure + build
#
# CUDA/OpenCL are off by default: phone/tablet SoCs don't have a discrete GPU
# those backends target, and neither toolchain is normally present on
# Termux/UserLAnd -- override with WITH_CUDA=ON/WITH_OPENCL=ON env vars if you
# really have a reason to (e.g. building inside UserLAnd on an ARM SBC with a
# supported GPU attached). WITH_MSR is off for the same reason install.sh/
# build-from-source.sh already disable it on the Linux x86-64 scripts: no MSR
# module access without root, and it's not useful for VerusHash anyway.
# ---------------------------------------------------------------------------
BUILD_SUBDIR="$BUILD_DIR/build"
mkdir -p "$BUILD_SUBDIR"

CMAKE_ARGS=(
    "$ARM_CMAKE_FLAG"
    "$WITH_HWLOC_FLAG"
    -DWITH_CUDA="${WITH_CUDA:-OFF}"
    -DWITH_OPENCL="${WITH_OPENCL:-OFF}"
    -DWITH_MSR=OFF
    -DCMAKE_BUILD_TYPE=Release
)
if [ -n "$RESOLVED_ARM_CPU" ]; then
    CMAKE_ARGS+=(-DARM_CPU="$RESOLVED_ARM_CPU")
fi

log "Running: cmake -S $BUILD_DIR -B $BUILD_SUBDIR ${CMAKE_ARGS[*]}"
cmake -S "$BUILD_DIR" -B "$BUILD_SUBDIR" "${CMAKE_ARGS[@]}"

log "Building with $JOBS job(s)..."
cmake --build "$BUILD_SUBDIR" -j "$JOBS"

BIN="$BUILD_SUBDIR/xmrig"
[ -x "$BIN" ] || die "Build finished but $BIN wasn't produced -- check the log above."

log "Build finished: $BIN"
"$BIN" --version || warn "Built binary exists but --version failed to run -- please paste this script's full output back."

log "Done. Tier used: ${RESOLVED_ARM_CPU:-<generic ARMv8-A+crypto>}. Next: copy/adapt config.json and run-xmrig.sh next to this binary, or run '$BIN -c config.json' directly."
