# XMRig

[![Github All Releases](https://img.shields.io/github/downloads/xmrig/xmrig/total.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub release](https://img.shields.io/github/release/xmrig/xmrig/all.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub Release Date](https://img.shields.io/github/release-date/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/releases)
[![GitHub license](https://img.shields.io/github/license/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/blob/master/LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/stargazers)
[![GitHub forks](https://img.shields.io/github/forks/xmrig/xmrig.svg)](https://github.com/xmrig/xmrig/network)

XMRig is a high performance, open source, cross platform RandomX, KawPow, CryptoNight and [GhostRider](https://github.com/xmrig/xmrig/tree/master/src/crypto/ghostrider#readme) unified CPU/GPU miner and [RandomX benchmark](https://xmrig.com/benchmark). Official binaries are available for Windows, Linux, macOS and FreeBSD.

## Mining backends
- **CPU** (x86/x64/ARMv7/ARMv8/RISC-V)
- **OpenCL** for AMD GPUs.
- **CUDA** for NVIDIA GPUs via external [CUDA plugin](https://github.com/xmrig/xmrig-cuda).

## Download
* **[Binary releases](https://github.com/xmrig/xmrig/releases)**
* **[Build from source](https://xmrig.com/docs/miner/build)**

## Usage
The preferred way to configure the miner is the [JSON config file](https://xmrig.com/docs/miner/config) as it is more flexible and human friendly. The [command line interface](https://xmrig.com/docs/miner/command-line-options) does not cover all features, such as mining profiles for different algorithms. Important options can be changed during runtime without miner restart by editing the config file or executing [API](https://xmrig.com/docs/miner/api) calls.

* **[Wizard](https://xmrig.com/wizard)** helps you create initial configuration for the miner.
* **[Workers](http://workers.xmrig.info)** helps manage your miners via HTTP API.

## VerusHash (VRSC)
This fork adds VerusHash 2.2 support for mining VRSC (Verus Coin), ported from
`monkins1010/ccminer`'s VerusHash core into XMRig's threading/pool
infrastructure, with a dedicated VerusCoin Stratum client. Supported on Linux
x86-64 (AES-NI/PCLMUL) and ARM64/ARMv7 (NEON, AES/PMULL crypto extension when
available -- see the Mobile section below).

## Mobile (Termux / UserLAnd, ARM64 and ARMv7)
The ARM port includes optional per-CPU-core tuning (`-mcpu`, see
`cmake/arm-cpu-tiers.cmake`, ARM64 only for now). To build and run directly
on an Android device via [Termux](https://termux.dev) or
[UserLAnd](https://github.com/CypherpunkArmory/UserLAnd) -- no file transfer
needed, just copy-paste this into the terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/bellga/xmrig-vrsc/master/termux-build.sh -o termux-build.sh
chmod +x termux-build.sh
./termux-build.sh
```

The script detects Termux vs. UserLAnd (and picks the right package manager
for each), installs build dependencies, detects your CPU core from
`/proc/cpuinfo` to pick a tuning tier automatically, and compiles natively
on-device. If it guesses the wrong core (see the script's own comments for
its confidence notes on this), override it explicitly:

```bash
./termux-build.sh cortex-a76      # force a specific -mcpu tier
ARM_CPU=none ./termux-build.sh    # skip per-core tuning, use the generic ARMv8-A+crypto build
```

Confirmed working end-to-end on real hardware: ARM64 (Termux and UserLAnd,
2026-09-17) and 32-bit ARMv7 (UserLAnd on a Moto E7 Power, Cortex-A53,
2026-09-22 -- ~500-530 KH/s across 8 threads using the software AES/PMULL
fallback described in the warning above, mining VerusHash live against a
pool). If something looks wrong on your device, please open an issue with
the script's output.

**Note for UserLAnd on 32-bit ARM (armv7l) userlands specifically:** the
dependency-install step below works around a known `proot` limitation on
some vendor kernels, where `dpkg` fails to unpack a package with
`unable to read link '<path>': Invalid argument` while replacing a symlink
(hit repeatedly on Ubuntu's `perl` package during testing). The script now
detects that specific error and retries automatically; if it's a *different*
package failing the same way, it should still self-heal, but please open an
issue with the output if it doesn't.

## Hash tests
Run the offline CPU hash suite without pool, API, or miner network dependencies:

```bash
./tests/hash/check.sh
```

The script builds the standalone hash-test binary and runs both the regular known-answer suite and the full RandomX mode checks.

## Donations
* Default donation 1% (1 minute in 100 minutes) can be increased via option `donate-level` or disabled in source code.
* XMR: `89Qcz2NnSXtZf1NA5V8mt9DkswfbsN6HpaGaHbfnwwTuRwUDFVvgc7BZf1AKqPrmxzQktfB9hfLF8Znj8UwJxqFH4E5Nugc`

## Developers
* **[xmrig](https://github.com/xmrig)**
* **[sech1](https://github.com/SChernykh)**

## Contacts
* support@xmrig.com
* [reddit](https://www.reddit.com/user/XMRig/)
* [twitter](https://twitter.com/xmrig_dev)
