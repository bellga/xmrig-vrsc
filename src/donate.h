/* XMRig
 * Copyright (c) 2018-2022 SChernykh   <https://github.com/SChernykh>
 * Copyright (c) 2016-2022 XMRig       <https://github.com/xmrig>, <support@xmrig.com>
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

#ifndef XMRIG_DONATE_H
#define XMRIG_DONATE_H


#include <cstdint>


/*
 * Dev donation (this fork).
 *
 * Percentage of hashing power donated to this fork's maintainer. The DEFAULT is 5%, but the
 * end user can lower it in their config (`donate-level`) or via `--donate-level`. A MINIMUM of
 * 1% is enforced and cannot be bypassed: if the user configures 0 or a negative value, the
 * minimum applies instead of disabling donation entirely (see Pools::setDonateLevel()).
 *
 * Example of how it works for the setting of 1%:
 * Your miner will mine into your usual pool for a random time (in a range from 49.5 to 148.5 minutes),
 * then switch to the developer's pool for 1 minute, then switch again to your pool for 99 minutes
 * and then switch again to developer's pool for 1 minute; these rounds will continue until the miner stops.
 *
 * Randomised only on the first round to prevent waves on the donation pool.
 *
 * Switching is instant and only happens after a successful connection, so you never lose any hashes.
 */
constexpr const int kDefaultDonateLevel = 5;
constexpr const int kMinimumDonateLevel = 1;


/*
 * kDonateWalletGeneric is used for the existing MoneroOcean multi-algo donation pool
 * (xmrig.moneroocean.stream), which is what handles donation for every algorithm this fork
 * already supports (RandomX, CryptoNight, KawPow, GhostRider, ...). It expects a wallet address
 * valid for whatever coin that pool pays out donations in (check the pool's docs) -- it is NOT
 * necessarily a VRSC address.
 *
 * kDonateWalletVerus / kDonateHostVerus / kDonatePortVerus are for a SEPARATE, dedicated VRSC
 * pool that donation connects to specifically when the miner is actively running VerusHash (the
 * MoneroOcean pool above does not know about VerusHash yet). Filled in from a real verusminer
 * config: `-o stratum+tcp://na.luckpool.net:3960 -u RQrN3fm7tgNoSHJ1Beu9YQ3Ds3kgPo47Vu.SsA15`.
 * The ".SsA15" suffix on the login is a worker/rig name (per luckpool's docs, not part of the
 * VRSC address itself) -- kept here so donation traffic is distinguishable as its own worker on
 * the pool dashboard; drop it (or change it) if that's not wanted. Port 3960 is luckpool's plain
 * stratum+tcp (non-TLS) port -- see net/strategies/DonateStrategy.cpp's VerusHash pool, which is
 * built with tls=false to match.
 */
constexpr const char *kDonateWalletGeneric = "89Qcz2NnSXtZf1NA5V8mt9DkswfbsN6HpaGaHbfnwwTuRwUDFVvgc7BZf1AKqPrmxzQktfB9hfLF8Znj8UwJxqFH4E5Nugc";
constexpr const char *kDonateWalletVerus   = "RQrN3fm7tgNoSHJ1Beu9YQ3Ds3kgPo47Vu.SsA15";
constexpr const char *kDonateHostVerus     = "na.luckpool.net";
constexpr const uint16_t kDonatePortVerus  = 3960;


#endif // XMRIG_DONATE_H
