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

#include <cmath>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#include "base/net/stratum/VerusStratumClient.h"
#include "3rdparty/rapidjson/document.h"
#include "base/io/json/Json.h"
#include "base/io/json/JsonRequest.h"
#include "base/io/log/Log.h"
#include "base/kernel/interfaces/IClientListener.h"
#include "base/tools/Cvt.h"
#include "crypto/verushash/verushash.h"
#include "net/JobResult.h"


namespace {


// Byte offsets within the 140-byte VerusHash block header (see equi_stratum_notify /
// stratum_gen_work's ALGO_EQUIHASH branch in monkins1010/ccminer). Mirrors verushash::kInputSize
// et al in crypto/verushash/verushash.h.
constexpr size_t kHeaderSize      = 140;
constexpr size_t kVersionOff      = 0;
constexpr size_t kPrevHashOff     = 4;
constexpr size_t kMerkleOff       = 36;  // coinb1 ("merkle" per ccminer's own comment)
constexpr size_t kReservedOff     = 68;  // coinb2 ("blank/reserved", hashFinalSaplingRoot)
constexpr size_t kNTimeOff        = 100;
constexpr size_t kNBitsOff        = 104;
constexpr size_t kNNonceOff       = 108; // 32 bytes, words 27..34 (EQNONCE_OFFSET=30 anchors here)
constexpr size_t kNNonceSize      = 32;
constexpr size_t kEqNonceWordOff  = 120 - kNNonceOff; // word 30, relative to kNNonceOff == 12

constexpr size_t kSolutionSize    = 1344;
constexpr uint8_t kSolutionVarint[3] = { 0xfd, 0x40, 0x05 }; // CompactSize(1344), little-endian


inline void writeHex(char *dst, const uint8_t *src, size_t len)
{
    static const char *hexChars = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        dst[i * 2]     = hexChars[src[i] >> 4];
        dst[i * 2 + 1] = hexChars[src[i] & 0x0F];
    }
}


} // namespace


xmrig::VerusStratumClient::VerusStratumClient(int id, const char *agent, IClientListener *listener) :
    Client(id, agent, listener)
{
}


void xmrig::VerusStratumClient::login()
{
    m_results.clear();

    subscribe();
    authorize();
}


void xmrig::VerusStratumClient::onClose()
{
    m_authorized = false;
    Client::onClose();
}


const char *xmrig::VerusStratumClient::errorMessage(const rapidjson::Value &error)
{
    if (error.IsArray() && error.GetArray().Size() > 1) {
        auto &value = error.GetArray()[1];
        if (value.IsString()) {
            return value.GetString();
        }
    }

    if (error.IsString()) {
        return error.GetString();
    }

    if (error.IsObject()) {
        return Json::getString(error, "message");
    }

    return nullptr;
}


bool xmrig::VerusStratumClient::handleResponse(int64_t id, const rapidjson::Value &result, const rapidjson::Value &error)
{
    auto it = m_callbacks.find(id);
    if (it != m_callbacks.end()) {
        const uint64_t elapsed = Chrono::steadyMSecs() - it->second.ts;

        if (error.IsArray() || error.IsObject() || error.IsString()) {
            it->second.callback(error, false, elapsed);
        }
        else {
            it->second.callback(result, true, elapsed);
        }

        m_callbacks.erase(it);

        return true;
    }

    return handleSubmitResponse(id, errorMessage(error));
}


void xmrig::VerusStratumClient::subscribe()
{
    using namespace rapidjson;

    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    Value params(kArrayType);
    params.PushBack(StringRef(agent()), allocator);

    JsonRequest::create(doc, m_sequence, "mining.subscribe", params);

    send(doc, [this](const rapidjson::Value &result, bool success, uint64_t elapsed) { onSubscribeResponse(result, success, elapsed); });
}


void xmrig::VerusStratumClient::onSubscribeResponse(const rapidjson::Value &result, bool success, uint64_t)
{
    if (!success) {
        return;
    }

    try {
        if (!result.IsArray()) {
            throw std::runtime_error("invalid mining.subscribe response: result is not an array");
        }

        auto arr = result.GetArray();

        // Standard Stratum subscribe response: [subscriptions, extranonce1, extranonce2_size].
        // VerusCoin pools (per ccminer's stratum_parse_extranonce, pndx defaults to 1) put
        // extranonce1 at index 1, same as everywhere else; we derive extranonce2's size
        // ourselves from its length instead of trusting index 2 (VRSC's own xnonce2_size is
        // always "32 - len(extranonce1)", not whatever the pool separately reports there).
        if (arr.Size() <= 1 || !arr[1].IsString()) {
            throw std::runtime_error("invalid mining.subscribe response: no extranonce1");
        }

        setExtraNonce(arr[1].GetString());
    } catch (const std::exception &ex) {
        LOG_ERR("%s " RED("%s"), tag(), ex.what());
    }
}


void xmrig::VerusStratumClient::setExtraNonce(const char *hex)
{
    if (!hex) {
        return;
    }

    size_t len = strlen(hex);
    if (len & 1) {
        LOG_ERR("%s " RED("invalid extranonce1: odd number of hex chars"), tag());
        return;
    }

    const size_t size = len / 2;

    // ccminer's "verus" branch of stratum_parse_extranonce requires 3..12 raw bytes; be a
    // little more permissive here (a pool sending something outside that window is still
    // usable as long as it leaves room for a local extranonce2 half) since this is exactly the
    // kind of pool-specific detail that needs live confirmation against na.luckpool.net.
    if (size == 0 || size > kNNonceSize) {
        LOG_ERR("%s " RED("invalid extranonce1: unexpected length %zu"), tag(), size);
        return;
    }

    m_xnonce1.resize(size);
    if (!Cvt::fromHex(m_xnonce1.data(), m_xnonce1.size(), hex, len)) {
        LOG_ERR("%s " RED("invalid extranonce1: not valid hex"), tag());
        m_xnonce1.clear();
        return;
    }

    LOG_DEBUG("[%s] extranonce1 set to %s (%zu bytes, local extranonce2 %zu bytes)", url(), hex, size, kNNonceSize - size);
}


void xmrig::VerusStratumClient::authorize()
{
    using namespace rapidjson;

    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    Value params(kArrayType);
    params.PushBack(m_user.toJSON(), allocator);
    params.PushBack(m_password.toJSON(), allocator);

    JsonRequest::create(doc, m_sequence, "mining.authorize", params);

    send(doc, [this](const rapidjson::Value &result, bool success, uint64_t elapsed) { onAuthorizeResponse(result, success, elapsed); });
}


void xmrig::VerusStratumClient::onAuthorizeResponse(const rapidjson::Value &result, bool success, uint64_t)
{
    try {
        if (!success) {
            const auto message = errorMessage(result);
            throw std::runtime_error(message ? message : "mining.authorize call failed");
        }

        if (!result.IsBool()) {
            throw std::runtime_error("invalid mining.authorize response: result is not a boolean");
        }

        if (!result.GetBool()) {
            throw std::runtime_error("login failed");
        }
    } catch (const std::exception &ex) {
        LOG_ERR("%s " RED_BOLD("%s"), tag(), ex.what());

        close();
        return;
    }

    LOG_DEBUG("[%s] login succeeded", url());

    if (!m_authorized) {
        m_authorized = true;
        m_listener->onLoginSuccess(this);
    }
}


void xmrig::VerusStratumClient::parseNotification(const char *method, const rapidjson::Value &params, const rapidjson::Value &)
{
    // Note: the base Client::parse() only reaches parseNotification() for lines that carry no
    // numeric "id" (an id-bearing line is routed to parseResponse() instead, further up the
    // shared parser). client.show_message notifications from equihash-stratum pools are sent
    // with id:null in the common case (per equi_stratum_show_message's own early-return when id
    // is absent/null), so that's the only case reachable here -- no reply is expected or sent.

    if (strcmp(method, "mining.notify") == 0) {
        if (!params.IsArray() || !handleNotify(params)) {
            LOG_ERR("%s " RED("invalid mining.notify notification"), tag());
        }
        return;
    }

    if (strcmp(method, "mining.set_target") == 0) {
        if (!params.IsArray() || !handleSetTarget(params)) {
            LOG_ERR("%s " RED("invalid mining.set_target notification"), tag());
        }
        return;
    }

    if (strcmp(method, "mining.set_difficulty") == 0) {
        if (!params.IsArray() || !handleSetDifficulty(params)) {
            LOG_ERR("%s " RED("invalid mining.set_difficulty notification"), tag());
        }
        return;
    }

    // Non-standard: VerusCoin/equihash-stratum pools smuggle block height through
    // client.show_message instead of a dedicated field (see equi_stratum_show_message).
    if (strcmp(method, "client.show_message") == 0) {
        handleShowMessage(params);
        return;
    }
}


bool xmrig::VerusStratumClient::handleNotify(const rapidjson::Value &params)
{
    auto arr = params.GetArray();
    if (arr.Size() < 9) {
        return false;
    }

    int p = 0;
    const auto &vJobId    = arr[p++];
    const auto &vVersion  = arr[p++];
    const auto &vPrevHash = arr[p++];
    const auto &vCoinb1   = arr[p++];
    const auto &vCoinb2   = arr[p++];
    const auto &vStime    = arr[p++];
    const auto &vNbits    = arr[p++];
    const auto &vClean    = arr[p++];
    const auto &vSolution = arr[p++];
    (void)vClean; // "clean jobs" flag: not currently used -- we always replace m_job on any
                  // content change (see the m_job != job check below), so nothing is lost by
                  // not special-casing a forced restart here.

    if (!vJobId.IsString() || !vVersion.IsString() || !vPrevHash.IsString() || !vCoinb1.IsString() ||
        !vCoinb2.IsString() || !vStime.IsString() || !vNbits.IsString() || !vSolution.IsString()) {
        return false;
    }

    if (strlen(vPrevHash.GetString()) != 64 || strlen(vVersion.GetString()) != 8 ||
        strlen(vCoinb1.GetString()) != 64 || strlen(vCoinb2.GetString()) != 64 ||
        strlen(vNbits.GetString()) != 8 || strlen(vStime.GetString()) != 8) {
        return false;
    }

    // NOTE (live-pool finding, na.luckpool.net): unlike ccminer's reference, which always
    // expects a full 1344-byte solution, real-world notifications observed here carry a much
    // shorter hex string (e.g. 229 or 177 bytes, varying per job). VerusCoin's actual on-wire
    // solution (see VerusCoin/VerusCoin's primitives/solutiondata.h, CVerusSolutionVector) is a
    // structured, variable-length PBaaS blob (descriptor + optional merge-mining headers +
    // extra data), most of whose trailing bytes are typically zero on a plain (non-PBaaS,
    // non-merge-mined) chain tip -- consistent with a pool-side stratum shim trimming trailing
    // zero bytes before hex-encoding to save bandwidth, same idea as trailing-zero RLE that
    // VerusCoin's own CCompactSolutionVector does for storage. We treat whatever's given as a
    // left-aligned prefix of the full 1344-byte solution and zero-pad the rest, which is exactly
    // what re-serializing "solution + zeros" produces if that hypothesis is right. This is
    // unverified until we see whether shares built this way are accepted by the pool.
    const size_t solutionHexLen = strlen(vSolution.GetString());
    if (solutionHexLen == 0 || solutionHexLen > kSolutionSize * 2 || (solutionHexLen & 1)) {
        LOG_ERR("%s " RED("mining.notify: unexpected solution length %zu (want 1..%zu, even)"), tag(), solutionHexLen, kSolutionSize * 2);
        return false;
    }

    if (m_xnonce1.empty()) {
        LOG_ERR("%s " RED("mining.notify received before extranonce1 was set"), tag());
        return false;
    }

    // -- Assemble the 140-byte header, exactly as stratum_gen_work's ALGO_EQUIHASH branch does.
    uint8_t header[kHeaderSize] = { 0 };

    if (!Cvt::fromHex(header + kVersionOff,  4,  vVersion.GetString(),  8) ||
        !Cvt::fromHex(header + kPrevHashOff, 32, vPrevHash.GetString(), 64) ||
        !Cvt::fromHex(header + kMerkleOff,   32, vCoinb1.GetString(),   64) ||
        !Cvt::fromHex(header + kReservedOff, 32, vCoinb2.GetString(),   64) ||
        !Cvt::fromHex(header + kNTimeOff,    4,  vStime.GetString(),    8) ||
        !Cvt::fromHex(header + kNBitsOff,    4,  vNbits.GetString(),    8)) {
        return false;
    }

    // nNonce field (32 bytes): pool's extranonce1 first, local extranonce2 (kept zero -- see
    // VerusStratumClient.h) after it, zero-padded to 32 bytes.
    memcpy(header + kNNonceOff, m_xnonce1.data(), m_xnonce1.size());
    // remaining bytes already zero-initialized above.

    // Zero-initialized (Buffer == std::vector<uint8_t>); we only decode into the prefix the
    // pool actually sent, per the note above.
    Buffer solution(kSolutionSize, 0);
    if (!Cvt::fromHex(solution.data(), solutionHexLen / 2, vSolution.GetString(), solutionHexLen)) {
        return false;
    }

    LOG_INFO("%s verus solution: pool sent %zu of %zu bytes (job %s)", tag(), solutionHexLen / 2, kSolutionSize, vJobId.GetString());

    // solution[0] is a VerusHash "extended solution" format version byte (not the block header's
    // own nVersion field), and solution[5] gates whether this job uses the extended layout --
    // see verusscan.cpp's `if (version >= 7 && work->solution[5] > 0)` branch.
    const bool extended = (solution[0] >= 7) && (solution[5] > 0);

    // DIAGNOSTIC (temporary): decode the solution head the same way VerusCoin core's own
    // CPBaaSSolutionDescriptor(vch) constructor does (primitives/solutiondata.h), so we can see
    // the real version/descrBits/numPBaaSHeaders/extraDataSize this pool is sending instead of
    // guessing from length alone. Remove once submissions are confirmed accepted.
    {
        const uint32_t descrVersion = solution[0] | (solution[1] << 8) | (solution[2] << 16) | (static_cast<uint32_t>(solution[3]) << 24);
        const uint8_t  descrBits    = solution[4];
        const uint8_t  numPBaaS     = solution[5];
        const uint16_t extraDataSz  = solution[6] | (static_cast<uint16_t>(solution[7]) << 8);
        LOG_INFO("%s verus solution descriptor: version=%u descrBits=%u numPBaaSHeaders=%u extraDataSize=%u extended=%s head=%02x%02x%02x%02x%02x%02x%02x%02x",
                  tag(), descrVersion, descrBits, numPBaaS, extraDataSz, extended ? "true" : "false",
                  solution[0], solution[1], solution[2], solution[3], solution[4], solution[5], solution[6], solution[7]);
    }

    uint8_t nonceSpacePrefix[11] = { 0 };

    uint8_t blob[verushash::kInputSize] = { 0 };
    memcpy(blob, header, kHeaderSize);
    memcpy(blob + kHeaderSize, kSolutionVarint, sizeof(kSolutionVarint));
    memcpy(blob + kHeaderSize + sizeof(kSolutionVarint), solution.data(), solution.size());

    if (extended) {
        // Capture the pool-assigned nNonce bytes that verusscan.cpp relocates into the blob's
        // tail BEFORE zeroing the header fields the extended layout doesn't hash directly.
        memcpy(nonceSpacePrefix,     header + kNNonceOff,     7); // pdata[EQNONCE_OFFSET-3..], 7B
        memcpy(nonceSpacePrefix + 7, header + kNNonceOff + 20, 4); // pdata[EQNONCE_OFFSET+2], word 32

        memset(blob + kPrevHashOff, 0, 32 + 32 + 32);   // hashPrevBlock, hashMerkleRoot, hashFinalSaplingRoot
        memset(blob + kNBitsOff,    0, 4);              // nBits
        memset(blob + kNNonceOff,  0, kNNonceSize);      // nNonce
        memset(blob + kHeaderSize + sizeof(kSolutionVarint) + 8, 0, 64); // solution[8:72]
    }

    memcpy(blob + verushash::kNonceOffset, nonceSpacePrefix, sizeof(nonceSpacePrefix));
    // blob[1483..1487) (the free-running local nonce) is left zero here; XMRig's per-thread
    // nonce loop overwrites exactly those 4 bytes on every attempt (Job::nonceOffset()==1483).

    char blobHex[verushash::kInputSize * 2 + 1];
    writeHex(blobHex, blob, sizeof(blob));
    blobHex[sizeof(blobHex) - 1] = '\0';

    Job job;
    job.setId(vJobId.GetString());
    job.setAlgorithm(m_pool.algorithm());
    job.setHeight(m_height);

    // Prefer the pool's real 256-bit target (mining.set_target), applied directly via
    // Job::setTarget() -- see handleSetTarget()'s comment for why this avoids a scale mismatch
    // that job.setDiff()'s diff-based round trip had. Only fall back to the diff-based path if
    // this pool never sends mining.set_target at all (mining.set_difficulty only).
    if (m_haveNextTarget) {
        job.setTarget(m_nextTargetHex);
        // setTarget() also sets m_diff = toDiff(m_target) as a side effect (Job::toDiff() is the
        // Monero/RandomX-style 2^64/target formula) -- that's a DIFFERENT scale than VerusCoin's
        // own diff convention (target_to_diff_verus, what m_nextDiff holds and what the pool's own
        // dashboard/vardiff logic uses), so left alone it makes "new job"/"accepted" log lines show
        // a diff number that doesn't match the pool's. It does NOT affect share acceptance --
        // job.target() (m_target) is the raw bytes from the pool either way -- only what gets
        // printed. Override it with the correctly-scaled number for display/logging.
        if (m_nextDiff > 0.0) {
            job.setDisplayDiff(static_cast<uint64_t>(std::ceil(m_nextDiff)));
        }
        // DIAGNOSTIC (temporary): confirm the local target actually being used for the share
        // check, to compare against the diff-based m_target this replaces. Remove once diff
        // scaling is confirmed correct by acceptance rate.
        LOG_INFO("%s verus job target: hex=%s -> local target=%llu (display diff=%llu)", tag(), m_nextTargetHex,
                  static_cast<unsigned long long>(job.target()), static_cast<unsigned long long>(job.diff()));
    } else {
        job.setDiff(m_nextDiff > 0.0 ? static_cast<uint64_t>(std::ceil(m_nextDiff)) : 1);
    }

    if (!job.setBlob(blobHex)) {
        LOG_ERR("%s " RED("failed to build VerusHash job blob"), tag());
        return false;
    }

    bool ok = true;
    m_listener->onVerifyAlgorithm(this, job.algorithm(), &ok);
    if (!ok) {
        if (!isQuiet()) {
            LOG_ERR("[%s] incompatible/disabled algorithm \"%s\" detected, reconnect", url(), job.algorithm().name());
        }
        close();
        return true; // handled -- don't also log a generic "invalid notification"
    }

    // Stash what mining.submit needs (see submit() below).
    m_jobId            = vJobId.GetString();
    memcpy(m_ntimeRaw, header + kNTimeOff, 4);
    memcpy(m_nbitsRaw, header + kNBitsOff, 4);
    m_solution          = std::move(solution);
    m_extendedSolution  = extended;
    memcpy(m_nonceSpacePrefix, nonceSpacePrefix, sizeof(m_nonceSpacePrefix));

    if (m_job != job) {
        m_job = std::move(job);

        if (!m_authorized) {
            m_authorized = true;
            m_listener->onLoginSuccess(this);
        }

        m_listener->onJobReceived(this, m_job, params);
    }
    else if (!isQuiet()) {
        LOG_WARN("%s " YELLOW("duplicate job received"), tag());
    }

    return true;
}


bool xmrig::VerusStratumClient::handleSetTarget(const rapidjson::Value &params)
{
    auto arr = params.GetArray();
    if (arr.Empty() || !arr[0].IsString()) {
        return false;
    }

    const char *targetHex = arr[0].GetString();
    if (strlen(targetHex) != 64) {
        return false;
    }

    uint8_t targetBin[32];
    if (!Cvt::fromHex(targetBin, sizeof(targetBin), targetHex, 64)) {
        return false;
    }

    // targetBin as received (hex-decoded left to right) is the usual Bitcoin/Zcash-family display
    // convention: index 0 is the MOST significant byte (uint256::GetHex() prints its internal
    // little-endian byte[31] first). CpuWorker's local share check, however, reads the hash the
    // opposite way -- `*reinterpret_cast<uint64_t*>(hash + 24)`, i.e. hash[31] is the most
    // significant byte of that 64-bit read (native/LE interpretation, matching every other
    // algorithm's hash output convention in this fork). So to compare like with like, the target
    // needs the SAME byte order as the hash: byte-reverse targetBin into targetBe (index 31 = most
    // significant), then take targetBe's top 8 bytes (offset 24) directly as the local 64-bit
    // target -- see m_nextTargetHex below, applied in handleNotify() via Job::setTarget().
    //
    // (Previously this function only derived a VerusCoin-scale "network difficulty" number from
    // the target -- via target_to_diff_verus()'s compact-exponent math below, still used for the
    // diff NUMBER shown per share -- and Job::setDiff() converted that back into a 64-bit target
    // using XMRig's Monero-style `target = 2^64 / diff` formula. Confirmed live against
    // na.luckpool.net: that round trip produced a target far too loose for VerusHash's real
    // 256-bit target space -- most locally-"found" shares were rejected "low difficulty share" by
    // the pool, with only a handful (matching a target roughly an order of magnitude too large)
    // slipping through by chance. Using the pool's real target's top 8 bytes directly, with no
    // diff-based round trip, avoids that scale mismatch entirely.)
    uint8_t targetBe[32] = { 0 };
    uint8_t *bitsStart = nullptr;
    int filled = 0;

    for (int i = 0; i < 32 && filled < 8; ++i) {
        targetBe[31 - i] = targetBin[i];
        if (targetBin[i]) {
            ++filled;
            if (!bitsStart) {
                bitsStart = &targetBin[i];
            }
        }
    }

    writeHex(m_nextTargetHex, targetBe + 24, 8);
    m_nextTargetHex[16] = '\0';
    m_haveNextTarget = true;

    if (!bitsStart) {
        m_nextDiff = 0.0;
        return true;
    }

    const int padding = static_cast<int>(&targetBin[31] - bitsStart);
    const uint8_t exponent = static_cast<uint8_t>(((padding * 8 + 1) + 7) / 8);

    if (exponent < 3 || exponent > 32) {
        return false;
    }

    uint32_t targetBits = 0;
    memcpy(&targetBits, &targetBe[exponent - 3], 3);
    targetBits |= (static_cast<uint32_t>(exponent) << 24);

    const unsigned exponentDiff = 8u * (0x20u - ((targetBits >> 24) & 0xFFu));
    const double significand = static_cast<double>(targetBits & 0xFFFFFFu);
    m_nextDiff = significand > 0.0 ? std::ldexp(0x0f0f0f / significand, static_cast<int>(exponentDiff)) : 0.0;

    // DIAGNOSTIC (temporary): most shares are being rejected "low difficulty share" even though
    // a handful ARE accepted -- consistent with the local target (Job::setDiff() -> 64-bit
    // Monero-style m_target) being systematically looser than what the pool actually enforces,
    // rather than a data/hash-content bug. This log settles whether the pool even uses
    // mining.set_target at all (vs. mining.set_difficulty below) and shows the raw value so the
    // conversion above can be checked against it. Remove once diff scaling is confirmed correct.
    LOG_INFO("%s verus set_target: raw=%s -> nextDiff=%.0f", tag(), targetHex, m_nextDiff);

    return true;
}


bool xmrig::VerusStratumClient::handleSetDifficulty(const rapidjson::Value &params)
{
    auto arr = params.GetArray();
    if (arr.Empty() || (!arr[0].IsNumber())) {
        return false;
    }

    m_nextDiff = arr[0].GetDouble();

    // DIAGNOSTIC (temporary): see handleSetTarget()'s comment above -- this settles whether the
    // pool uses mining.set_difficulty (this path) and shows the raw number the pool sent, to
    // check against the diff actually shown on each "new job"/"rejected" log line.
    LOG_INFO("%s verus set_difficulty: raw=%.6f", tag(), m_nextDiff);

    return true;
}


void xmrig::VerusStratumClient::handleShowMessage(const rapidjson::Value &params)
{
    if (!params.IsArray() || params.Empty() || !params[0].IsString()) {
        return;
    }

    char symbol[32] = { 0 };
    uint32_t height = 0;
    const int matched = sscanf(params[0].GetString(), "equihash %31s block %u", symbol, &height);
    if (matched > 1 && height) {
        m_height = height;
    }
}


int64_t xmrig::VerusStratumClient::submit(const JobResult &result)
{
#   ifndef XMRIG_PROXY_PROJECT
    if ((m_state != ConnectedState) || !m_authorized) {
        return -1;
    }
#   endif

    if (m_jobId.isNull() || m_xnonce1.empty()) {
        return -1;
    }

    // -- nonce field (mining.submit's 4th param): a 32-byte buffer built the same way
    // equi_stratum_submit() builds it -- start from what the header's nNonce field looked like
    // at hash time (zeroed for an extended-solution job, pool extranonce1 + zero otherwise),
    // then unconditionally stamp word 30 (EQNONCE_OFFSET) with the local nonce that was
    // actually found (work->data[EQNONCE_OFFSET] = work->nonces[idnonce] in verusscan.cpp).
    uint8_t nonceBuf[kNNonceSize] = { 0 };
    if (!m_extendedSolution) {
        memcpy(nonceBuf, m_xnonce1.data(), m_xnonce1.size());
    }

    const uint32_t localNonce = static_cast<uint32_t>(result.nonce);
    memcpy(nonceBuf + kEqNonceWordOff, &localNonce, 4);

    const size_t nonceLen = kNNonceSize - m_xnonce1.size();
    char nonceHex[kNNonceSize * 2 + 1];
    writeHex(nonceHex, nonceBuf + m_xnonce1.size(), nonceLen);
    nonceHex[nonceLen * 2] = '\0';

    // -- ntime field: equi_stratum_submit does sprintf("%08x", swab32(work->data[25])).
    // work->data[25] is those same 4 raw bytes read as a little-endian uint32 (no swap at
    // storage time -- hex2bin() just copies them in wire order); swab32() then byte-reverses
    // that value; and %08x prints a uint32 most-significant-byte-first. Reading a LE-interpreted
    // value back out big-endian-first is exactly undoing the LE interpretation -- the two
    // reversals cancel out, so the resulting hex string is identical to the original wire bytes.
    // (A previous version of this function reversed the bytes here, which was wrong -- it
    // produced "ntime out of range" rejections against na.luckpool.net; see git history.)
    char timeHex[9];
    writeHex(timeHex, m_ntimeRaw, 4);
    timeHex[8] = '\0';

    // -- solution field: 3-byte varint + 1344-byte solution, with the last 15 bytes replaced by
    // the same nonce-tail bytes the accepted hash actually used (nonceSpacePrefix + the local
    // nonce). NOTE: equi_stratum_submit() also zeroes solution[8:72] and then immediately
    // restores the original bytes there before sending -- a documented no-op once you track it
    // through (see VerusStratumClient.cpp git history / porte-verushash-spec.md), so we just
    // leave the original solution bytes at [8:72] untouched here instead of round-tripping them.
    Buffer submitSolution = m_solution;
    if (submitSolution.size() != kSolutionSize) {
        return -1;
    }

    memcpy(submitSolution.data() + (kSolutionSize - verushash::kNonceFieldSize),
           m_nonceSpacePrefix, sizeof(m_nonceSpacePrefix));
    memcpy(submitSolution.data() + (kSolutionSize - 4), &localNonce, 4);

    char solHex[3 * 2 + kSolutionSize * 2 + 1];
    writeHex(solHex, kSolutionVarint, 3);
    writeHex(solHex + 6, submitSolution.data(), submitSolution.size());
    solHex[sizeof(solHex) - 1] = '\0';

    using namespace rapidjson;

    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    Value params(kArrayType);
    params.PushBack(m_user.toJSON(), allocator);
    params.PushBack(Value(m_jobId.data(), allocator), allocator);
    params.PushBack(Value(timeHex, allocator), allocator);
    params.PushBack(Value(nonceHex, allocator), allocator);
    params.PushBack(Value(solHex, allocator), allocator);

    JsonRequest::create(doc, m_sequence, "mining.submit", params);

#   ifdef XMRIG_PROXY_PROJECT
    m_results[m_sequence] = SubmitResult(m_sequence, result.diff, result.actualDiff(), result.id, 0);
#   else
    m_results[m_sequence] = SubmitResult(m_sequence, result.diff, result.actualDiff(), 0, result.backend);
#   endif

    return send(doc);
}
