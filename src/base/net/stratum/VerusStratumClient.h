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

/*
 * Dedicated Stratum client for VerusCoin (VRSC) pools.
 *
 * This fork's other non-default client (EthStratumClient/AutoClient) speaks the Monero-"login"
 * and Ethash-family mining.notify dialects; neither is what VerusCoin pools speak. VRSC pools
 * (per monkins1010/ccminer's equi/equi-stratum.cpp, the reference this class ports) use a
 * bespoke, Equihash-derived dialect: mining.subscribe / mining.authorize / mining.notify (with
 * job_id/version/prevhash/coinb1/coinb2/stime/nbits/clean/solution fields, no merkle branch) /
 * mining.submit, plus a non-standard client.show_message text pattern for block height. See
 * claude/porte-verushash-spec.md for the full protocol writeup and the open questions flagged
 * below (diff scaling in particular needs live-pool calibration).
 */

#ifndef XMRIG_VERUSSTRATUMCLIENT_H
#define XMRIG_VERUSSTRATUMCLIENT_H


#include "base/net/stratum/Client.h"
#include "base/tools/Buffer.h"


namespace xmrig {


class VerusStratumClient : public Client
{
public:
    XMRIG_DISABLE_COPY_MOVE_DEFAULT(VerusStratumClient)

    VerusStratumClient(int id, const char *agent, IClientListener *listener);
    ~VerusStratumClient() override = default;

protected:
    int64_t submit(const JobResult &result) override;
    void login() override;
    void onClose() override;

    bool handleResponse(int64_t id, const rapidjson::Value &result, const rapidjson::Value &error) override;
    void parseNotification(const char *method, const rapidjson::Value &params, const rapidjson::Value &error) override;

private:
    static const char *errorMessage(const rapidjson::Value &error);

    void authorize();
    void onAuthorizeResponse(const rapidjson::Value &result, bool success, uint64_t elapsed);
    void onSubscribeResponse(const rapidjson::Value &result, bool success, uint64_t elapsed);
    void subscribe();

    void setExtraNonce(const char *hex);
    bool handleNotify(const rapidjson::Value &params);
    bool handleSetTarget(const rapidjson::Value &params);
    bool handleSetDifficulty(const rapidjson::Value &params);
    void handleShowMessage(const rapidjson::Value &params);

    bool m_authorized = false;

    // Pool-assigned extranonce1 (3-12 raw bytes per the "verus" branch of ccminer's
    // stratum_parse_extranonce) plus the local extranonce2 half that, together with it, fills
    // the 32-byte header nNonce field (bytes 108..139). We never grind extranonce2 ourselves
    // (XMRig's own per-thread 32-bit nonce counter, wired to blob offset 1483 via
    // Job::nonceOffset(), already provides per-attempt entropy -- see Job.cpp), so it's just
    // kept zero-filled at the right size.
    Buffer m_xnonce1;

    // Latest mining.notify job, kept around for mining.submit (job_id, ntime, the original
    // un-zeroed solution bytes, and whether the version>=7 "extended solution" branch applied).
    String  m_jobId;
    uint8_t m_ntimeRaw[4]  = { 0 }; // raw bytes as sent by the pool, no byte-swap
    uint8_t m_nbitsRaw[4]  = { 0 };
    Buffer  m_solution;             // original 1344-byte solution, unmodified
    bool    m_extendedSolution = false; // solution[0] >= 7 && solution[5] > 0 (see verushash pipeline notes)
    uint64_t m_height = 0;

    // target_to_diff_verus()-style diff, when the pool used mining.set_target instead of
    // mining.set_difficulty (see handleSetTarget()).
    double m_nextDiff = 0.0;
};


} /* namespace xmrig */


#endif /* XMRIG_VERUSSTRATUMCLIENT_H */
