/* XMRig-VRSC — AccountReporter implementation. See header for design notes. */

#include "net/AccountReporter.h"
#include "3rdparty/rapidjson/document.h"
#include "backend/common/Hashrate.h"
#include "backend/common/interfaces/IBackend.h"
#include "backend/cpu/Cpu.h"
#include "backend/cpu/interfaces/ICpuInfo.h"
#include "base/io/log/Log.h"
#include "base/io/log/Tags.h"
#include "base/net/http/Fetch.h"
#include "base/net/http/HttpData.h"
#include "base/tools/Cvt.h"
#include "base/tools/Timer.h"
#include "core/config/Config.h"
#include "core/Controller.h"
#include "core/Miner.h"
#include "version.h"

#include <uv.h>
#include <cstdio>
#include <cstring>
#include <random>


xmrig::AccountReporter::AccountReporter(Controller *controller) :
    m_controller(controller)
{
    m_timer = new Timer(this);

    if (!m_controller->config()->userMachineId() || strlen(m_controller->config()->userMachineId()) == 0) {
        const std::string id = generateMachineId();
        m_controller->config()->setUserMachineId(id.c_str());
        m_controller->config()->save();
        LOG_INFO("%s " CYAN_BOLD("generated machine ID") " for account reporting: %s", Tags::config(), id.c_str());
    }
}


xmrig::AccountReporter::~AccountReporter()
{
    delete m_timer;
}


std::string xmrig::AccountReporter::generateMachineId()
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist;

    uint8_t bytes[16];
    const uint64_t a = dist(gen);
    const uint64_t b = dist(gen);
    memcpy(bytes, &a, 8);
    memcpy(bytes + 8, &b, 8);

    return Cvt::toHex(bytes, sizeof(bytes)).data();
}


void xmrig::AccountReporter::start()
{
    if (m_armed) {
        return;
    }

    m_armed = true;

    const uint64_t ms = static_cast<uint64_t>(m_controller->config()->userReportInterval()) * 1000ULL;
    LOG_INFO("%s " CYAN_BOLD("account reporting armed") " -- heartbeat every %u s (machine ID %s)",
             Tags::config(), m_controller->config()->userReportInterval(), m_controller->config()->userMachineId());

    m_timer->start(ms, ms);
}


void xmrig::AccountReporter::setAlgo(const char *algo)
{
    if (algo) {
        m_algo = algo;
    }
}


void xmrig::AccountReporter::onTimer(const Timer *)
{
    sendHeartbeat();
}


void xmrig::AccountReporter::sendHeartbeat()
{
    double hashrate = 0.0;
    size_t threads  = 0;

    for (auto backend : m_controller->miner()->backends()) {
        const auto hr = backend->hashrate();
        if (!hr) {
            continue;
        }

        hashrate += hr->average();
        threads  += hr->threads();
    }

    const bool hugePages = m_controller->config()->cpu().isHugePages();

#   if defined(__linux__)
#       if defined(__ANDROID__)
    const char *platform = "android";
#       else
    const char *platform = "linux";
#       endif
#   elif defined(__APPLE__)
    const char *platform = "macos";
#   elif defined(_WIN32)
    const char *platform = "windows";
#   else
    const char *platform = "unknown";
#   endif

#   if defined(__x86_64__) || defined(_M_X64)
    const char *arch = "x86-64";
#   elif defined(__aarch64__) || defined(_M_ARM64)
    const char *arch = "arm64";
#   else
    const char *arch = "other";
#   endif

    constexpr double oneGiB = 1024.0 * 1024.0 * 1024.0;
    const double ramTotalGb = static_cast<double>(uv_get_total_memory()) / oneGiB;

    using namespace rapidjson;
    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    doc.AddMember("token",         StringRef(m_controller->config()->userToken()), allocator);
    doc.AddMember("machine_id",    StringRef(m_controller->config()->userMachineId()), allocator);
    doc.AddMember("cpu_model",     StringRef(Cpu::info()->brand()), allocator);
    doc.AddMember("threads",       static_cast<uint64_t>(threads), allocator);
    doc.AddMember("ram_total_gb",  ramTotalGb, allocator);
    doc.AddMember("hashrate",      hashrate, allocator);
    doc.AddMember("algo",          Value(m_algo.empty() ? "unknown" : m_algo.c_str(), allocator), allocator);
    doc.AddMember("platform",      StringRef(platform), allocator);
    doc.AddMember("arch",          StringRef(arch), allocator);
    doc.AddMember("huge_pages",    hugePages, allocator);
    doc.AddMember("xmrig_version", StringRef(APP_VERSION), allocator);

    FetchRequest req(HTTP_POST,
                      m_controller->config()->userReportHost(),
                      m_controller->config()->userReportPort(),
                      m_controller->config()->userReportPath(),
                      doc,
                      m_controller->config()->isUserReportTls(),
                      false); // quiet was true, but that also hides *which* of HttpClient/HttpsClient's
                              // several distinct error paths (DNS, connect, TLS verify, HTTP parse) is
                              // actually firing behind AccountReporter's own generic one-line message
                              // below -- turned off while chasing a live "-71 (protocol error)" report
                              // whose exact cause (of two remaining candidates after the fingerprint fix
                              // in HttpsClient.cpp) isn't yet pinned down. onHttpData() below still only
                              // logs once per failed interval either way, so this isn't the spam the
                              // original comment was about.

    fetch(Tags::config(), std::move(req), shared_from_this());
}


void xmrig::AccountReporter::onHttpData(const HttpData &data)
{
    // data.status is negative for a transport/TLS-layer failure (no HTTP response was ever received --
    // see HttpData::statusName(), which already knows to render that via uv_strerror instead of as an
    // HTTP status code) and >=100 for an actual HTTP status once a response came back. Only the latter
    // says anything about the account/token; a negative status is a network or TLS problem and telling
    // someone to go check their token for one is actively misleading.
    if (data.status < 0) {
        LOG_ERR("%s " RED_BOLD("account heartbeat failed") " -- %s (network/TLS error, unrelated to user-token)",
                Tags::config(), data.statusName());
        return;
    }

    if (data.status < 200 || data.status >= 300) {
        LOG_ERR("%s " RED_BOLD("account heartbeat failed") " -- HTTP %d (check user-token in config.json)",
                Tags::config(), data.status);
    }
}
