/* XMRig-VRSC — BenchmarkSubmitter implementation. See header for design notes. */

#include "net/BenchmarkSubmitter.h"
#include "3rdparty/rapidjson/document.h"
#include "backend/common/Hashrate.h"
#include "backend/common/interfaces/IBackend.h"
#include "backend/cpu/Cpu.h"
#include "backend/cpu/interfaces/ICpuInfo.h"
#include "base/io/log/Log.h"
#include "base/io/log/Tags.h"
#include "base/net/http/Fetch.h"
#include "base/net/http/HttpData.h"
#include "base/tools/Timer.h"
#include "core/config/Config.h"
#include "core/Controller.h"
#include "core/Miner.h"
#include "version.h"

#include <cstdio>
#include <memory>


xmrig::BenchmarkSubmitter::BenchmarkSubmitter(Controller *controller) :
    m_controller(controller)
{
    m_timer = new Timer(this);
}


xmrig::BenchmarkSubmitter::~BenchmarkSubmitter()
{
    delete m_timer;
}


void xmrig::BenchmarkSubmitter::start()
{
    if (m_armed || m_done) {
        return;
    }

    m_armed = true;

    const uint64_t ms = static_cast<uint64_t>(m_controller->config()->submitBenchmarkDuration()) * 1000ULL;
    LOG_INFO("%s " CYAN_BOLD("benchmark submission armed") " -- measuring for %u s, will submit once and turn itself off",
             Tags::config(), m_controller->config()->submitBenchmarkDuration());

    m_timer->start(ms, 0);
}


void xmrig::BenchmarkSubmitter::setAlgo(const char *algo)
{
    if (algo) {
        m_algo = algo;
    }
}


void xmrig::BenchmarkSubmitter::onTimer(const Timer *)
{
    submit();
}


void xmrig::BenchmarkSubmitter::submit()
{
    if (m_done) {
        return;
    }
    m_done = true;

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

    bool hugePages = m_controller->config()->cpu().isHugePages();

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

    using namespace rapidjson;
    Document doc(kObjectType);
    auto &allocator = doc.GetAllocator();

    doc.AddMember("cpu_model",     StringRef(Cpu::info()->brand()), allocator);
    doc.AddMember("threads",       static_cast<uint64_t>(threads), allocator);
    doc.AddMember("hashrate",      hashrate, allocator);
    doc.AddMember("algo",          Value(m_algo.empty() ? "unknown" : m_algo.c_str(), allocator), allocator);
    doc.AddMember("platform",      StringRef(platform), allocator);
    doc.AddMember("arch",          StringRef(arch), allocator);
    doc.AddMember("huge_pages",    hugePages, allocator);
    doc.AddMember("xmrig_version", StringRef(APP_VERSION), allocator);
    doc.AddMember("duration_s",    m_controller->config()->submitBenchmarkDuration(), allocator);

    char hrBuf[32];
    snprintf(hrBuf, sizeof(hrBuf), "%.2f H/s", hashrate);
    LOG_INFO("%s " CYAN_BOLD("submitting benchmark") " -- %s, %s, %zu threads",
             Tags::config(), Cpu::info()->brand(), hrBuf, threads);

    FetchRequest req(HTTP_POST,
                      m_controller->config()->submitBenchmarkHost(),
                      m_controller->config()->submitBenchmarkPort(),
                      m_controller->config()->submitBenchmarkPath(),
                      doc,
                      m_controller->config()->isSubmitBenchmarkTls(),
                      false);

    fetch(Tags::config(), std::move(req), shared_from_this());
}


void xmrig::BenchmarkSubmitter::onHttpData(const HttpData &data)
{
    if (data.status >= 200 && data.status < 300) {
        LOG_INFO("%s " GREEN_BOLD("benchmark submitted") " -- turning \"submit-benchmark\" back off in config.json", Tags::config());

        m_controller->config()->setSubmitBenchmark(false);
        m_controller->config()->save();
    }
    else {
        LOG_ERR("%s " RED_BOLD("benchmark submission failed") " -- HTTP %d, will NOT retry automatically (flag left on, safe to try again on next start)",
                Tags::config(), data.status);
    }
}
