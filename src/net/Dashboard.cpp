/* XMRig-VRSC — Dashboard implementation. See Dashboard.h for design notes. */

#include "net/Dashboard.h"
#include "backend/common/Hashrate.h"
#include "backend/common/interfaces/IBackend.h"
#include "base/io/log/Log.h"
#include "base/tools/Chrono.h"
#include "core/config/Config.h"
#include "core/Controller.h"
#include "core/Miner.h"

#include <cstdio>
#include <cmath>
#include <ctime>
#include <algorithm>
#include <vector>


bool xmrig::Dashboard::m_enabled = false;


namespace {


inline const char *c(const char *code)
{
    return xmrig::Log::isColors() ? code : "";
}


} // anonymous namespace


xmrig::Dashboard::Dashboard(Controller *controller) :
    m_controller(controller)
{
    m_startTime = Chrono::steadyMSecs();

    for (size_t i = 0; i < kHistorySize; ++i) {
        m_jobs.push_back({ "", "", 0, "" });
        m_shares.push_back({ "", 0, 0, "", 0, false });
    }
}


xmrig::Dashboard::~Dashboard() = default;


bool xmrig::Dashboard::isEnabled()
{
    return m_enabled;
}


void xmrig::Dashboard::setEnabled(bool enabled)
{
    m_enabled = enabled;
}


void xmrig::Dashboard::setPool(const char *host, int port, const char *algo)
{
    m_poolHost = host ? host : "";
    m_poolPort = port;
    m_algo     = algo ? algo : "";
}


void xmrig::Dashboard::onJob(const char *id, uint64_t diff, const char *scale)
{
    m_lastDiff  = diff;
    m_lastScale = scale ? scale : "";

    m_jobs.push_back({ nowTime(), id ? id : "", diff, scale ? scale : "" });
    while (m_jobs.size() > kHistorySize) {
        m_jobs.pop_front();
    }
}


void xmrig::Dashboard::onResult(bool accepted, uint64_t diff, const char *scale, uint64_t elapsedMs)
{
    if (accepted) {
        ++m_accepted;
        m_shares.push_back({ nowTime(), m_accepted, diff, scale ? scale : "", elapsedMs, true });
        while (m_shares.size() > kHistorySize) {
            m_shares.pop_front();
        }
    }
    else {
        ++m_rejected;
    }
}


void xmrig::Dashboard::tick()
{
    double h10 = 0.0, h30 = 0.0, h60 = 0.0, havg = 0.0;
    size_t threads = 0;
    bool any = false;

    for (auto backend : m_controller->miner()->backends()) {
        const auto hashrate = backend->hashrate();
        if (!hashrate) {
            continue;
        }

        any = true;
        threads += hashrate->threads();

        const auto r10 = hashrate->calc(10000);
        const auto r30 = hashrate->calc(30000);
        const auto r60 = hashrate->calc(60000);

        if (r10.first) { h10 += r10.second; }
        if (r30.first) { h30 += r30.second; }
        if (r60.first) { h60 += r60.second; }

        havg += hashrate->average();
    }

    if (!any) {
        return;
    }

    m_threads    = threads;
    m_hugePages  = m_controller->config()->cpu().isHugePages();

    m_stat10s.update(h10);
    m_stat30s.update(h30);
    m_stat60s.update(h60);
    m_statAvg.update(havg);

    render();
}


std::string xmrig::Dashboard::nowTime()
{
    const time_t t = time(nullptr);
    struct tm tmVal{};
#   ifdef _WIN32
    localtime_s(&tmVal, &t);
#   else
    localtime_r(&t, &tmVal);
#   endif

    char buf[16];
    snprintf(buf, sizeof(buf), "%02d:%02d:%02d", tmVal.tm_hour, tmVal.tm_min, tmVal.tm_sec);

    return buf;
}


std::string xmrig::Dashboard::formatHashrate(double h)
{
    static const char *units[] = { "H/s", "KH/s", "MH/s", "GH/s", "TH/s" };
    size_t i = 0;

    while (h >= 1000.0 && i < 4) {
        h /= 1000.0;
        ++i;
    }

    char buf[32];
    snprintf(buf, sizeof(buf), "%.2f %s", h, units[i]);

    return buf;
}


std::string xmrig::Dashboard::padRight(const std::string &s, size_t width)
{
    if (s.size() >= width) {
        return s;
    }

    return s + std::string(width - s.size(), ' ');
}


std::string xmrig::Dashboard::padLeft(const std::string &s, size_t width)
{
    if (s.size() >= width) {
        return s;
    }

    return std::string(width - s.size(), ' ') + s;
}


void xmrig::Dashboard::render()
{
    std::vector<std::string> lines;

    // Box-drawing horizontal rule (UTF-8 U+2501).
    const std::string rule = []() {
        std::string s;
        for (int i = 0; i < 70; ++i) { s += "\xE2\x94\x81"; }
        return s;
    }();

    lines.push_back(std::string(c(CYAN_BOLD_S)) + rule + c(CLEAR));
    lines.push_back(std::string(c(WHITE_BOLD_S)) + " xmrig-vrsc" + c(CLEAR) + " " + c(CYAN_S) + "\xE2\x80\x94 " + m_algo + c(CLEAR));
    lines.push_back(std::string(c(CYAN_BOLD_S)) + rule + c(CLEAR));

    const uint64_t upMs = Chrono::steadyMSecs() - m_startTime;
    const uint64_t upS  = upMs / 1000;
    char upBuf[16];
    snprintf(upBuf, sizeof(upBuf), "%02u:%02u:%02u",
             static_cast<unsigned>(upS / 3600), static_cast<unsigned>((upS % 3600) / 60), static_cast<unsigned>(upS % 60));

    std::string poolStr = m_poolHost.empty() ? "connecting..." : (m_poolHost + ":" + std::to_string(m_poolPort));

    lines.push_back(" pool      " + padRight(poolStr, 32) + "uptime    " + std::string(upBuf));

    std::string threadsStr = std::to_string(m_threads) + " (huge pages: " + (m_hugePages ? "on" : "off") + ")";
    std::string diffStr    = m_lastDiff > 0 ? (std::to_string(m_lastDiff) + m_lastScale) : "-";

    lines.push_back(" threads   " + padRight(threadsStr, 32) + "diff      " + diffStr);
    lines.push_back("");

    lines.push_back(std::string(c(WHITE_BOLD_S)) + " hashrate" + c(CLEAR));
    lines.push_back("  " + padRight("tempo", 9) + padRight("atual", 12) + padRight("m\xC3\xADnimo", 12) + padRight("m\xC3\xA9""dia", 12) + padRight("m\xC3\xA1ximo", 12));

    auto row = [&](const char *label, const RollingStat &s) {
        lines.push_back("  " + padRight(label, 9)
                         + padRight(formatHashrate(s.current), 12)
                         + padRight(formatHashrate(s.min < 0.0 ? 0.0 : s.min), 12)
                         + padRight(formatHashrate(s.avg()), 12)
                         + padRight(formatHashrate(s.max), 12));
    };

    row("10s", m_stat10s);
    row("30s", m_stat30s);
    row("60s", m_stat60s);
    row("avg", m_statAvg);
    lines.push_back("");

    const uint64_t total = m_accepted + m_rejected;
    const double rate = total > 0 ? (100.0 * static_cast<double>(m_accepted) / static_cast<double>(total)) : 100.0;
    char rateBuf[16];
    snprintf(rateBuf, sizeof(rateBuf), "%.1f%%", rate);

    lines.push_back(std::string(" shares    ") + c(GREEN_BOLD_S) + "aceitas: " + std::to_string(m_accepted) + c(CLEAR)
                     + "      " + c(RED_BOLD_S) + "rejeitadas: " + std::to_string(m_rejected) + c(CLEAR)
                     + "      taxa: " + rateBuf);
    lines.push_back("");

    lines.push_back(std::string(c(MAGENTA_BOLD_S)) + " \xE2\x94\x80\xE2\x94\x80 \xC3\xBAltimos jobs (10 mais recentes) \xE2\x94\x80\xE2\x94\x80" + c(CLEAR));
    for (auto it = m_jobs.rbegin(); it != m_jobs.rend(); ++it) {
        if (it->id.empty()) {
            lines.push_back("");
            continue;
        }
        lines.push_back("  " + padRight(it->time, 11) + padRight("job " + it->id, 20) + "diff " + std::to_string(it->diff) + it->scale);
    }
    lines.push_back("");

    lines.push_back(std::string(c(GREEN_BOLD_S)) + " \xE2\x94\x80\xE2\x94\x80 shares aceitas (10 mais recentes) \xE2\x94\x80\xE2\x94\x80" + c(CLEAR));
    for (auto it = m_shares.rbegin(); it != m_shares.rend(); ++it) {
        if (it->time.empty()) {
            lines.push_back("");
            continue;
        }
        lines.push_back("  " + padRight(it->time, 11) + padRight("#" + std::to_string(it->number), 8)
                         + padRight("diff " + std::to_string(it->diff) + it->scale, 16)
                         + std::to_string(it->elapsedMs) + "ms");
    }

    lines.push_back(std::string(c(CYAN_BOLD_S)) + rule + c(CLEAR));

    // Redraw in place: move cursor up over the previous frame first.
    if (!m_firstRender) {
        printf("\x1B[%dA", m_renderLines);
    }

    for (const auto &line : lines) {
        fputs("\r\x1B[2K", stdout);
        fputs(line.c_str(), stdout);
        fputc('\n', stdout);
    }

    fflush(stdout);

    m_renderLines  = static_cast<int>(lines.size());
    m_firstRender  = false;
}
