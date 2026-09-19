/* XMRig-VRSC
 * Dashboard: fixed, redrawn-in-place mining status panel (opt-in via
 * --dashboard / config.json "dashboard": true). Off by default; when off,
 * behavior is bit-for-bit identical to upstream (all call sites are
 * guarded by isEnabled()).
 */

#ifndef XMRIG_DASHBOARD_H
#define XMRIG_DASHBOARD_H


#include <cstdint>
#include <deque>
#include <string>


namespace xmrig {


class Controller;


class Dashboard
{
public:
    explicit Dashboard(Controller *controller);
    ~Dashboard();

    static bool isEnabled();
    static void setEnabled(bool enabled);

    // Called once, when the pool connection goes active.
    void setPool(const char *host, int port, const char *algo);

    // Called from Network::setJob(), once per new job.
    void onJob(const char *id, uint64_t diff, const char *scale);

    // Called from Network::onResultAccepted(), once per submit result.
    void onResult(bool accepted, uint64_t diff, const char *scale, uint64_t elapsedMs);

    // Called once per second from Network::tick() (reuses its existing 1s timer).
    void tick();

private:
    struct RollingStat
    {
        double current = 0.0;
        double min      = -1.0;
        double max      = 0.0;
        double sum      = 0.0;
        uint64_t count  = 0;

        void update(double v)
        {
            current = v;
            if (min < 0.0 || v < min) { min = v; }
            if (v > max) { max = v; }
            sum += v;
            ++count;
        }

        inline double avg() const { return count > 0 ? sum / count : 0.0; }
    };

    struct JobEntry
    {
        std::string time;
        std::string id;
        uint64_t diff;
        std::string scale;
    };

    struct ShareEntry
    {
        std::string time;
        uint64_t number;
        uint64_t diff;
        std::string scale;
        uint64_t elapsedMs;
        bool accepted;
    };

    void render();
    static std::string nowTime();
    static std::string formatHashrate(double h);
    static std::string padRight(const std::string &s, size_t width);
    static std::string padLeft(const std::string &s, size_t width);

    Controller *m_controller;

    // Captured once at construction -- static for the process lifetime,
    // same data XMRig's own startup Summary print uses (Summary.cpp,
    // BaseConfig::printVersions()) -- kept pinned at the top of every
    // frame instead of relying on the terminal's scrollback to still have
    // the one-time startup banner around.
    std::string m_about;
    std::string m_libs;
    std::string m_hugePagesStatus;
    std::string m_oneGbPagesStatus;
    std::string m_cpuLine1;
    std::string m_cpuLine2;
    int m_donateLevel       = 0;

    std::string m_poolHost;
    int m_poolPort          = 0;
    std::string m_algo;

    uint64_t m_startTime;
    size_t m_threads        = 0;
    bool m_hugePages        = false;

    uint64_t m_lastDiff     = 0;
    std::string m_lastScale;

    uint64_t m_accepted     = 0;
    uint64_t m_rejected     = 0;

    RollingStat m_stat10s;
    RollingStat m_stat30s;
    RollingStat m_stat60s;
    RollingStat m_statAvg;

    static constexpr size_t kHistorySize = 10;
    std::deque<JobEntry> m_jobs;
    std::deque<ShareEntry> m_shares;

    bool m_firstRender      = true;
    int m_renderLines       = 0;

    static bool m_enabled;
};


} // namespace xmrig


#endif // XMRIG_DASHBOARD_H
