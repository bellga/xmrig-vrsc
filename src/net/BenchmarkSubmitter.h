/* XMRig-VRSC
 * BenchmarkSubmitter: opt-in (config.json "submit-benchmark": true), off by
 * default. Once the pool connection goes active, mines normally for
 * submitBenchmarkDuration() seconds, then POSTs CPU model + measured
 * hashrate to the configured endpoint and flips "submit-benchmark" back to
 * false in config.json (single-shot, never resubmits on its own).
 *
 * No wallet address, no IP, nothing that identifies who submitted it --
 * just hardware + the measured result.
 */

#ifndef XMRIG_BENCHMARKSUBMITTER_H
#define XMRIG_BENCHMARKSUBMITTER_H


#include "base/kernel/interfaces/IHttpListener.h"
#include "base/kernel/interfaces/ITimerListener.h"

#include <memory>
#include <string>


namespace xmrig {


class Controller;
class HttpData;
class Timer;


class BenchmarkSubmitter : public IHttpListener, public ITimerListener, public std::enable_shared_from_this<BenchmarkSubmitter>
{
public:
    explicit BenchmarkSubmitter(Controller *controller);
    ~BenchmarkSubmitter() override;

    // Called once, when the pool connection goes active -- arms the
    // one-shot measurement timer. Safe to call more than once; only the
    // first call (per process) actually arms it.
    void start();

    // Called from Network::setJob(), so we know what algo was mined.
    void setAlgo(const char *algo);

protected:
    void onHttpData(const HttpData &data) override;
    void onTimer(const Timer *timer) override;

private:
    void submit();

    Controller *m_controller;
    std::string m_algo;
    Timer *m_timer  = nullptr;
    bool m_armed    = false;
    bool m_done     = false;
};


} // namespace xmrig


#endif // XMRIG_BENCHMARKSUBMITTER_H
