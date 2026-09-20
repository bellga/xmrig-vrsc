/* XMRig-VRSC
 * AccountReporter: opt-in (config.json "user-token": "seu-token-secreto"),
 * off by default (empty token = disabled). Once the pool connection goes
 * active, sends a heartbeat every user-report-interval seconds for as long
 * as the miner keeps running, so the account's public profile can show
 * "online now" instead of a one-time snapshot.
 *
 * Auto-generates and persists a random per-machine ID on first use (via
 * Config::save()) so the same account can have several machines listed
 * separately without the user having to name/configure anything.
 *
 * Never sends the token anywhere except this one endpoint, and never
 * sends anything that identifies the person beyond what they already
 * see on their own public profile (CPU/RAM/platform/hashrate).
 */

#ifndef XMRIG_ACCOUNTREPORTER_H
#define XMRIG_ACCOUNTREPORTER_H


#include "base/kernel/interfaces/IHttpListener.h"
#include "base/kernel/interfaces/ITimerListener.h"

#include <memory>
#include <string>


namespace xmrig {


class Controller;
class HttpData;
class Timer;


class AccountReporter : public IHttpListener, public ITimerListener, public std::enable_shared_from_this<AccountReporter>
{
public:
    explicit AccountReporter(Controller *controller);
    ~AccountReporter() override;

    // Called once, when the pool connection goes active -- arms the
    // repeating heartbeat timer. Safe to call more than once.
    void start();

    // Called from Network::setJob(), so we know what algo is being mined.
    void setAlgo(const char *algo);

protected:
    void onHttpData(const HttpData &data) override;
    void onTimer(const Timer *timer) override;

private:
    void sendHeartbeat();
    static std::string generateMachineId();

    Controller *m_controller;
    std::string m_algo;
    Timer *m_timer  = nullptr;
    bool m_armed    = false;
};


} // namespace xmrig


#endif // XMRIG_ACCOUNTREPORTER_H
