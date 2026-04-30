# main.py
# Entry point. Loads config, wires all modules, starts threads, runs main log loop.
import yaml
import signal
import sys
import time
from monitor   import tail_log
from baseline  import BaselineTracker
from detector  import AnomalyDetector
from blocker   import Blocker, AuditLogger
from unbanner  import Unbanner
from notifier  import SlackNotifier
import dashboard


def load_config(path: str = 'config.yaml') -> dict:
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def main():
    cfg = load_config()
    print('[main] Config loaded')

    # Initialise all components
    audit    = AuditLogger(cfg['audit_log_path'])
    base     = BaselineTracker(cfg)
    notifier = SlackNotifier(cfg['slack_webhook_url'])
    blocker  = Blocker(cfg, audit)
    detector = AnomalyDetector(cfg, base)
    unbanner = Unbanner(cfg, blocker, notifier)

    # Anti-spam cooldowns
    _last_ip_ban     = {}
    _last_global     = [0.0]
    IP_COOLDOWN      = cfg['ip_ban_cooldown_seconds']
    GLOBAL_COOLDOWN  = cfg['global_alert_cooldown_seconds']

    # ── Anomaly callbacks ────────────────────────────────────────────────────

    def on_ip_anomaly(ip: str, rate: float, mean: float, zscore: float):
        now = time.time()
        if blocker.is_banned(ip):
            return  # Already blocked
        if now - _last_ip_ban.get(ip, 0) < IP_COOLDOWN:
            return  # Within cooldown — prevent double-trigger
        _last_ip_ban[ip] = now
        condition = 'ip_rate_anomaly'
        duration  = blocker.ban(ip, condition, rate, mean)
        notifier.send_ban(ip, rate, mean, zscore, duration, condition)
        print(f'[main] BANNED {ip}: rate={rate:.4f} mean={mean:.4f} z={zscore:.2f} dur={duration}')

    def on_global_anomaly(rate: float, mean: float, zscore: float):
        now = time.time()
        if now - _last_global[0] < GLOBAL_COOLDOWN:
            return
        _last_global[0] = now
        notifier.send_global_alert(rate, mean, zscore)
        print(f'[main] GLOBAL ANOMALY: rate={rate:.4f} mean={mean:.4f} z={zscore:.2f}')

    detector.on_ip_anomaly     = on_ip_anomaly
    detector.on_global_anomaly = on_global_anomaly

    # ── Start subsystems ─────────────────────────────────────────────────────

    dashboard.init(detector, blocker, base)
    dashboard.run(cfg['dashboard_host'], cfg['dashboard_port'])
    unbanner.start()

    # ── Graceful shutdown ─────────────────────────────────────────────────────

    def _shutdown(sig, frame):
        print('\n[main] Shutdown signal received')
        unbanner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT,  _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    # ── Main loop — process every Nginx log line ──────────────────────────────

    print('[main] Entering log processing loop...')
    for entry in tail_log(cfg['log_path']):
        try:
            detector.process(entry)
        except Exception as exc:
            print(f'[main] Loop error (continuing): {exc}')


if __name__ == '__main__':
    main()
