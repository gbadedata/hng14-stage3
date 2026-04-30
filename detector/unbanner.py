# unbanner.py
# Background thread that checks ban expiry and releases bans on the backoff schedule.
import time
import threading


class Unbanner:
    """
    Runs as a daemon thread. Wakes every unban_check_interval_seconds.
    For each active ban: if (now - banned_at) >= duration, call blocker.unban().
    Permanent bans (duration == -1) are never released.
    Sends Slack notification on every unban via notifier.send_unban().
    """

    def __init__(self, config: dict, blocker, notifier):
        self.check_interval = config['unban_check_interval_seconds']
        self.blocker        = blocker
        self.notifier       = notifier
        self._running       = False
        self._thread        = threading.Thread(
            target=self._run,
            daemon=True,
            name='unbanner'
        )

    def start(self):
        self._running = True
        self._thread.start()
        print(f'[unbanner] Started — checking every {self.check_interval}s')

    def stop(self):
        self._running = False

    def _run(self):
        while self._running:
            self._check_expiry()
            time.sleep(self.check_interval)

    def _check_expiry(self):
        now = time.time()
        for ban in self.blocker.get_banned_ips():
            ip       = ban['ip']
            duration = ban['duration']
            if duration == -1:
                continue  # Permanent — never release
            if now - ban['banned_at'] >= duration:
                self.blocker.unban(ip)
                self.notifier.send_unban(ip, duration)
                print(f'[unbanner] Released {ip} after {duration}s')
