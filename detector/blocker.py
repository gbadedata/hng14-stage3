# blocker.py
# iptables DROP rules + ban state tracking + AuditLogger.
import subprocess
import threading
import time
import os
from datetime import datetime


class AuditLogger:
    """
    Writes structured entries for every ban, unban, and baseline recalculation.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """

    def __init__(self, log_path: str):
        self.log_path = log_path
        os.makedirs(os.path.dirname(log_path), exist_ok=True)

    def log(self, action: str, ip: str = '', condition: str = '',
            rate: float = 0.0, baseline: float = 0.0, duration: int = 0):
        line = (
            f'[{datetime.now().isoformat()}] {action} {ip} | '
            f'{condition} | rate={rate:.4f} | baseline={baseline:.4f} | duration={duration}'
        )
        print(f'[audit] {line}')
        try:
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except OSError as e:
            print(f'[audit] Write failed: {e}')


class Blocker:
    """
    Manages iptables DROP rules for anomalous IPs.
    Tracks ban history per IP to implement the backoff schedule.
    ban_durations from config: [600, 1800, 7200, -1]
    """

    def __init__(self, config: dict, audit: AuditLogger):
        self.enable_iptables = config.get('enable_iptables', True)
        self.ban_durations   = config['ban_durations']
        self.audit           = audit

        # Active bans: {ip: {banned_at, ban_index, duration, condition}}
        self._bans = {}
        # Persistent ban history: {ip: int} — survives unbans for backoff
        self._ban_history = {}
        self._lock = threading.Lock()

    def ban(self, ip: str, condition: str, rate: float, baseline: float) -> int:
        """
        Ban ip with appropriate backoff duration.
        Returns the ban duration in seconds (-1 = permanent).
        """
        with self._lock:
            # Advance the ban index for this IP
            prev_idx = self._ban_history.get(ip, -1)
            new_idx  = min(prev_idx + 1, len(self.ban_durations) - 1)
            self._ban_history[ip] = new_idx
            duration = self.ban_durations[new_idx]

            self._bans[ip] = {
                'banned_at': time.time(),
                'ban_index': new_idx,
                'duration':  duration,
                'condition': condition,
            }

        if self.enable_iptables:
            self._iptables_add(ip)

        self.audit.log('BAN', ip=ip, condition=condition,
                       rate=rate, baseline=baseline, duration=duration)
        return duration

    def unban(self, ip: str, rate: float = 0.0, baseline: float = 0.0):
        """Remove the iptables DROP rule and clear the active ban record."""
        if self.enable_iptables:
            self._iptables_del(ip)
        with self._lock:
            ban_info = self._bans.pop(ip, {})
        self.audit.log('UNBAN', ip=ip, condition='ban_expired',
                       rate=rate, baseline=baseline,
                       duration=ban_info.get('duration', 0))

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self._bans

    def get_banned_ips(self) -> list:
        with self._lock:
            return [
                {
                    'ip':        ip,
                    'banned_at': v['banned_at'],
                    'duration':  v['duration'],
                    'condition': v['condition'],
                }
                for ip, v in self._bans.items()
            ]

    def _iptables_add(self, ip: str):
        try:
            subprocess.run(
                ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                check=True, capture_output=True, text=True
            )
            print(f'[blocker] iptables DROP added for {ip}')
        except subprocess.CalledProcessError as e:
            print(f'[blocker] iptables add error: {e.stderr}')

    def _iptables_del(self, ip: str):
        """Delete ALL matching DROP rules (handles duplicates from restarts)."""
        while True:
            r = subprocess.run(
                ['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP'],
                capture_output=True
            )
            if r.returncode != 0:
                break
        print(f'[blocker] iptables DROP removed for {ip}')
