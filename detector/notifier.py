# notifier.py
# Slack webhook alerts for ban, unban, and global anomaly events.
import requests
import threading
from datetime import datetime


class SlackNotifier:
    """
    Sends Slack alerts via incoming webhook.
    Fires in a background thread so detection is never blocked.
    Webhook URL stored in config — never hardcoded.
    All required fields included in every alert type.
    """

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url
        self._enabled    = bool(
            webhook_url and webhook_url.startswith('https://hooks.slack.com')
        )
        if not self._enabled:
            print('[notifier] Slack disabled — webhook URL not configured')

    def send_ban(self, ip: str, rate: float, baseline: float,
                 zscore: float, duration: int, condition: str):
        dur_str = 'PERMANENT' if duration == -1 else f'{duration}s'
        text = (
            f':rotating_light: *IP BANNED*\n'
            f'• Condition: `{condition}`\n'
            f'• IP address: `{ip}`\n'
            f'• Current rate: `{rate:.4f} req/s`\n'
            f'• Baseline mean: `{baseline:.4f} req/s`\n'
            f'• Z-score: `{zscore:.2f}`\n'
            f'• Ban duration: `{dur_str}`\n'
            f'• Timestamp: `{datetime.now().isoformat()}`'
        )
        self._fire({'text': text})

    def send_unban(self, ip: str, duration: int):
        text = (
            f':white_check_mark: *IP UNBANNED*\n'
            f'• IP address: `{ip}`\n'
            f'• Ban duration served: `{duration}s`\n'
            f'• Timestamp: `{datetime.now().isoformat()}`'
        )
        self._fire({'text': text})

    def send_global_alert(self, rate: float, baseline: float, zscore: float):
        text = (
            f':warning: *GLOBAL TRAFFIC ANOMALY*\n'
            f'• Condition: `global_rate_anomaly`\n'
            f'• Current global rate: `{rate:.4f} req/s`\n'
            f'• Baseline mean: `{baseline:.4f} req/s`\n'
            f'• Z-score: `{zscore:.2f}`\n'
            f'• Action: Slack alert only (no IP block)\n'
            f'• Timestamp: `{datetime.now().isoformat()}`'
        )
        self._fire({'text': text})

    def _fire(self, payload: dict):
        """Non-blocking POST — runs in a daemon thread."""
        threading.Thread(
            target=self._post,
            args=(payload,),
            daemon=True
        ).start()

    def _post(self, payload: dict):
        if not self._enabled:
            print(f'[notifier] (disabled) Would send: {str(payload)[:80]}')
            return
        try:
            r = requests.post(self.webhook_url, json=payload, timeout=5)
            if r.status_code != 200:
                print(f'[notifier] Slack HTTP {r.status_code}: {r.text}')
        except Exception as e:
            print(f'[notifier] Slack error: {e}')
