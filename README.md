# HNG14 Stage 3 - Anomaly Detection Engine

A real-time DDoS/anomaly detection daemon built for cloud.ng (Nextcloud). Watches all incoming HTTP traffic, learns normal baseline behaviour, and automatically blocks suspicious IPs via iptables.

## Live URLs

- **Server IP:** 3.9.164.183 (Nextcloud accessible here)
- **Metrics Dashboard:** http://dashboard.gbadedata.com

## GitHub Repository

https://github.com/gbadedata/hng14-stage3

## Language Choice

Python — chosen for its strong standard library (`collections.deque`, `threading`, `subprocess`), rapid development speed, and `psutil` for system metrics. Python's threading model is sufficient for I/O-bound tasks like log tailing and HTTP alerting.

## How the Sliding Window Works

Each IP gets its own `SlidingWindowCounter` instance backed by a `collections.deque`. Every incoming request appends a float timestamp to the **right** of the deque. On every `add()` call and every `rate()` query, stale timestamps are evicted from the **left** of the deque using `popleft()` while the leftmost entry is older than `window_seconds` (60s) from now. Rate is calculated as `len(deque) / window_seconds` — giving an exact rolling requests-per-second with no bucketing or approximation. A separate global `SlidingWindowCounter` tracks all traffic combined. No rate-limiting libraries are used — pure `deque` logic only.

## How the Baseline Works

`BaselineTracker` maintains a `collections.deque` of `(timestamp, count)` tuples — one entry per completed second of traffic. The window covers the last **1800 seconds (30 minutes)**. Entries older than 1800s are evicted from the left. Every **60 seconds**, `_recalculate()` computes population mean and stddev from the window samples. Per-hour slots (`{hour: [counts]}`) are also maintained — when the current hour has >= 60 samples, that slot is preferred over the full rolling window, allowing the baseline to adapt to time-of-day patterns. Floor values (`baseline_floor_mean: 0.1`, `baseline_floor_stddev: 0.1`) prevent division-by-zero and nonsense z-scores at startup. The `effective_mean` is always computed from real traffic — never hardcoded.

## How Detection Works

For each IP: `zscore = (current_rate - effective_mean) / effective_stddev`. Flagged as anomalous if `zscore >= 3.0` OR `rate >= 5x effective_mean` — whichever fires first. During error surges (IP's 4xx/5xx rate >= 3x baseline error rate), the z-score threshold is reduced by 1.5 (minimum 1.0). Per-IP anomaly triggers iptables DROP + Slack alert within 10 seconds. Global anomaly triggers Slack alert only.

## How iptables Blocking Works

On detection: `iptables -I INPUT -s IP -j DROP` is called via `subprocess`. Bans follow a backoff schedule: 10 min → 30 min → 2 hours → permanent. A background `Unbanner` thread checks expiry every 10 seconds and calls `iptables -D INPUT -s IP -j DROP` on release. Every ban and unban sends a Slack notification.

## Setup Instructions

### Prerequisites
- Linux VPS (2 vCPU, 2GB RAM minimum)
- Docker + Docker Compose plugin
- Python 3.11+
- Root access (for iptables)

### Step 1 — Clone and start the Docker stack
```bash
git clone https://github.com/gbadedata/hng14-stage3.git
cd hng14-stage3
docker compose up -d
```

### Step 2 — Find the log volume path
```bash
docker volume inspect hng14-stage3_HNG-nginx-logs
# Note the Mountpoint path
```

### Step 3 — Configure the detector
```bash
cd detector
nano config.yaml
# Set log_path to the Mountpoint path + /hng-access.log
# Set slack_webhook_url to your Slack webhook
```

### Step 4 — Install Python dependencies
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
deactivate
```

### Step 5 — Run as a systemd service
```bash
cat > /etc/systemd/system/hng-detector.service << 'SVCEOF'
[Unit]
Description=HNG14 Anomaly Detection Daemon
After=network.target docker.service

[Service]
Type=simple
User=root
WorkingDirectory=/root/hng14-stage3/detector
ExecStart=/root/hng14-stage3/detector/venv/bin/python main.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable hng-detector
systemctl start hng-detector
```

### Step 6 — Verify
```bash
systemctl status hng-detector
curl http://dashboard.gbadedata.com/api/metrics
```

## Repository Structure

```
hng14-stage3/
├── detector/
│   ├── main.py         # Entry point — wires all modules
│   ├── monitor.py      # Log file tailer and JSON parser
│   ├── baseline.py     # Rolling 30-min baseline tracker
│   ├── detector.py     # Sliding windows + anomaly detection
│   ├── blocker.py      # iptables DROP rules + audit logger
│   ├── unbanner.py     # Auto-unban background thread
│   ├── notifier.py     # Slack webhook alerts
│   ├── dashboard.py    # Flask live metrics dashboard
│   ├── config.yaml     # All thresholds and settings
│   └── requirements.txt
├── nginx/
│   └── nginx.conf      # JSON access logs + real IP forwarding
├── docs/
│   ├── architecture.png
│   └── screenshots/    # All 7 required screenshots
├── docker-compose.yml
└── README.md
```

## Blog Post

https://dev.to/gbadedata/how-i-built-a-real-time-ddos-detection-engine-from-scratch

## Screenshots

| Screenshot | Description |
|-----------|-------------|
| Tool-running.png | Daemon running and processing log lines |
| Ban-slack.png | Slack ban notification |
| Unban-slack.png | Slack unban notification |
| Global-alert-slack.png | Slack global anomaly notification |
| Iptables-banned.png | iptables DROP rule for blocked IP |
| Audit-log.png | Structured audit log with all event types |
| Baseline-graph.png | Baseline effective_mean over time |
