# detector.py
# Per-IP and global sliding windows. Anomaly detection with z-score and rate multiplier.
import time
import threading
from collections import deque


class SlidingWindowCounter:
    """
    Tracks request timestamps in a deque over the last window_seconds.
    Deque structure: each entry is a float timestamp of one request.
    Eviction: popleft() while deque[0] < (now - window_seconds).
    Rate = len(deque) / window_seconds — exact rolling rate, not bucketed.
    """

    def __init__(self, window_seconds: int):
        self.window_seconds = window_seconds
        self._ts     = deque()   # request timestamps
        self._err_ts = deque()   # error request timestamps
        self._lock   = threading.Lock()

    def add(self, ts: float, is_error: bool = False):
        """Record one request at timestamp ts."""
        with self._lock:
            self._ts.append(ts)
            if is_error:
                self._err_ts.append(ts)
            self._evict(ts)

    def _evict(self, now: float):
        """Remove timestamps older than window_seconds. LOCK MUST BE HELD."""
        cutoff = now - self.window_seconds
        # Pop from LEFT (oldest) while leftmost entry is too old
        while self._ts and self._ts[0] < cutoff:
            self._ts.popleft()
        while self._err_ts and self._err_ts[0] < cutoff:
            self._err_ts.popleft()

    def rate(self, now: float = None) -> float:
        """Return requests per second over the current window."""
        if now is None:
            now = time.time()
        with self._lock:
            self._evict(now)
            return len(self._ts) / self.window_seconds

    def error_rate(self, now: float = None) -> float:
        """Return error requests per second over the current window."""
        if now is None:
            now = time.time()
        with self._lock:
            self._evict(now)
            return len(self._err_ts) / self.window_seconds


class AnomalyDetector:
    """
    Maintains per-IP and global SlidingWindowCounters.
    On each request, evaluates the rate against the rolling baseline.
    Fires on_ip_anomaly or on_global_anomaly callbacks when thresholds exceeded.
    """

    def __init__(self, config: dict, baseline):
        self.config   = config
        self.baseline = baseline

        # All thresholds from config — never hardcoded
        self._ip_window_secs   = config['per_ip_window_seconds']
        self._gl_window_secs   = config['global_window_seconds']
        self._z_threshold      = config['zscore_threshold']
        self._rate_mult        = config['rate_multiplier_threshold']
        self._err_surge_mult   = config['error_surge_multiplier']
        self._err_surge_reduce = config['error_surge_zscore_reduction']
        self._err_surge_min_z  = config['error_surge_min_zscore']

        # Per-IP counters
        self._ip_windows = {}
        # Global counter
        self._global = SlidingWindowCounter(self._gl_window_secs)
        self._lock   = threading.Lock()

        # Anomaly callbacks — set by main.py
        self.on_ip_anomaly     = None  # fn(ip, rate, mean, zscore)
        self.on_global_anomaly = None  # fn(rate, mean, zscore)

    def process(self, entry: dict):
        """Called once per log line from the main loop."""
        ip       = entry['source_ip']
        ts       = entry['parsed_time']
        is_error = entry['is_error']

        # Record in baseline
        self.baseline.record_request(ts, is_error)

        # Record in global sliding window
        self._global.add(ts, is_error)

        # Record in per-IP sliding window
        with self._lock:
            if ip not in self._ip_windows:
                self._ip_windows[ip] = SlidingWindowCounter(self._ip_window_secs)
            self._ip_windows[ip].add(ts, is_error)

        # Evaluate anomaly conditions
        self._check_ip(ip, ts)
        self._check_global(ts)

    def _check_ip(self, ip: str, now: float):
        """Evaluate this IP's rate against the baseline."""
        with self._lock:
            window = self._ip_windows.get(ip)
        if not window:
            return

        rate       = window.rate(now)
        error_rate = window.error_rate(now)
        stats      = self.baseline.get_stats()
        mean       = stats['effective_mean']
        stddev     = stats['effective_stddev']

        # Start with default z-score threshold from config
        z_thresh = self._z_threshold

        # Tighten threshold on error surge
        if stats['error_mean'] > 0 and error_rate >= self._err_surge_mult * stats['error_mean']:
            z_thresh = max(z_thresh - self._err_surge_reduce, self._err_surge_min_z)

        # Compute z-score: how many stddevs above mean is this rate?
        zscore = (rate - mean) / stddev if stddev > 0 else 0.0

        # Fire if either threshold exceeded (OR condition — whichever fires first)
        is_anomalous = (zscore >= z_thresh) or (mean > 0 and rate >= self._rate_mult * mean)
        if is_anomalous and self.on_ip_anomaly:
            self.on_ip_anomaly(ip, rate, mean, zscore)

    def _check_global(self, now: float):
        """Evaluate global traffic rate against the baseline."""
        rate   = self._global.rate(now)
        stats  = self.baseline.get_stats()
        mean   = stats['effective_mean']
        stddev = stats['effective_stddev']

        zscore = (rate - mean) / stddev if stddev > 0 else 0.0

        is_anomalous = (zscore >= self._z_threshold) or (mean > 0 and rate >= self._rate_mult * mean)
        if is_anomalous and self.on_global_anomaly:
            self.on_global_anomaly(rate, mean, zscore)

    def get_top_ips(self, n: int = 10) -> list:
        """Return top N IPs sorted by current request rate."""
        now = time.time()
        with self._lock:
            rates = [(ip, w.rate(now)) for ip, w in self._ip_windows.items()]
        rates.sort(key=lambda x: x[1], reverse=True)
        return rates[:n]

    def global_rate(self) -> float:
        return self._global.rate()
