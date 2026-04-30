# baseline.py
# Rolling 30-minute baseline. Per-hour slots. Recalculates mean/stddev every 60 seconds.
import time
import math
import threading
from collections import deque
from datetime import datetime


class BaselineTracker:
    """
    Tracks per-second request counts over a rolling 30-minute window.
    Recalculates effective_mean and effective_stddev every recalc_interval seconds.
    Prefers the current hour slot when it has enough samples.
    All thresholds come from config — nothing hardcoded.
    """

    def __init__(self, config: dict):
        self.window_seconds   = config['baseline_window_seconds']
        self.recalc_interval  = config['baseline_recalc_interval']
        self.min_hour_samples = config['min_samples_for_hour_slot']
        self.floor_mean       = config['baseline_floor_mean']
        self.floor_stddev     = config['baseline_floor_stddev']
        self.audit_log_path   = config.get('audit_log_path', '/var/log/detector-audit.log')

        # Rolling window: deque of (second_timestamp: int, count: int)
        self._window = deque()

        # Current incomplete second accumulator
        self._cur_second = int(time.time())
        self._cur_count  = 0
        self._cur_errors = 0

        # Per-hour slots: {hour_int: [count_per_second, ...]}
        self._hour_slots = {}

        # Error rate tracking
        self._err_window = deque()

        # Published values
        self.effective_mean   = self.floor_mean
        self.effective_stddev = self.floor_stddev
        self.error_mean       = self.floor_mean
        self.last_recalc      = time.time()

        self._recalc_log = []
        self._lock = threading.Lock()

    def record_request(self, ts: float, is_error: bool = False):
        """Called once per log entry."""
        with self._lock:
            second = int(ts)
            if second != self._cur_second:
                self._flush()
                self._cur_second = second
                self._cur_count  = 0
                self._cur_errors = 0
            self._cur_count += 1
            if is_error:
                self._cur_errors += 1

    def get_stats(self) -> dict:
        """Snapshot of current baseline values for detector and dashboard."""
        with self._lock:
            return {
                'effective_mean':   self.effective_mean,
                'effective_stddev': self.effective_stddev,
                'error_mean':       self.error_mean,
                'window_size':      len(self._window),
                'last_recalc':      self.last_recalc,
                'recalc_log':       list(self._recalc_log[-10:]),
            }

    def _flush(self):
        """Move completed second into the rolling window. Called under lock."""
        ts     = self._cur_second
        count  = self._cur_count
        errors = self._cur_errors

        self._window.append((ts, count))
        self._err_window.append((ts, errors))

        # Evict entries older than window_seconds from LEFT of deque
        cutoff = ts - self.window_seconds
        while self._window and self._window[0][0] < cutoff:
            self._window.popleft()
        while self._err_window and self._err_window[0][0] < cutoff:
            self._err_window.popleft()

        # Add to per-hour slot
        hour = datetime.fromtimestamp(ts).hour
        if hour not in self._hour_slots:
            self._hour_slots[hour] = []
        self._hour_slots[hour].append(count)

        # Trigger recalculation if enough time has passed
        if time.time() - self.last_recalc >= self.recalc_interval:
            self._recalculate()

    def _recalculate(self):
        """
        Compute effective_mean and effective_stddev from the best available data.
        Prefers current-hour slot when it has enough samples.
        Applies floor values to prevent nonsense at startup.
        Writes entry to audit log file.
        Called under lock.
        """
        hour      = datetime.now().hour
        hour_data = self._hour_slots.get(hour, [])

        # Choose data source: prefer hour slot, fall back to rolling window
        if len(hour_data) >= self.min_hour_samples:
            samples = hour_data
            source  = f'hour_{hour}_slot ({len(samples)} samples)'
        else:
            samples = [c for _, c in self._window]
            source  = f'rolling_window ({len(samples)} samples)'

        if len(samples) < 2:
            return

        # Population mean and stddev
        n        = len(samples)
        mean     = sum(samples) / n
        variance = sum((x - mean) ** 2 for x in samples) / n
        stddev   = math.sqrt(variance)

        # Apply floor values from config
        self.effective_mean   = max(mean,   self.floor_mean)
        self.effective_stddev = max(stddev, self.floor_stddev)

        # Error baseline
        err_counts      = [c for _, c in self._err_window]
        self.error_mean = max(
            sum(err_counts) / max(len(err_counts), 1),
            self.floor_mean
        )

        self.last_recalc = time.time()

        # Build audit entry
        entry = {
            'timestamp':        datetime.now().isoformat(),
            'action':           'BASELINE_RECALC',
            'source':           source,
            'effective_mean':   round(self.effective_mean, 4),
            'effective_stddev': round(self.effective_stddev, 4),
            'error_mean':       round(self.error_mean, 4),
        }
        self._recalc_log.append(entry)
        if len(self._recalc_log) > 50:
            self._recalc_log.pop(0)

        # Write to audit log file in required format
        line = (
            f'[{entry["timestamp"]}] BASELINE_RECALC  | '
            f'source={source} | '
            f'rate={self.effective_mean:.4f} | '
            f'baseline={self.effective_mean:.4f} | '
            f'duration=0'
        )
        try:
            with open(self.audit_log_path, 'a', encoding='utf-8') as f:
                f.write(line + '\n')
        except Exception as e:
            print(f'[baseline] audit write error: {e}')
