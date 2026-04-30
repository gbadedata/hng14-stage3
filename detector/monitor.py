# monitor.py
# Continuously tails the Nginx JSON access log and yields parsed entries.
import time
import json
import os


def tail_log(log_path: str):
    """
    Generator that yields parsed log entry dicts, one per HTTP request.
    Waits for the file to exist, then seeks to the end and follows new lines.
    """
    while not os.path.exists(log_path):
        print(f'[monitor] Waiting for log file: {log_path}')
        time.sleep(2)

    with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
        f.seek(0, 2)  # Seek to end — skip historical lines
        print(f'[monitor] Tailing: {log_path}')
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)  # 50ms poll — low CPU cost
                continue
            entry = _parse(line.strip())
            if entry:
                yield entry


def _parse(line: str):
    """
    Parse one JSON log line into a normalised dict.
    Returns None if the line is empty or malformed.
    """
    if not line:
        return None
    try:
        raw = json.loads(line)
        for field in ('source_ip', 'timestamp', 'method', 'path', 'status', 'response_size'):
            if field not in raw:
                return None
        return {
            'source_ip':     raw['source_ip'],
            'timestamp':     raw['timestamp'],
            'method':        raw['method'],
            'path':          raw['path'],
            'status':        int(raw['status']),
            'response_size': int(raw['response_size']),
            'is_error':      int(raw['status']) >= 400,
            'parsed_time':   time.time(),
        }
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return None
