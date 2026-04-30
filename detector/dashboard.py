# dashboard.py
# Flask web server — live metrics dashboard refreshing every 3 seconds.
import time
import threading
import psutil
from datetime import datetime
from flask import Flask, jsonify

app = Flask(__name__)
_st = {'start': time.time(), 'det': None, 'blk': None, 'base': None}


def init(detector, blocker, baseline):
    _st['det']  = detector
    _st['blk']  = blocker
    _st['base'] = baseline


@app.route('/')
def index():
    return _HTML


@app.route('/api/metrics')
def metrics():
    uptime = int(time.time() - _st['start'])
    h, r   = divmod(uptime, 3600)
    m, s   = divmod(r, 60)
    stats  = _st['base'].get_stats() if _st['base'] else {}
    return jsonify({
        'uptime':          f'{h:02d}:{m:02d}:{s:02d}',
        'global_rps':      _st['det'].global_rate()    if _st['det']  else 0,
        'baseline_mean':   stats.get('effective_mean',   0),
        'baseline_stddev': stats.get('effective_stddev', 0),
        'banned_ips':      _st['blk'].get_banned_ips() if _st['blk']  else [],
        'top_ips':         _st['det'].get_top_ips(10)  if _st['det']  else [],
        'cpu_pct':         psutil.cpu_percent(interval=None),
        'mem_pct':         psutil.virtual_memory().percent,
        'mem_used_mb':     round(psutil.virtual_memory().used / 1024**2, 1),
    })


def run(host: str, port: int):
    threading.Thread(
        target=lambda: app.run(host=host, port=port, debug=False, use_reloader=False),
        daemon=True,
        name='dashboard'
    ).start()
    print(f'[dashboard] http://{host}:{port}')


_HTML = '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>HNG14 Anomaly Detector</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:monospace;background:#0f172a;color:#e2e8f0;padding:20px}
  h1{color:#38bdf8;font-size:1.3em;margin-bottom:16px}
  .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:12px;margin-bottom:20px}
  .card{background:#1e293b;border:1px solid #334155;border-radius:8px;padding:14px}
  .label{color:#64748b;font-size:.75em;margin-bottom:4px}
  .val{color:#38bdf8;font-size:1.5em;font-weight:700}
  table{width:100%;border-collapse:collapse}
  th{color:#64748b;font-size:.8em;padding:6px 8px;text-align:left}
  td{padding:6px 8px;border-bottom:1px solid #1e293b;font-size:.9em}
  .banned{color:#f87171;font-weight:bold}
  #ts{color:#475569;font-size:.7em;margin-bottom:12px}
  .section{margin-bottom:20px}
</style>
</head>
<body>
<h1>&#x1F6E1; HNG14 Anomaly Detection Engine — Live Metrics</h1>
<div id="ts">Loading...</div>
<div id="grid" class="grid"></div>
<div id="banned" class="card section"></div>
<div id="topips" class="card"></div>
<script>
const fmt = n => (typeof n==='number' ? n.toFixed(3) : n);
async function refresh(){
  try{
    const d = await (await fetch('/api/metrics')).json();
    document.getElementById('ts').textContent = 'Updated: '+new Date().toLocaleTimeString();
    const metrics = [
      ['Global req/s',     fmt(d.global_rps)],
      ['Baseline mean',    fmt(d.baseline_mean)],
      ['Baseline stddev',  fmt(d.baseline_stddev)],
      ['CPU',              d.cpu_pct.toFixed(1)+'%'],
      ['Memory',           d.mem_pct.toFixed(1)+'% ('+d.mem_used_mb+'MB)'],
      ['Uptime',           d.uptime],
      ['Banned IPs',       d.banned_ips.length],
    ];
    document.getElementById('grid').innerHTML = metrics.map(([l,v])=>
      `<div class="card"><div class="label">${l}</div><div class="val">${v}</div></div>`
    ).join('');
    const bh = d.banned_ips.length ? d.banned_ips.map(b=>{
      const dur = b.duration===-1?'PERMANENT':b.duration+'s';
      const at  = new Date(b.banned_at*1000).toLocaleTimeString();
      return `<tr><td class="banned">${b.ip}</td><td>${b.condition}</td><td>${dur}</td><td>${at}</td></tr>`;
    }).join('') : '<tr><td colspan="4" style="color:#475569">No bans active</td></tr>';
    document.getElementById('banned').innerHTML =
      '<b style="color:#94a3b8">Banned IPs ('+d.banned_ips.length+')</b>'+
      '<table><tr><th>IP</th><th>Condition</th><th>Duration</th><th>Banned At</th></tr>'+bh+'</table>';
    const th = d.top_ips.length ? d.top_ips.map(([ip,r])=>
      `<tr><td>${ip}</td><td>${r.toFixed(4)} req/s</td></tr>`
    ).join('') : '<tr><td colspan="2" style="color:#475569">No traffic yet</td></tr>';
    document.getElementById('topips').innerHTML =
      '<b style="color:#94a3b8">Top 10 Source IPs</b>'+
      '<table><tr><th>IP</th><th>Rate</th></tr>'+th+'</table>';
  }catch(e){console.error(e)}
}
refresh();
setInterval(refresh, 3000);
</script>
</body>
</html>'''
