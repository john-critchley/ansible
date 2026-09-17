#!/usr/bin/python3
"""Keep worker counters in journald without logging URLs, tokens or clients."""
import urllib.request

FIELDS = {
    'BusyWorkers', 'IdleWorkers', 'GracefulWorkers', 'Processes', 'Stopping',
    'ConnsTotal', 'ConnsAsyncWaitIO', 'ConnsAsyncWriting',
    'ConnsAsyncKeepAlive', 'ConnsAsyncClosing', 'Scoreboard',
}
try:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open('http://127.0.0.1/server-status?auto', timeout=10) as response:
        values = dict(line.split(': ', 1) for line in response.read(65536).decode().splitlines() if ': ' in line)
    if 'BusyWorkers' not in values:
        raise ValueError('status response missing worker counters')
    pressure = int(values['BusyWorkers']) >= 300 or int(values.get('Stopping', '0')) >= 8
    print(('WARNING worker pressure: ' if pressure else '') + ' '.join(f'{key}={values[key]}' for key in sorted(FIELDS) if key in values), flush=True)
except Exception as exc:
    print(f'WARNING Apache status unavailable: {type(exc).__name__}', flush=True)
    raise SystemExit(1)
