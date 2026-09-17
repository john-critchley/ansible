# Apache capacity on gravlax

Deploy with `ansible-playbook apache_capacity.yml`. The same role runs under
`setup_server.yml --tags apache` during provisioning. Use the targeted playbook
on the existing server: the checkout's virtual hosts lag the live configuration.
The role deliberately requires event MPM, and validates Apache before a full
restart (needed for ServerLimit). Existing connections reconnect after restart.

The profile allows 400 simultaneous requests (previously 150), using 16 active
children of 25 threads. ServerLimit 32 (previously default 16) leaves another
16 slots for draining generations. This is a starting capacity for the 1.8 GiB
host, not a load-tested maximum. KeepAliveTimeout is 2 seconds; ProxyTimeout is
120 seconds of upstream inactivity. Active SSE streams can live indefinitely;
neither setting caps their lifetime. MaxConnectionsPerChild stays unlimited to
avoid introducing extra draining generations around long-lived streams.

## Investigation, 2026-09-05

- Apache 2.4.68, event MPM, 1,345 MiB available before deployment.
- Baseline: 1 busy worker (the status request), 49 idle, 0 stopping processes,
  0 active client connections, approximately 0.07 requests/second.
- Eight Apache backend sockets in CLOSE-WAIT to REST ports 8020/8120, despite
  idle workers. These alone do not establish worker exhaustion or a leak.
- Live MCP proxies (public/private/misc) already have disablereuse=On.
  Backend source enables legacy SSE and stateless Streamable HTTP; legacy SSE
  has no explicit maximum lifetime in the application handler.
- Retained Apache error logs contain no scoreboard/MaxRequestWorkers errors.
  August 5 error logs have rotated away. Systemd journal confirms a midnight
  graceful reload and a full restart at 06:07 UTC that day. This is consistent
  with, but does not prove, long-lived requests pinning old generations.
- Historical cause remains unconfirmed. Do not declare SSE leakage fixed.

Apache documents how active requests and draining processes consume different
limits: https://httpd.apache.org/docs/2.4/mod/event.html

## Capture a recurrence

The systemd timer samples local-only mod_status every minute into journald.
It reports WARNING at 300 busy workers, 8 stopping processes, or status failure.
This is diagnostic logging, not an external alert or automatic restart. Normal
journal retention applies. No request URLs, credentials or client IPs are logged.

```
sudo journalctl -u apache-worker-sample.service --since '1 hour ago'
curl -fsS --max-time 10 'http://127.0.0.1/server-status?auto'
# Run on gravlax during pressure; full status shows vhost, request and age.
# Treat full status as sensitive: request strings may contain credentials.
curl -fsS --max-time 10 'http://127.0.0.1/server-status'
sudo ss -tanp
sudo journalctl -u apache2 --since '1 hour ago'
```

High BusyWorkers plus old /mcp requests points to streams; high Stopping or
GracefulWorkers after reloads points to pinned generations. Idle workers with
CLOSE-WAIT backend sockets alone are not evidence of occupied request threads.
If active SSE is responsible, investigate disconnect cancellation and connection
limits in the MCP service; an idle timeout cannot bound heartbeating streams.
Separating MCP into another Apache instance would provide stronger isolation
than a shared worker pool, but is outside this capacity change.
