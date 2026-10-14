# Metrics, log retention and password age

[Documentation](../README.md) › [Server](README.md)

## Prometheus metrics exporter
Tacquito ships a Prometheus HTTP exporter for auth-rate and error counters (FreeRADIUS has none; `tacctl status` counts RADIUS accepts and rejects from its auth log). By default it binds to **loopback only** (`127.0.0.1:8080`): local scrapers on the box work, external scrapers are opt-in. Manage it with:
```
tacctl config metrics                         # show current state + scrape URL
tacctl config metrics address 10.1.0.1:8080   # expose to external scrapers on a specific mgmt IP
tacctl config metrics disable                 # sink to 127.0.0.1:0 (unreachable ephemeral port)
tacctl config metrics enable                  # revert to loopback:8080 default
```
`disable` does not use tacquito's own `-export-promhttp=false` flag, because upstream's handler cancels the server context when the exporter goroutine returns, which would tear down the whole daemon. Binding to a loopback ephemeral port keeps every scraper from reaching it instead.

## Log retention
Accounting logs are rotated daily and retained for 90 days (see `/etc/logrotate.d/tacquito`, and `/etc/logrotate.d/tacctl-radius` for RADIUS). Adjust the `rotate` value if your compliance requirements differ.

## Password age
The default password age warning is 90 days. Adjust with:
```
tacctl config password-age <days>
```
