# Network access

[Documentation](../README.md) › [Security](README.md)

## Bind to a specific interface
The default listener is `-address :49` (all interfaces). Change it to your management IP:
```
tacctl config listen tcp 10.1.0.1:49
tacctl config listen --backend radius --listener auth udp 10.1.0.1:1812    # and the RADIUS ones,
                                                                           # where enabled
tacctl config listen --backend radius --listener acct udp 10.1.0.1:1813
```
The settings live in `tacctl.yaml` (`listeners.<backend>.<name>`), from which tacctl renders the units' systemd drop-ins, so they survive `tacctl upgrade`. Use `tacctl config listen show` to inspect, or `tacctl config listen reset` to revert to the default. More listeners: [Listeners](../server/backends.md#listeners).

## Configure connection filters
Use allow/deny lists for additional IP-level filtering (enforced by every backend; a filtered client gets no answer):
```
tacctl config allow add 10.1.0.0/24
tacctl config deny add 10.99.0.0/24
```
Deny takes precedence over allow.
