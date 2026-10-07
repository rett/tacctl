#!/usr/bin/env python3
"""Write the store and the secrets the RADIUS container check uses.

  make-store.py <out dir>

<out dir>/store.yaml is a tacctl store with real bcrypt hashes; sec.<scope>
holds each scope's secret for 'radclient -S'. The passwords are in cases.sh.
<out dir>/tacctl.yaml holds the per-group device settings (run.sh, flow.sh).
Needs python3-bcrypt. 10.0.2.0/24 in scope 'prod' and in filters.allow is
replaced by the container's own network (run.sh, flow.sh).

Vendor attributes (cases.sh): lab enables none and tags 127.0.0.10-12 with
each vendor; vc, vj, vw enable one vendor each and tag one address with
another vendor; vall enables all three and tags one address wti.
"""
import binascii
import os
import sys

import bcrypt


def h(pw, rounds=10, prefix=b'2b'):
    return binascii.hexlify(bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=rounds, prefix=prefix))).decode()


SECRETS = {
    'bs': 'back\\slash "and" quote\'s-secret',
    'inner': 'inner-secret-0123456789abcdef',
    'lab': 'it\'s a "lab" secret #1 ${confdir} %{User-Name}',
    'prod': 'prod-secret-0123456789abcdef',
    'tonly': 'tacacs-only-secret-0123456789',
    'v6': 'v6-secret-0123456789abcdef',
    'vc': 'vc-secret-0123456789abcdef',
    'vj': 'vj-secret-0123456789abcdef',
    'vw': 'vw-secret-0123456789abcdef',
    'vall': 'vall-secret-0123456789abcdef',
    # Not a scope: the client the FreeRADIUS package ships (localhost).
    'distro': 'testing123',
}


def yq(s):
    return "'" + s.replace("'", "''") + "'"


STORE = f'''version: 1
groups:
  operator: {{priv_lvl: 7, juniper_class: OP-CLASS, builtin: true}}
  readonly: {{priv_lvl: 1, juniper_class: RO-CLASS, builtin: true}}
  superuser: {{priv_lvl: 15, juniper_class: RW-CLASS, builtin: true}}
  netops: {{priv_lvl: 10, juniper_class: NETOPS_class-1}}
users:
  '007':
    group: netops
    scopes: [lab, vw]
    hash: {h("Bond-James-Bond-7")}
    disabled: false
  alice:
    group: superuser
    scopes: [lab, prod, v6, vc, vj, vw, vall]
    hash: {h("Correct-Horse-1", 12)}
    disabled: false
  bob:
    group: operator
    scopes: [lab, tonly]
    hash: {h('pass word %{x} "q"', 10, b'2a')}
    disabled: false
  carol:
    group: readonly
    scopes: [lab]
    hash: {h("Carol-Is-Disabled-1")}
    disabled: true
  dave:
    group: readonly
    scopes: [tonly, bs, vall]
    hash: {h("Dave-Readonly-Pass-1")}
    disabled: false
  root:
    group: readonly
    scopes: [lab]
    hash: null
    disabled: true
    accounting_sink: true
scopes:
  bs:
    prefixes: [127.0.0.4/32]
    secret: {yq(SECRETS['bs'])}
  inner:
    prefixes: [127.0.0.2/32]
    secret: {SECRETS['inner']}
  lab:
    prefixes: [127.0.0.0/8]
    secret: {yq(SECRETS['lab'])}
    devices: {{127.0.0.10/32: cisco, 127.0.0.11/32: juniper, 127.0.0.12/32: wti}}
  prod:
    prefixes: [10.0.2.0/24]
    secret: {SECRETS['prod']}
  tonly:
    prefixes: [127.0.0.3/32]
    secret: {SECRETS['tonly']}
    protocols: [tacacs]
  v6:
    prefixes: ['::1/128']
    secret: {SECRETS['v6']}
  vc:
    prefixes: [127.0.0.16/30]
    secret: {SECRETS['vc']}
    vendor_attrs: [cisco]
    devices: {{127.0.0.17/32: juniper, 127.0.0.18/32: cisco}}
  vj:
    prefixes: [127.0.0.20/30]
    secret: {SECRETS['vj']}
    vendor_attrs: [juniper]
    devices: {{127.0.0.21/32: wti}}
  vw:
    prefixes: [127.0.0.24/30]
    secret: {SECRETS['vw']}
    vendor_attrs: [wti]
    devices: {{127.0.0.25/32: cisco}}
  vall:
    prefixes: [127.0.0.28/30]
    secret: {SECRETS['vall']}
    vendor_attrs: [cisco, juniper, wti]
    devices: {{127.0.0.29/32: wti}}
filters:
  allow: [127.0.0.0/29, 127.0.0.10/31, 127.0.0.12/32, 127.0.0.16/28, 127.0.0.64/26, 10.0.2.0/24, '::1/128']
  deny: [127.0.0.66/32]
'''

# The per-group device settings of tacctl.yaml (0.2.2) for netops (cases.sh:
# 007): Junos deny sets, sent with the login class only, and a WTI level
# below the SuperUser band of its priv-lvl 10.
TACCTL_YAML = '''junos:
  netops:
    deny_commands: ['^request system', '^start shell']
    deny_configuration: ['^system login']
wti_level:
  netops: user
'''

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, 'store.yaml'), 'w') as f:
    f.write(STORE)
with open(os.path.join(out, 'tacctl.yaml'), 'w') as f:
    f.write(TACCTL_YAML)
for name, secret in SECRETS.items():
    with open(os.path.join(out, 'sec.' + name), 'w') as f:
        f.write(secret)
