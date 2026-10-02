#!/usr/bin/env python3
"""Write the store and the secrets the RADIUS container check uses.

  make-store.py <out dir>

<out dir>/store.yaml is a tacctl store with real bcrypt hashes; sec.<scope>
holds each scope's secret for 'radclient -S'. The passwords are in cases.sh.
Needs python3-bcrypt. 10.0.2.0/24 in scope 'prod' and in filters.allow is
replaced by the container's own network (setup.sh).
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
    scopes: [lab]
    hash: {h("Bond-James-Bond-7")}
    disabled: false
  alice:
    group: superuser
    scopes: [lab, prod, v6]
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
    scopes: [tonly, bs]
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
filters:
  allow: [127.0.0.0/29, 127.0.0.64/26, 10.0.2.0/24, '::1/128']
  deny: [127.0.0.66/32]
'''

out = sys.argv[1]
os.makedirs(out, exist_ok=True)
with open(os.path.join(out, 'store.yaml'), 'w') as f:
    f.write(STORE)
for name, secret in SECRETS.items():
    with open(os.path.join(out, 'sec.' + name), 'w') as f:
        f.write(secret)
