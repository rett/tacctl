#!/usr/bin/env python3
"""Regenerate corpus.jsonl: inputs run through the Python the bash code runs.

    python3 internal/cidr/testdata/gen.py > internal/cidr/testdata/corpus.jsonl

Each line is {"in": s, "canon": str|null, "key": [version, broadcast, network]|null,
"wildcard": str|null} as lib/core.sh (canonicalize_cidr, sort_cidrs_by_specificity)
and lib/render_devices.sh (cidr_to_cisco_wildcard) compute them with
ipaddress.ip_network(s, strict=False). A deterministic seed keeps the file
stable; the hand-written cases come first. Python 3.12 is the reference (3.13
prints IPv4-mapped IPv6 addresses differently).
"""
import ipaddress
import json
import random

hand = [
    "10.0.0.0/8", "192.168.1.0/24", "10.1.5.5/32", "10.1.5.5/24", "172.16.1.99/16",
    "2001:db8::/32", "fe80::/10", "2001:DB8::/32", "2001:0db8:0000::/48",
    "not-a-cidr", "10.0.0.0/33", "999.0.0.0/8", "", " ", " 10.0.0.0/8", "10.0.0.0/8 ",
    "10.0.0.1", "1.2.3.4/0", "0.0.0.0/0", "::/0", "::", "::1", "::1/128", "::ffff:1.2.3.4/96",
    "::ffff:1.2.3.4", "1::", "1::/16", "1:2:3:4:5:6:7:8", "1:2:3:4:5:6:7:8/64",
    "1:2:3:4:5:6:7::", "1:2:3:4:5:6:7:8:9", "1::2::3", ":1:2:3:4:5:6:7", "1:2:3:4:5:6:7:",
    "1:2:3:4:5:6:1.2.3.4", "1:2:3:4:5:6:7:1.2.3.4", "::1.2.3.4", "::1.2.3.256",
    "fe80::1%eth0/64", "fe80::%eth0/64", "fe80::%eth0", "fe80::1%/64", "fe80::1%a%b/64", "fe80::1%eth0",
    "10.0.0.0/255.255.255.0", "10.0.0.0/0.0.0.255", "10.0.0.0/255.0.255.0", "10.0.0.0/0.255.0.255",
    "10.0.0.0/0.0.0.0", "10.0.0.0/255.255.255.255", "10.0.0.0/0.0.0.1", "10.0.0.0/255.255.255.254",
    "10.0.0.0/", "/24", "/", "10.0.0.0//24", "10.0.0.0/24/24", "10.0.0.0/+24", "10.0.0.0/ 24",
    "10.0.0.0/024", "10.0.0.0/0000000000024", "10.0.0.0/-1", "10.0.0.0/8.", "10.0.0.0/1e1",
    "01.2.3.4", "1.2.3.04", "1.2.3.0", "1.2.3", "1.2.3.4.5", "1..3.4", "1.2.3.4.", ".1.2.3.4",
    "1.2.3.256", "1.2.3.1000", "1.2.3.-1", "1.2.3.+1", "1.2.3.0x1", "a.b.c.d", "１.2.3.4",
    "2001:db8::/129", "2001:db8::/-1", "2001:db8::/0128", "2001:db8::/255.255.0.0", "2001:db8::1/abc",
    "2001:db8:::1", "2001:db8::g", "2001:db8::12345", "2001:db8::0:0:0:1", "2001:0:0:1:0:0:0:1",
    "2001:0:0:1:0:0:1:1", "0:0:0:0:0:0:0:0", "0:0:0:0:0:0:0:1", "1:0:0:0:0:0:0:0", "0:0:1:0:0:0:0:0",
    "1:0:1:0:1:0:1:0", "1:0:0:1:0:0:1:0", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF/128",
    "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/1", "8000::/1", "8000::/65", "::8000:0:0:0/65",
    "10.0.0.0\n", "10.0.0.0/8\n", "\t10.0.0.0/8", "10.0.0.0/8\x00",
    "1.2.3.4/32", "255.255.255.255/31", "255.255.255.255/1", "128.0.0.0/1", "127.0.0.1/8",
    "10.0.0.0/24", "10.0.0.0/25", "10.0.0.128/25", "192.0.2.0/27",
    "1:2:3:4:5:6:7:8/8", "1:2:3:4:5:6:7:8/127", "[::1]/128", "::1/", "::1/ 1", "::/00",
    "0::0", "00000::", "0000::", "::0000", "::00000", "1:2::3:4:5:6:7", "1:2:3:4::5:6:7:8",
]

rng = random.Random(20261003)

def rand_v4():
    a = [str(rng.choice([0, 1, 10, 127, 128, 172, 192, 224, 255, rng.randrange(256)])) for _ in range(4)]
    s = ".".join(a)
    r = rng.random()
    if r < 0.6:
        s += "/" + str(rng.randrange(0, 34))
    elif r < 0.7:
        s += "/" + ".".join(str(rng.choice([0, 128, 192, 224, 240, 248, 252, 254, 255])) for _ in range(4))
    elif r < 0.75:
        s += "/" + ".".join(str(rng.choice([0, 1, 3, 7, 15, 31, 63, 127, 255])) for _ in range(4))
    return s

def rand_v6():
    n = rng.randrange(1, 9)
    hs = ["%x" % rng.choice([0, 0, 0, 1, 0xdb8, 0x2001, 0xfe80, 0xffff, rng.randrange(65536)]) for _ in range(n)]
    if rng.random() < 0.5:
        i = rng.randrange(len(hs) + 1)
        hs.insert(i, "")
        s = ":".join(hs)
        if i == 0:
            s = ":" + s
        if i == len(hs) - 1:
            s += ":"
        s = s.replace(":::", "::")
    else:
        s = ":".join(("%x" % rng.randrange(65536)) for _ in range(8))
    if rng.random() < 0.3:
        s = s.upper()
    r = rng.random()
    if r < 0.7:
        s += "/" + str(rng.randrange(0, 130))
    return s

def mutate(s):
    r = rng.random()
    if not s:
        return s
    i = rng.randrange(len(s))
    if r < 0.3:
        return s[:i] + s[i + 1:]
    if r < 0.6:
        return s[:i] + rng.choice(".:/% 0x-+g\t") + s[i:]
    return s[:i] + rng.choice("0123456789abcdef./:") + s[i + 1:]

cases = list(hand)
for _ in range(500):
    cases.append(rand_v4())
for _ in range(500):
    cases.append(rand_v6())
for _ in range(500):
    cases.append(mutate(rng.choice([rand_v4, rand_v6])()))

seen = set()
for s in cases:
    if s in seen:
        continue
    seen.add(s)
    try:
        n = ipaddress.ip_network(s, strict=False)
    except ValueError:
        rec = {"in": s, "canon": None, "key": None, "wildcard": None}
    else:
        rec = {
            "in": s,
            "canon": str(n),
            "key": [n.version, str(int(n.broadcast_address)), str(int(n.network_address))],
            "wildcard": (f"{n.network_address} {n.hostmask}" if n.version == 4 else None),
        }
    print(json.dumps(rec, ensure_ascii=True))
