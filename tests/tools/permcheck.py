#!/usr/bin/env python3
"""permcheck.py: lab check of per-command authorization against a TACACS+ server.

    permcheck.py --host HOST [--port 49] --secret SECRET [options] CASES

Sends one TACACS+ authorization request (RFC 8907, service=shell, the way
IOS asks per command) for every line of CASES and compares the server's
answer with the one the line expects. It is a lab harness for the command
rules of docs/plans/0.2.3-baseline-design.md: it proves what the daemon
decides (tacquito's anchoring, fall-through and catch-all behaviour)
without a device. It sends no password and changes nothing on the server;
the users it names need an account in a group with command rules, and the
server must accept this machine as a client of SECRET.

CASES is a text file of lines

    user|cmd|args|expected

    user      the TACACS+ user to ask for (a lab account, for example one
              named gotest...: never a production one)
    cmd       the command word (show, clear, configure, ...)
    args      the arguments, separated by blanks, each sent as its own
              cmd-arg (empty for none); a '<cr>' is appended as IOS does
    expected  permit or deny

Blank lines and lines starting with '#' are ignored. A '|' cannot occur in
a field. Example lines:

    gotestviewer|show|running-config|permit
    gotestviewer|show|tech-support|deny
    gotestviewer|terminal|length 0|permit
    gotestengineer|reload||deny

Options:
    --host HOST        the server (required)
    --port PORT        its TACACS+ port (default 49)
    --secret SECRET    the shared secret of this client (or the environment
                       variable PERMCHECK_SECRET); use a lab secret, and
                       never put a production one on a command line
    --priv N           priv-lvl of the request (default 15)
    --no-cr            do not append the trailing cmd-arg '<cr>'
    --timeout SECONDS  per-request timeout (default 5)
    -q, --quiet        print only the lines that differ and the summary
    -h, --help         this text

Exit status: 0 when every line got the expected answer, 1 when any differed
or the server did not answer, 2 for a usage error or an unreadable CASES.

Example against a throwaway server (fake secret):

    permcheck.py --host 127.0.0.1 --port 14949 --secret fakeprobesecret1 cases.txt

The test pairs of the baseline are in tests/tools/permcheck-baseline.txt.
"""
import argparse
import hashlib
import os
import socket
import struct
import sys

STATUS = {1: "permit", 2: "permit", 0x10: "deny", 0x11: "error"}
STATUS_NAME = {1: "PASS_ADD", 2: "PASS_REPL", 0x10: "FAIL", 0x11: "ERROR"}


def _pad(sid, ver, seq, key, n):
    """The MD5 pseudo-random pad that obfuscates a TACACS+ body."""
    out, prev = b"", b""
    while len(out) < n:
        prev = hashlib.md5(struct.pack(">I", sid) + key + bytes([ver, seq]) + prev).digest()
        out += prev
    return out[:n]


def _xor(data, pad):
    return bytes(a ^ b for a, b in zip(data, pad))


def _recv(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise OSError("connection closed by the server")
        buf += chunk
    return buf


def author(host, port, key, user, args, priv=15, timeout=5.0):
    """One authorization request; returns (status word, server message, reply args)."""
    items = [a.encode() for a in args]
    # authen_method TACACSPLUS(6), priv_lvl, authen_type ASCII(1), service login(1)
    body = struct.pack("BBBBBBBB", 6, priv, 1, 1, len(user), 0, 0, len(items))
    body += bytes(len(a) for a in items) + user.encode() + b"".join(items)
    sid = int.from_bytes(os.urandom(4), "big")
    ver, seq = 0xC0, 1
    header = struct.pack(">BBBBII", ver, 2, seq, 0, sid, len(body))  # type 2 = authorization
    with socket.create_connection((host, port), timeout=timeout) as s:
        s.sendall(header + _xor(body, _pad(sid, ver, seq, key, len(body))))
        v, _t, sq, _fl, rsid, ln = struct.unpack(">BBBBII", _recv(s, 12))
        reply = _xor(_recv(s, ln), _pad(rsid, v, sq, key, ln))
    status, argc, msg_len, data_len = struct.unpack(">BBHH", reply[:6])
    lens = list(reply[6:6 + argc])
    off = 6 + argc
    msg = reply[off:off + msg_len].decode(errors="replace")
    off += msg_len + data_len
    rargs = []
    for n in lens:
        rargs.append(reply[off:off + n].decode(errors="replace"))
        off += n
    return STATUS.get(status, hex(status)), msg, rargs


def request_args(cmd, cmd_args, cr=True):
    args = ["service=shell", "protocol=ip", "cmd=" + cmd]
    args += ["cmd-arg=" + a for a in cmd_args]
    if cr:
        args.append("cmd-arg=<cr>")
    return args


def parse_cases(text):
    """Yield (line number, user, cmd, args list, expected) for each case line."""
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 4:
            raise ValueError("line %d: want user|cmd|args|expected, got %r" % (number, line))
        user, cmd, args, expected = (f.strip() for f in fields)
        if not user or not cmd:
            raise ValueError("line %d: user and cmd are required" % number)
        if expected not in ("permit", "deny"):
            raise ValueError("line %d: expected must be permit or deny, got %r" % (number, expected))
        yield number, user, cmd, args.split(), expected


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="permcheck.py",
        description="Check per-command TACACS+ authorization against expected answers.",
        epilog="Lines of CASES: user|cmd|args|expected (permit or deny). See the head of this file.",
    )
    ap.add_argument("cases", help="file of user|cmd|args|expected lines")
    ap.add_argument("--host", required=True)
    ap.add_argument("--port", type=int, default=49)
    ap.add_argument("--secret", default=os.environ.get("PERMCHECK_SECRET"))
    ap.add_argument("--priv", type=int, default=15)
    ap.add_argument("--no-cr", action="store_true")
    ap.add_argument("--timeout", type=float, default=5.0)
    ap.add_argument("-q", "--quiet", action="store_true")
    opts = ap.parse_args(argv)
    if not opts.secret:
        print("permcheck: --secret (or PERMCHECK_SECRET) is required", file=sys.stderr)
        return 2
    try:
        with open(opts.cases, encoding="utf-8") as f:
            cases = list(parse_cases(f.read()))
    except (OSError, ValueError) as e:
        print("permcheck: %s" % e, file=sys.stderr)
        return 2
    key = opts.secret.encode()
    bad = 0
    for number, user, cmd, args, expected in cases:
        label = "%s: %s %s" % (user, cmd, " ".join(args))
        try:
            got, msg, _ = author(opts.host, opts.port, key, user,
                                 request_args(cmd, args, not opts.no_cr), opts.priv, opts.timeout)
        except (OSError, struct.error) as e:
            bad += 1
            print("ERROR line %d  %s  (%s)" % (number, label.rstrip(), e))
            continue
        if got == expected:
            if not opts.quiet:
                print("ok    line %d  %-7s %s" % (number, got, label.rstrip()))
        else:
            bad += 1
            print("DIFF  line %d  got %s, want %s  %s%s" % (
                number, got, expected, label.rstrip(), ("  [" + msg + "]") if msg else ""))
    print("%d case(s), %d differ" % (len(cases), bad))
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
