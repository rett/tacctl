#!/usr/bin/env python3
"""Run a command in a pty and answer its first password prompt.

usage: pty-run.py PASSWORD COMMAND [ARGS...]

tacctl asks for the device password on the terminal (never an argument or
the environment), so a harness needs a pty to give it. The command's output
is printed when it ends; the exit status is the command's.
"""
import os
import pty
import select
import sys
import time

TIMEOUT = 900


def main() -> int:
    if len(sys.argv) < 3:
        sys.stderr.write(__doc__)
        return 2
    password, argv = sys.argv[1], sys.argv[2:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp(argv[0], argv)
    buf = b""
    sent = False
    end = time.time() + TIMEOUT
    while time.time() < end:
        ready, _, _ = select.select([fd], [], [], 1)
        if not ready:
            continue
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        buf += data
        if not sent and b"assword" in buf[-200:]:
            os.write(fd, password.encode() + b"\n")
            sent = True
    _, status = os.waitpid(pid, 0)
    sys.stdout.write(buf.decode(errors="replace").replace("\r", ""))
    return os.waitstatus_to_exitcode(status)


if __name__ == "__main__":
    sys.exit(main())
