#!/bin/bash
# sshtry.sh <user> <password> <command...>: one SSH password login to this
# container's own sshd, running <command>. Prints the command's output, then
# 'rc=<status> t=<whole seconds>'. rc 255 is a refused login. Works without sshpass
# (not in the base repositories of every distribution): ssh asks
# SSH_ASKPASS for the password when it has no terminal.
user="$1"; export THC_PW="$2"; shift 2
SECONDS=0
out=$(DISPLAY=:0 SSH_ASKPASS=/usr/local/bin/thc-askpass SSH_ASKPASS_REQUIRE=force setsid -w \
    ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=1 -o ConnectTimeout=5 \
        "${user}@127.0.0.1" "$@" < /dev/null 2>&1)
rc=$?
printf '%s\n' "$out" | grep -v '^$' | grep -v 'Permission denied\|^Connection closed' || true
echo "rc=${rc} t=${SECONDS}"
