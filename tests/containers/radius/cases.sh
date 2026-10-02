#!/bin/bash
# The radclient cases of the RADIUS container check (tests/README.md,
# "RADIUS in containers"). Run inside the container once FreeRADIUS serves
# tacctl's rendered files:  cases.sh <dir with sec.* files>
# Prints PASS/FAIL per case; exit 0 when all pass.
#
# Clients are told apart by source address: everything in 127.0.0.0/8 is
# local, so radclient can send from 127.0.0.2, .3, .4, .9, .66
# (Packet-Src-IP-Address); a request to the container's own address comes
# from that address (scope prod).
cd "${1:?usage: cases.sh <dir with sec.* files>}" || exit 2
MYIP=$(hostname -I | cut -d' ' -f1)
pass=0; fail=0

# rq <dest> <scope whose secret to use> <user> <password> [<source ip>]
#   -> 'Accept <reply attributes>' | 'Reject <reply attributes>' | 'None'
rq() {
    local dest="$1" sec="$2" user="$3" pw="$4" src="${5:-}" out
    out=$( { printf 'User-Name = "%s"\nUser-Password = "%s"\n' "$user" "$pw"
             [[ -n "$src" ]] && printf 'Packet-Src-IP-Address = %s\n' "$src"; } \
        | radclient -x -r 1 -t 3 -S "sec.${sec}" "$dest" auth 2>&1)
    if grep -q 'Received Access-Accept' <<< "$out"; then
        echo "Accept $(grep -E '^\s+(Service-Type|Cisco-AVPair|Juniper-Local-User-Name)' <<< "$out" | tr -s '\t\n' ' ')"
    elif grep -q 'Received Access-Reject' <<< "$out"; then
        echo "Reject $(grep -E '^\s+(Service-Type|Cisco-AVPair|Juniper-Local-User-Name)' <<< "$out" | tr -s '\t\n' ' ')"
    else
        echo "None"
    fi
}

# t <description> <expected regex> <result>
t() {
    if [[ "$3" =~ $2 ]]; then
        pass=$((pass + 1)); echo "PASS  $1  ->  $3"
    else
        fail=$((fail + 1)); echo "FAIL  $1  ->  $3   (expected: $2)"
    fi
}

BOB_PW='pass word %{x} \"q\"'
t "alice, right password, scope lab (127.0.0.1)"  '^Accept .*Service-Type = Administrative-User .*Cisco-AVPair = "shell:priv-lvl=15" .*Juniper-Local-User-Name = "RW-CLASS"' "$(rq 127.0.0.1 lab alice 'Correct-Horse-1')"
t "alice, wrong password: reject, no reply attributes" '^Reject $' "$(rq 127.0.0.1 lab alice 'wrong-password')"
t "bob (\$2a\$ hash, password with space, %{}, quotes), lab" '^Accept .*NAS-Prompt-User .*priv-lvl=7" .*"OP-CLASS"' "$(rq 127.0.0.1 lab bob "$BOB_PW")"
t "007 (custom group priv 10, all-digit name), lab" '^Accept .*NAS-Prompt-User .*priv-lvl=10" .*"NETOPS_class-1"' "$(rq 127.0.0.1 lab 007 'Bond-James-Bond-7')"
t "bob from a prod client: not a user of that scope" '^Reject $' "$(rq "$MYIP" prod bob "$BOB_PW")"
t "alice from a prod client"                      '^Accept '   "$(rq "$MYIP" prod alice 'Correct-Horse-1')"
t "carol (disabled), right password"              '^Reject $'  "$(rq 127.0.0.1 lab carol 'Carol-Is-Disabled-1')"
t "root (accounting sink)"                        '^Reject $'  "$(rq 127.0.0.1 lab root 'anything')"
t "unknown user"                                  '^Reject $'  "$(rq 127.0.0.1 lab nobody 'x')"
t "alice, empty password"                         '^Reject $'  "$(rq 127.0.0.1 lab alice '')"
t "overlap: 127.0.0.2 belongs to scope inner (/32); lab's secret gets no answer" '^None$' "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.2)"
t "overlap: 127.0.0.2 with inner's secret; alice is not in inner" '^Reject $' "$(rq 127.0.0.1 inner alice 'Correct-Horse-1' 127.0.0.2)"
t "TACACS+-only scope: its secret is unknown to RADIUS" '^None$' "$(rq 127.0.0.1 tonly bob "$BOB_PW" 127.0.0.3)"
t "TACACS+-only scope: 127.0.0.3 is a lab client over RADIUS; dave (tonly, bs) is rejected" '^Reject $' "$(rq 127.0.0.1 lab dave 'Dave-Readonly-Pass-1' 127.0.0.3)"
t "secret with a backslash and both quotes (scope bs), dave" '^Accept .*priv-lvl=1" .*"RO-CLASS"' "$(rq 127.0.0.1 bs dave 'Dave-Readonly-Pass-1' 127.0.0.4)"
t "filters.deny 127.0.0.66 (inside an allowed range): no answer" '^None$' "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.66)"
t "filters.allow: 127.0.0.9 is outside every allowed range: no answer" '^None$' "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.9)"
t "the package's localhost/testing123 client is not served" '^None$' "$(rq 127.0.0.1 distro alice 'Correct-Horse-1')"
if ss -uln | grep -qE '\[::1?\]:1812'; then
    t "IPv6 client ::1 (scope v6, allowed by an IPv6 filter), alice" '^Accept ' "$(rq '[::1]' v6 alice 'Correct-Horse-1')"
else
    echo "SKIP  IPv6 client (no udp6 listener)"
fi
out=$(printf 'User-Name = "alice"\nCHAP-Password = "Correct-Horse-1"\n' | radclient -x -r 1 -t 3 -S sec.lab 127.0.0.1 auth 2>&1)
t "CHAP request for alice"                        'Received Access-Reject' "$(grep -o 'Received Access-[A-Za-z]*' <<< "$out" | head -1)"
out=$(printf 'Message-Authenticator = 0x00\n' | radclient -x -r 1 -t 2 -S sec.lab 127.0.0.1 status 2>&1)
t "Status-Server is not answered"                 'No reply'   "$(grep -o 'No reply' <<< "$out" | head -1)"
out=$(printf 'User-Name = "alice"\nAcct-Status-Type = Start\nAcct-Session-Id = "sess-0001"\nNAS-IP-Address = 127.0.0.1\n' | radclient -x -r 1 -t 3 -S sec.lab 127.0.0.1:1813 acct 2>&1)
t "accounting Start is acknowledged"              'Accounting-Response' "$(grep -o 'Received Accounting-Response' <<< "$out" | head -1)"
out=$(printf 'User-Name = "alice"\nAcct-Status-Type = Start\nAcct-Session-Id = "sess-0002"\nPacket-Src-IP-Address = 127.0.0.66\n' | radclient -x -r 1 -t 2 -S sec.lab 127.0.0.1:1813 acct 2>&1)
t "accounting from a denied address: no answer"   'No reply'   "$(grep -o 'No reply' <<< "$out" | head -1)"
echo "cases: ${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]
