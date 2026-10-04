#!/bin/bash
# The radclient cases of the RADIUS container check (tests/README.md,
# "RADIUS in containers"). Run inside the container once FreeRADIUS serves
# tacctl's rendered files:  cases.sh <dir with sec.* files>
# Prints PASS/FAIL per case; exit 0 when all pass.
#
# Clients are told apart by source address: everything in 127.0.0.0/8 is
# local, so radclient can send from 127.0.0.2, .3, .4, .9, .66 and the vendor
# scopes' addresses (Packet-Src-IP-Address); a request to the container's own
# address comes from that address (scope prod).
#
# A reply is decoded with tacctl's dictionary (radclient -D), so that
# tacctl's internal attributes would show by name, and every attribute of it
# is compared: an Accept must carry exactly the attributes a case names (the
# Message-Authenticator aside), a Reject none. An attribute the dictionary
# does not know would show as Attr-<n>.
cd "${1:?usage: cases.sh <dir with sec.* files>}" || exit 2
MYIP=$(hostname -I | cut -d' ' -f1)
pass=0; fail=0
DICT=""
for d in /etc/freeradius/3.0/tacctl-radius-dictionary /etc/raddb/tacctl-radius-dictionary; do
    [[ -r "${d}/dictionary" ]] && DICT="$d"
done
if [[ -z "$DICT" ]]; then
    echo "FAIL  tacctl's dictionary is not in the raddb; replies cannot be decoded"
    exit 1
fi
SEEN=""

# The reply attributes of radclient -x output on stdin, '; '-separated, in
# the order they came, without the Message-Authenticator.
reply_attrs() {
    sed -n '/^Received Access-/,$p' | sed '1d' | grep -E '^\s+[A-Za-z]' \
        | grep -v 'Message-Authenticator' | sed 's/^\s*//' | paste -sd';' | sed 's/;/; /g'
}

# rq <dest> <scope whose secret to use> <user> <password> [<source ip>]
#   -> 'Accept <reply attributes>' | 'Reject <reply attributes>' | 'None'
# A request is sent up to three times, 2 s apart, but only while no reply has
# come (radclient -r 3 -t 2): a lost or late reply is not a failure, and a
# reject is still reported as soon as it arrives.
rq() {
    local dest="$1" sec="$2" user="$3" pw="$4" src="${5:-}" out attrs
    out=$( { printf 'User-Name = "%s"\nUser-Password = "%s"\n' "$user" "$pw"
             [[ -n "$src" ]] && printf 'Packet-Src-IP-Address = %s\n' "$src"; } \
        | radclient -x -r 3 -t 2 -D "$DICT" -S "sec.${sec}" "$dest" auth 2>&1)
    attrs=$(reply_attrs <<< "$out")
    SEEN+="${attrs}"$'\n'
    if grep -q 'Received Access-Accept' <<< "$out"; then
        echo "Accept ${attrs}"
    elif grep -q 'Received Access-Reject' <<< "$out"; then
        echo "Reject ${attrs}"
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

# is <description> <expected exactly> <result>
is() {
    if [[ "$3" == "$2" ]]; then
        pass=$((pass + 1)); echo "PASS  $1  ->  $3"
    else
        fail=$((fail + 1)); echo "FAIL  $1  ->  $3   (expected exactly: $2)"
    fi
}

ADM='Service-Type = Administrative-User'
C15='Cisco-AVPair = "shell:priv-lvl=15"'
J_RW='Juniper-Local-User-Name = "RW-CLASS"'
W3='WTI-Super = Administrator'
BOB_PW='pass word %{x} \"q\"'

is "alice, right password, scope lab (enables no vendor): Service-Type only" "Accept ${ADM}" "$(rq 127.0.0.1 lab alice 'Correct-Horse-1')"
is "alice, wrong password: reject, no reply attributes" "Reject " "$(rq 127.0.0.1 lab alice 'wrong-password')"
is "bob (\$2a\$ hash, password with space, %{}, quotes), lab" "Accept Service-Type = NAS-Prompt-User" "$(rq 127.0.0.1 lab bob "$BOB_PW")"
is "007 (custom group priv 10, all-digit name), lab" "Accept Service-Type = NAS-Prompt-User" "$(rq 127.0.0.1 lab 007 'Bond-James-Bond-7')"
t "bob from a prod client: not a user of that scope" '^Reject $' "$(rq "$MYIP" prod bob "$BOB_PW")"
is "alice from a prod client (enables no vendor)" "Accept ${ADM}" "$(rq "$MYIP" prod alice 'Correct-Horse-1')"
t "carol (disabled), right password"              '^Reject $'  "$(rq 127.0.0.1 lab carol 'Carol-Is-Disabled-1')"
t "root (accounting sink)"                        '^Reject $'  "$(rq 127.0.0.1 lab root 'anything')"
t "unknown user"                                  '^Reject $'  "$(rq 127.0.0.1 lab nobody 'x')"
t "alice, empty password"                         '^Reject $'  "$(rq 127.0.0.1 lab alice '')"
t "overlap: 127.0.0.2 belongs to scope inner (/32); lab's secret gets no answer" '^None$' "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.2)"
t "overlap: 127.0.0.2 with inner's secret; alice is not in inner" '^Reject $' "$(rq 127.0.0.1 inner alice 'Correct-Horse-1' 127.0.0.2)"
t "TACACS+-only scope: its secret is unknown to RADIUS" '^None$' "$(rq 127.0.0.1 tonly bob "$BOB_PW" 127.0.0.3)"
t "TACACS+-only scope: 127.0.0.3 is a lab client over RADIUS; dave (tonly, bs) is rejected" '^Reject $' "$(rq 127.0.0.1 lab dave 'Dave-Readonly-Pass-1' 127.0.0.3)"
is "secret with a backslash and both quotes (scope bs), dave" "Accept Service-Type = NAS-Prompt-User" "$(rq 127.0.0.1 bs dave 'Dave-Readonly-Pass-1' 127.0.0.4)"
t "filters.deny 127.0.0.66 (inside an allowed range): no answer" '^None$' "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.66)"
t "filters.allow: 127.0.0.9 is outside every allowed range: no answer" '^None$' "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.9)"
t "the package's localhost/testing123 client is not served" '^None$' "$(rq 127.0.0.1 distro alice 'Correct-Horse-1')"

# --- vendor attributes: what the scope enables, what an address is tagged with
is "lab enables none; 127.0.0.10 tagged cisco: Cisco only"        "Accept ${ADM}; ${C15}"  "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.10)"
is "lab enables none; 127.0.0.11 tagged juniper: Juniper only"    "Accept ${ADM}; ${J_RW}" "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.11)"
is "lab enables none; 127.0.0.12 tagged wti: WTI only"            "Accept ${ADM}; ${W3}"   "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.12)"
is "vc enables cisco; untagged 127.0.0.16: Cisco only"            "Accept ${ADM}; ${C15}"  "$(rq 127.0.0.1 vc alice 'Correct-Horse-1' 127.0.0.16)"
is "vc enables cisco; 127.0.0.17 tagged juniper: Juniper, no Cisco" "Accept ${ADM}; ${J_RW}" "$(rq 127.0.0.1 vc alice 'Correct-Horse-1' 127.0.0.17)"
is "vc enables cisco; 127.0.0.18 tagged cisco: Cisco only"        "Accept ${ADM}; ${C15}"  "$(rq 127.0.0.1 vc alice 'Correct-Horse-1' 127.0.0.18)"
is "vj enables juniper; untagged 127.0.0.20: Juniper only"        "Accept ${ADM}; ${J_RW}" "$(rq 127.0.0.1 vj alice 'Correct-Horse-1' 127.0.0.20)"
is "vj enables juniper; 127.0.0.21 tagged wti: WTI, no Juniper"   "Accept ${ADM}; ${W3}"   "$(rq 127.0.0.1 vj alice 'Correct-Horse-1' 127.0.0.21)"
is "vw enables wti; untagged 127.0.0.24: WTI only"                "Accept ${ADM}; ${W3}"   "$(rq 127.0.0.1 vw alice 'Correct-Horse-1' 127.0.0.24)"
is "vw enables wti; 007 (priv 10): SuperUser"                     "Accept Service-Type = NAS-Prompt-User; WTI-Super = SuperUser" "$(rq 127.0.0.1 vw 007 'Bond-James-Bond-7' 127.0.0.24)"
is "vw enables wti; 127.0.0.25 tagged cisco: Cisco, no WTI"       "Accept ${ADM}; ${C15}"  "$(rq 127.0.0.1 vw alice 'Correct-Horse-1' 127.0.0.25)"
is "vall enables all three; untagged 127.0.0.28: all three"       "Accept ${ADM}; ${C15}; ${J_RW}; ${W3}" "$(rq 127.0.0.1 vall alice 'Correct-Horse-1' 127.0.0.28)"
is "vall enables all three; dave (readonly): priv 1, RO-CLASS, ViewOnly (WTI-Super 0)" \
    'Accept Service-Type = NAS-Prompt-User; Cisco-AVPair = "shell:priv-lvl=1"; Juniper-Local-User-Name = "RO-CLASS"; WTI-Super = ViewOnly' \
    "$(rq 127.0.0.1 vall dave 'Dave-Readonly-Pass-1' 127.0.0.28)"
is "vall enables all three; 127.0.0.29 tagged wti: WTI only"      "Accept ${ADM}; ${W3}"   "$(rq 127.0.0.1 vall alice 'Correct-Horse-1' 127.0.0.29)"
is "vall, wrong password: a reject carries no vendor attribute"   "Reject "                "$(rq 127.0.0.1 vall alice 'wrong-password' 127.0.0.28)"
is "vall, tagged wti, wrong password: no attribute"               "Reject "                "$(rq 127.0.0.1 vall alice 'wrong-password' 127.0.0.29)"
is "vc, a user not in the scope (bob): no attribute"              "Reject "                "$(rq 127.0.0.1 vc bob "$BOB_PW" 127.0.0.16)"
t "a tagged address with another scope's secret: no answer"      '^None$'                 "$(rq 127.0.0.1 lab alice 'Correct-Horse-1' 127.0.0.17)"

if ss -uln | grep -qE '\[::1?\]:1812'; then
    is "IPv6 client ::1 (scope v6, allowed by an IPv6 filter), alice" "Accept ${ADM}" "$(rq '[::1]' v6 alice 'Correct-Horse-1')"
else
    echo "SKIP  IPv6 client (no udp6 listener)"
fi
out=$(printf 'User-Name = "alice"\nCHAP-Password = "Correct-Horse-1"\n' | radclient -x -r 3 -t 2 -S sec.lab 127.0.0.1 auth 2>&1)
t "CHAP request for alice"                        'Received Access-Reject' "$(grep -o 'Received Access-[A-Za-z]*' <<< "$out" | head -1)"
out=$(printf 'Message-Authenticator = 0x00\n' | radclient -x -r 1 -t 2 -S sec.lab 127.0.0.1 status 2>&1)
t "Status-Server is not answered"                 'No reply'   "$(grep -o 'No reply' <<< "$out" | head -1)"
out=$(printf 'User-Name = "alice"\nAcct-Status-Type = Start\nAcct-Session-Id = "sess-0001"\nNAS-IP-Address = 127.0.0.1\n' | radclient -x -r 3 -t 2 -S sec.lab 127.0.0.1:1813 acct 2>&1)
t "accounting Start is acknowledged"              'Accounting-Response' "$(grep -o 'Received Accounting-Response' <<< "$out" | head -1)"
out=$(printf 'User-Name = "alice"\nAcct-Status-Type = Start\nAcct-Session-Id = "sess-0002"\nPacket-Src-IP-Address = 127.0.0.66\n' | radclient -x -r 1 -t 2 -S sec.lab 127.0.0.1:1813 acct 2>&1)
t "accounting from a denied address: no answer"   'No reply'   "$(grep -o 'No reply' <<< "$out" | head -1)"

# Over every reply above: nothing of tacctl's own, nothing undecodable.
is "no tacctl-internal or unknown attribute in any reply" "" "$(grep -oE '(Tacctl-|Tmp-|Attr-)[A-Za-z0-9.-]*' <<< "$SEEN" | sort -u | paste -sd' ')"
echo "cases: ${pass} passed, ${fail} failed"
[[ $fail -eq 0 ]]
