package hosts

// The scripts of 'host provisioner <name> rotate': a small dedicated pair
// (not client-install.sh) that RunScript copies to the host and runs as
// root there, over the ssh session the rotation already has.
//
//   - the create script makes the new provisioning account (or adopts one
//     it made on an earlier run: root's own record under RotateStateDir
//     says so; the comment field of the account proves nothing, the account
//     can change it), writes the account's public key (as the account, with
//     --key) or runs the host's own passwd on the terminal (--password: the
//     password is typed into that passwd and never reaches tacctl), and
//     only then, last, gives the account its sudoers line in
//     RotateSudoersFile. A failure takes back what the run did, including
//     the sudoers line;
//   - the remove script takes an account away again (a new account whose
//     proof failed, or the old one, last, over the new one): the sudoers
//     line first, then processes ended, userdel, and the home directory
//     moved out of reach and made root-owned unless it is to be deleted
//     (client-install.sh's home_refusal and keep_home). It can also take
//     only the sudoers line away (an adopted account stays).
//
// The values the scripts need come in a header of shell assignments
// (validated, then quoted); the bodies are constants. The shared sudoers
// file is changed under a lock on the host (flock, else a lock directory),
// so two scripts at once lose no line.

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/shellquote"
)

const (
	// RotateMarker is the comment (the account's GECOS field) of an account
	// 'host provisioner' made. It is not the one 'host sync' gives and
	// manages (internal/hosts/accounts.go). It is for display only: the
	// field is the account's own to change (chfn) or comes from a directory
	// service, so nothing is decided by it. What proves an account is
	// tacctl's is root's record of creating it (RotateStateDir).
	RotateMarker = "tacctl provisioning account"
	// RotateStateDir is the directory on the host (root's, 0700) with one
	// record file per account the create script made: the account name, its
	// UID and whether ~/.ssh was made by the script. A re-run adopts an
	// account only when this record agrees with /etc/passwd.
	RotateStateDir = "/var/lib/tacctl-provisioner"
	// RotateSudoersFile holds one line per provisioning account; never
	// tacctl-host, which each sync rewrites.
	RotateSudoersFile = "/etc/sudoers.d/tacctl-provisioner"

	// AuthKey and AuthPassword are the two ways the new account logs in.
	AuthKey      = "key"
	AuthPassword = "password"

	// The lines the create script prints for the command line to read
	// (Env.RotateStatus): what the run did, so that a failed proof takes
	// back exactly that and no more.
	// OriginCreated and OriginAdopted are the two origins; SudoersAdded,
	// SudoersChanged and SudoersUnchanged what the run did to the
	// account's line (none before; another one before; the same one).
	OriginCreated     = "created"
	OriginAdopted     = "adopted"
	SudoersAdded      = "added"
	SudoersChanged    = "changed"
	SudoersUnchanged  = "unchanged"
	statusLinePattern = `^\[INFO\] (origin|sudoers-line): ([a-z]+)$`
)

var (
	reAccountName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)
	reRotatePub   = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com) [A-Za-z0-9+/]+={0,3}`)
	reStatusLine  = regexp.MustCompile(statusLinePattern)
)

// RotateStatus is what a create script reported doing (empty fields: it
// reported nothing).
type RotateStatus struct {
	// Origin is OriginCreated or OriginAdopted.
	Origin string
	// Sudoers is SudoersAdded, SudoersChanged or SudoersUnchanged.
	Sudoers string
}

// ValidAccountName reports whether name is a login name the rotation
// creates: lower case, digits, '_' and '-', at most 32, not starting with
// a digit or '-'.
func ValidAccountName(name string) bool { return reAccountName.MatchString(name) }

// PublicKeyLine is the part of an ssh public key line the new account's
// authorized_keys holds: the type and the key, with a fixed comment. ok is
// false for text that is not one key.
func PublicKeyLine(text string) (line string, ok bool) {
	for _, l := range strings.Split(text, "\n") {
		if l = strings.TrimSpace(l); l == "" {
			continue
		}
		m := reRotatePub.FindString(l)
		if m == "" {
			return "", false
		}
		return m + " tacctl-provisioner", true
	}
	return "", false
}

// ProvisionerSudoersLine is the account's line in RotateSudoersFile:
// passwordless for a key login (the account has no password), with the
// account's own password otherwise.
func ProvisionerSudoersLine(account, auth string) string {
	if auth == AuthKey {
		return account + " ALL=(ALL:ALL) NOPASSWD: ALL"
	}
	return account + " ALL=(ALL:ALL) ALL"
}

// UseraddLine is the command the create script runs first, as the plan
// prints it: below the first number of tacctl's range, for the group as
// well. (The script tries the intervals below the range that no earlier
// range of the server covers, highest first, and falls back to a
// system-range number.)
func UseraddLine(account string, r Range) string {
	n := strconv.Itoa(r.Min - 1)
	return "useradd -m -U -s /bin/bash -c '" + RotateMarker + "' -K UID_MAX=" + n + " -K GID_MAX=" + n + " " + account
}

// RotateCreate is the create script's input.
type RotateCreate struct {
	// Account is the new login; Auth is AuthKey or AuthPassword; PubKey is
	// the key line (PublicKeyLine) for AuthKey.
	Account, Auth, PubKey string
	// Range is the server's UID range and Avoid the ranges it used before
	// (and any other the account must stay out of).
	Range Range
	Avoid []Range
}

// forbidden is the ranges the account must stay out of, "<min>-<max> ...".
func (c RotateCreate) forbidden() string {
	out := []string{c.Range.String()}
	for _, r := range c.Avoid {
		out = append(out, r.String())
	}
	return strings.Join(out, " ")
}

// Script is the create script.
func (c RotateCreate) Script() []byte {
	var b strings.Builder
	q := func(name, v string) { b.WriteString(name + "=" + shellquote.Q(v) + "\n") }
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# tacctl: create the provisioning account (tacctl host provisioner ... rotate).\n")
	b.WriteString("# Holds a public key at most; no password and no secret. Deleted after use.\n")
	b.WriteString("set -euo pipefail\n")
	b.WriteString("umask 077\n")
	q("ACCOUNT", c.Account)
	q("AUTH", c.Auth)
	q("PUBKEY", c.PubKey)
	q("UID_FIRST", strconv.Itoa(c.Range.Min))
	q("FORBIDDEN", c.forbidden())
	q("MARKER", RotateMarker)
	q("SUDOERS_LINE", ProvisionerSudoersLine(c.Account, c.Auth))
	q("SUDOERS_FILE", RotateSudoersFile)
	q("STATE_DIR", RotateStateDir)
	b.WriteString(rotateCommon)
	b.WriteString(rotateCreateBody)
	return []byte(b.String())
}

// RotateRemove is the remove script's input.
type RotateRemove struct {
	// Account is the login to remove.
	Account string
	// RemoveHome deletes the home directory; else it is moved out of reach
	// and made root-owned.
	RemoveHome bool
	// SudoersOnly takes only the account's line out of the sudoers file and
	// leaves the account, its home and its record (an adopted account whose
	// proof failed).
	SudoersOnly bool
	// Range is the server's UID range and Avoid the earlier ones: an
	// account with a number in them belongs to 'host sync' and is refused.
	Range Range
	Avoid []Range
}

// Script is the remove script.
func (r RotateRemove) Script() []byte {
	var b strings.Builder
	q := func(name, v string) { b.WriteString(name + "=" + shellquote.Q(v) + "\n") }
	flag := func(v bool) string {
		if v {
			return "1"
		}
		return "0"
	}
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# tacctl: remove a provisioning account (tacctl host provisioner ... rotate).\n")
	b.WriteString("# Deleted after use.\n")
	b.WriteString("set -euo pipefail\n")
	b.WriteString("umask 077\n")
	q("ACCOUNT", r.Account)
	q("REMOVE_HOME", flag(r.RemoveHome))
	q("SUDOERS_ONLY", flag(r.SudoersOnly))
	q("FORBIDDEN", RotateCreate{Range: r.Range, Avoid: r.Avoid}.forbidden())
	q("SUDOERS_FILE", RotateSudoersFile)
	q("STATE_DIR", RotateStateDir)
	b.WriteString(rotateCommon)
	b.WriteString(rotateRemoveBody)
	return []byte(b.String())
}

// rotateCommon is what both scripts share: messages, the test knobs, the
// range check, the lock, the account's line in the sudoers file and root's
// record of the accounts the create script made.
const rotateCommon = `
info() { echo "[INFO] $*"; }
warn() { echo "[WARN] $*" >&2; }
die()  { echo "[ERROR] $*" >&2; exit 1; }

# ROTATE_TEST is fixed here, never read from the environment (this script runs
# as root, and the environment of an ssh session is not trusted): 0 on every
# host. The test suite turns the knobs below on by rewriting this one line in
# the copy of the script it runs; the production script never has a 1.
ROTATE_TEST=0
# The test suite points the fixed locations at a scratch directory.
LOGIN_DEFS="/etc/login.defs"
HOME_ROOT="/home"
HOME_OWNER=""
PASSWD_FILE="/etc/passwd"
ROOT_UID=0
SUDOERS_SCAN="/etc/sudoers /etc/sudoers.d/*"
USE_FLOCK=1
if [[ "$ROTATE_TEST" == "1" ]]; then
    LOGIN_DEFS="${TACCTL_ROTATE_LOGIN_DEFS:-/etc/login.defs}"
    HOME_ROOT="${TACCTL_ROTATE_HOME_ROOT:-/home}"
    HOME_OWNER="${TACCTL_ROTATE_HOME_OWNER:-}"
    PASSWD_FILE="${TACCTL_ROTATE_PASSWD:-/etc/passwd}"
    ROOT_UID="${TACCTL_ROTATE_ROOT_UID:-0}"
    STATE_DIR="${TACCTL_ROTATE_STATE:-$STATE_DIR}"
    SUDOERS_FILE="${TACCTL_ROTATE_SUDOERS:-$SUDOERS_FILE}"
    SUDOERS_SCAN="${TACCTL_ROTATE_SUDOERS_SCAN:-$SUDOERS_FILE}"
    if [[ "${TACCTL_ROTATE_NOFLOCK:-}" == "1" ]]; then USE_FLOCK=0; fi
elif [[ "$(id -u)" != "0" ]]; then
    die "This script must run as root. Nothing was changed."
fi
if ! command -v flock >/dev/null 2>&1; then USE_FLOCK=0; fi
trap 'exit 130' HUP INT TERM
trap 'exit 141' PIPE

# uid_forbidden <uid>: the number is in tacctl's range or one it used before.
uid_forbidden() {
    local r
    for r in $FORBIDDEN; do
        if (( $1 >= ${r%-*} && $1 <= ${r#*-} )); then return 0; fi
    done
    return 1
}

# locked <command...>: the command, with the lock on the sudoers file held
# (flock, or a lock directory where flock is missing), so that two scripts
# at once do not lose each other's line: the file is read, changed and
# renamed in one go.
LOCK_FILE="$(dirname "$SUDOERS_FILE")/.tacctl-provisioner.lock"
locked() {
    local rc=0 d="${LOCK_FILE}.d" i pid
    mkdir -p "$(dirname "$SUDOERS_FILE")" || return 1
    if [[ "$USE_FLOCK" == "1" ]]; then
        (
            flock -w 120 9 || { echo "[ERROR] Could not take the lock ${LOCK_FILE}: another script is changing the sudoers file." >&2; exit 98; }
            "$@"
        ) 9>"$LOCK_FILE" || rc=$?
        return "$rc"
    fi
    for ((i = 0; i < 240; i++)); do
        if mkdir "$d" 2>/dev/null; then echo "$$" > "$d/pid"; break; fi
        pid=$(cat "$d/pid" 2>/dev/null || true)
        if [[ -n "$pid" ]] && ! kill -0 "$pid" 2>/dev/null; then rm -rf "$d"; continue; fi
        sleep 0.5
    done
    if [[ "$(cat "$d/pid" 2>/dev/null || true)" != "$$" ]]; then
        echo "[ERROR] Could not take the lock ${d}: another script is changing the sudoers file." >&2
        return 1
    fi
    "$@" || rc=$?
    rm -rf "$d"
    return "$rc"
}

# sudoers_lines: the lines of the other accounts in SUDOERS_FILE.
sudoers_lines() {
    [[ -f "$SUDOERS_FILE" ]] || return 0
    { grep -vE '^[[:space:]]*(#|$)' "$SUDOERS_FILE" | grep -v "^${ACCOUNT}[[:space:]]"; } || true
}

# sudoers_own_line: the account's line in SUDOERS_FILE ("" when none).
sudoers_own_line() {
    [[ -f "$SUDOERS_FILE" ]] || return 0
    { grep -E "^${ACCOUNT}[[:space:]]" "$SUDOERS_FILE" | head -n 1; } || true
}

# sudoers_write_unlocked <line>: SUDOERS_FILE with the other accounts' lines
# and <line> (when not empty), checked by visudo before it replaces the file.
sudoers_write_unlocked() {
    local tmp dir
    dir=$(dirname "$SUDOERS_FILE")
    tmp=$(mktemp "$dir/.tacctl-provisioner.XXXXXX") || return 1
    {
        echo "# Managed by tacctl (tacctl host provisioner): provisioning accounts, one line each."
        sudoers_lines
        if [[ -n "$1" ]]; then echo "$1"; fi
    } > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 0440 "$tmp" || { rm -f "$tmp"; return 1; }
    if ! visudo -cf "$tmp" >/dev/null; then
        rm -f "$tmp"
        return 1
    fi
    if [[ "$ROTATE_TEST" != "1" ]]; then chown root:root "$tmp" || { rm -f "$tmp"; return 1; }; fi
    mv -f "$tmp" "$SUDOERS_FILE" || { rm -f "$tmp"; return 1; }
}

# sudoers_drop_unlocked: the account's line goes; the file too when it holds no other.
sudoers_drop_unlocked() {
    [[ -f "$SUDOERS_FILE" ]] || return 0
    if [[ -z "$(sudoers_lines)" ]]; then
        rm -f "$SUDOERS_FILE"
    else
        sudoers_write_unlocked ""
    fi
}

sudoers_write() { locked sudoers_write_unlocked "$1"; }
sudoers_drop()  { locked sudoers_drop_unlocked; }

# Root's record of the accounts this script made: STATE_DIR/<account>, in a
# directory of root's alone, with the lines account=, uid= and ssh_dir=
# (1: ~/.ssh was made by this script). It is what an adoption trusts.
# Nothing in the account's own reach (its comment field, its home) is
# trusted, and the file is read as text, never run.

# state_get <key>: the value in the account's record ("" when none).
state_get() { sed -n "s/^$1=//p" "$STATE_DIR/$ACCOUNT" 2>/dev/null | head -n 1; }

# state_valid <uid>: the record is root's, in root's directory, and names
# this account and this UID.
state_valid() {
    local f="$STATE_DIR/$ACCOUNT"
    [[ -d "$STATE_DIR" && ! -L "$STATE_DIR" && -f "$f" && ! -L "$f" ]] || return 1
    [[ "$(stat -c %u "$STATE_DIR")" == "$ROOT_UID" && "$(stat -c %u "$f")" == "$ROOT_UID" ]] || return 1
    (( ( 8#$(stat -c %a "$STATE_DIR") & 077 ) == 0 && ( 8#$(stat -c %a "$f") & 022 ) == 0 )) || return 1
    [[ "$(state_get account)" == "$ACCOUNT" && "$(state_get uid)" == "$1" ]]
}

# state_write <uid> <ssh_dir>: the record, through a temporary file.
state_write() {
    local tmp
    if [[ -L "$STATE_DIR" || ( -e "$STATE_DIR" && ! -d "$STATE_DIR" ) ]]; then return 1; fi
    if [[ ! -d "$STATE_DIR" ]]; then mkdir -m 0700 "$STATE_DIR" 2>/dev/null || [[ -d "$STATE_DIR" ]] || return 1; fi
    [[ "$(stat -c %u "$STATE_DIR")" == "$ROOT_UID" ]] || return 1
    chmod 0700 "$STATE_DIR" || return 1
    tmp=$(mktemp "$STATE_DIR/.record.XXXXXX") || return 1
    { printf 'account=%s\nuid=%s\nssh_dir=%s\n' "$ACCOUNT" "$1" "$2" > "$tmp" && chmod 0600 "$tmp" && mv -f "$tmp" "$STATE_DIR/$ACCOUNT"; } || { rm -f "$tmp"; return 1; }
}

# state_forget: the record goes (and the directory with the last one).
state_forget() {
    rm -f "$STATE_DIR/$ACCOUNT"
    rmdir "$STATE_DIR" 2>/dev/null || true
}
`

// rotateCreateBody is the create script after the header and rotateCommon.
const rotateCreateBody = `
for c in useradd usermod getent visudo sudo install stat find mktemp; do
    command -v "$c" >/dev/null 2>&1 || die "'$c' is not installed on this host. Nothing was changed."
done
if [[ "$AUTH" == "password" ]]; then
    command -v passwd >/dev/null 2>&1 || die "'passwd' is not installed on this host. Nothing was changed."
    if [[ ! -t 0 && ! ( "$ROTATE_TEST" == "1" && "${TACCTL_ROTATE_TEST_TTY:-}" == "1" ) ]]; then
        die "Setting the password needs a terminal. Nothing was changed."
    fi
fi
if ! grep -qsE '^[#@]includedir[[:space:]]+/etc/sudoers.d' /etc/sudoers 2>/dev/null && [[ "$ROTATE_TEST" != "1" ]]; then
    warn "/etc/sudoers does not include /etc/sudoers.d; the new account may get no sudo."
fi

# The steps are undone when one fails, in the reverse order: the sudoers
# line (the last step) if this run wrote it, and the account if this run
# made it. An adopted account stays; its ~/.ssh was emptied and is not
# brought back.
CREATED_NOW=0
SUDOERS_TOUCHED=0
ORIGIN=""
PREV_LINE=""
rollback() {
    local rc=$?
    trap - EXIT
    if [[ "$SUDOERS_TOUCHED" == "1" && "$CREATED_NOW" != "1" ]]; then
        warn "Taking the sudoers line of '${ACCOUNT}' this run wrote back out."
        if [[ -n "$PREV_LINE" ]]; then
            sudoers_write "$PREV_LINE" 2>/dev/null || warn "The line could not be restored; check ${SUDOERS_FILE}."
        else
            sudoers_drop 2>/dev/null || warn "The line could not be taken out; check ${SUDOERS_FILE}."
        fi
    fi
    if [[ "$CREATED_NOW" == "1" ]]; then
        warn "Removing the account '${ACCOUNT}' this run created."
        sudoers_drop 2>/dev/null || true
        userdel -r "$ACCOUNT" >/dev/null 2>&1 || userdel "$ACCOUNT" >/dev/null 2>&1 || true
        if getent group "$ACCOUNT" >/dev/null 2>&1; then groupdel "$ACCOUNT" >/dev/null 2>&1 || true; fi
        if getent passwd "$ACCOUNT" >/dev/null 2>&1; then
            warn "The account '${ACCOUNT}' could not be removed; remove it by hand: userdel -r ${ACCOUNT}"
        else
            state_forget
        fi
    fi
    exit "$rc"
}
trap rollback EXIT

# useradd_failed: useradd gave up; whatever it left of the account is ours
# to remove (the lock of the command on the tacctl server keeps a second
# run from this account out).
useradd_failed() {
    if getent passwd "$ACCOUNT" >/dev/null 2>&1; then
        CREATED_NOW=1
        die "useradd failed after creating '${ACCOUNT}'; what it made is being removed."
    fi
}

existing=$(getent passwd "$ACCOUNT" || true)
if [[ -n "$existing" ]]; then
    uid=$(cut -d: -f3 <<< "$existing")
    # Only an account this tool made is adopted, and root's record says so:
    # the comment field is the account's own, and a directory service's
    # accounts are not in the local file at all.
    if ! grep -q "^${ACCOUNT}:" "$PASSWD_FILE" 2>/dev/null; then
        die "An account named '${ACCOUNT}' exists on this host and is not a tacctl provisioning account: it is not in ${PASSWD_FILE} (it comes from a directory service). Nothing was changed."
    fi
    if ! state_valid "$uid"; then
        die "An account named '${ACCOUNT}' exists on this host and is not a tacctl provisioning account (tacctl has no root-owned record of creating it in ${STATE_DIR}). Nothing was changed."
    fi
    if uid_forbidden "$uid"; then
        die "The account '${ACCOUNT}' has UID ${uid}, inside tacctl's UID range or one it used before ($FORBIDDEN). Nothing was changed."
    fi
    ORIGIN=adopted
    info "Adopting the existing provisioning account '${ACCOUNT}' (UID ${uid})."
else
    if getent group "$ACCOUNT" >/dev/null 2>&1; then
        die "A group named '${ACCOUNT}' exists on this host. Nothing was changed."
    fi
    base=$(useradd -D 2>/dev/null | sed -n 's/^HOME=//p')
    base="${base:-/home}"
    if [[ "$ROTATE_TEST" == "1" ]]; then base="$HOME_ROOT"; fi
    if [[ -e "$base/$ACCOUNT" || -L "$base/$ACCOUNT" ]]; then
        die "${base}/${ACCOUNT} exists already. Nothing was changed."
    fi
    uid_min=$(awk '$1 == "UID_MIN" { v = $2 } END { print v }' "$LOGIN_DEFS" 2>/dev/null || true)
    [[ "$uid_min" =~ ^[0-9]+$ ]] || uid_min=1000
    cap=$((UID_FIRST - 1))
    # The numbers below tacctl's range that no earlier range covers, highest first.
    list="${uid_min}-${cap}"
    for r in $FORBIDDEN; do
        flo=${r%-*}; fhi=${r#*-}; next=""
        for i in $list; do
            lo=${i%-*}; hi=${i#*-}
            if (( fhi < lo || flo > hi )); then next="$next $i"; continue; fi
            if (( flo > lo )); then next="$next ${lo}-$((flo - 1))"; fi
            if (( fhi < hi )); then next="$next $((fhi + 1))-${hi}"; fi
        done
        list=$next
    done
    made=0
    for i in $(for j in $list; do if (( ${j%-*} <= ${j#*-} )); then echo "${j#*-} ${j%-*}"; fi; done | sort -rn | while read -r hi lo; do echo "${lo}-${hi}"; done); do
        lo=${i%-*}; hi=${i#*-}
        # The group's number is kept out of tacctl's range as well.
        args=(-K "UID_MAX=${hi}" -K "GID_MAX=${hi}")
        if (( lo != uid_min )); then args+=(-K "UID_MIN=${lo}" -K "GID_MIN=${lo}"); fi
        if useradd -m -U -s /bin/bash -c "$MARKER" "${args[@]}" "$ACCOUNT"; then made=1; break; fi
        useradd_failed
    done
    if [[ "$made" != "1" ]]; then
        info "No free number below tacctl's range; creating a system account."
        useradd -r -m -U -s /bin/bash -c "$MARKER" "$ACCOUNT" || { useradd_failed; die "Could not create the account '${ACCOUNT}' (useradd failed). Nothing was changed."; }
    fi
    CREATED_NOW=1
    ORIGIN=created
    uid=$(getent passwd "$ACCOUNT" | cut -d: -f3)
    # Root's record, at once: it is what lets a re-run adopt the account.
    state_write "$uid" 0 || die "Could not write the record of '${ACCOUNT}' in ${STATE_DIR}; the account was removed."
    if uid_forbidden "$uid"; then
        die "useradd gave '${ACCOUNT}' UID ${uid}, inside tacctl's UID range or one it used before ($FORBIDDEN); the account was removed."
    fi
    gid=$(getent passwd "$ACCOUNT" | cut -d: -f4)
    if uid_forbidden "$gid"; then
        die "useradd gave the group of '${ACCOUNT}' GID ${gid}, inside tacctl's UID range or one it used before ($FORBIDDEN); the account was removed."
    fi
    info "Created the account '${ACCOUNT}' (UID ${uid})."
fi
info "origin: ${ORIGIN}"

home=$(getent passwd "$ACCOUNT" | cut -d: -f6)
group=$(id -gn "$ACCOUNT")
if [[ -z "$home" || "$home" == "/" ]]; then die "The account '${ACCOUNT}' has no home directory."; fi
if [[ -L "$home" ]]; then die "The home of '${ACCOUNT}' is a symbolic link."; fi
if [[ ! -d "$home" ]]; then install -d -m 0700 -o "$ACCOUNT" -g "$group" "$home"; fi
chmod 0700 "$home"

# as_account <sh script> <args...>: the script, run by /bin/sh as the account
# itself, with this script's standard input. Whatever is written in the
# account's home is written with the account's rights, so a link the
# account plants there cannot take root's write anywhere else.
as_account() {
    local s="$1"
    shift
    if command -v runuser >/dev/null 2>&1; then
        runuser -u "$ACCOUNT" -- /bin/sh -c "$s" sh "$@"
    else
        sudo -n -u "$ACCOUNT" -- /bin/sh -c "$s" sh "$@"
    fi
}

SSH_SNIPPET='set -e
umask 077
cd "$1"
if [ -L .ssh ]; then echo ".ssh is a symbolic link" >&2; exit 32; fi
if [ -e .ssh ] && [ ! -d .ssh ]; then echo ".ssh is not a directory" >&2; exit 32; fi
if [ ! -e .ssh ]; then
    if [ "$2" != key ]; then exit 0; fi
    mkdir -m 0700 .ssh
fi
chmod 0700 .ssh
find .ssh -mindepth 1 -maxdepth 1 -exec rm -rf -- {} +
if [ "$2" = key ]; then
    t=$(mktemp .ssh/.authorized_keys.XXXXXX)
    cat > "$t"
    chmod 0600 "$t"
    mv -f "$t" .ssh/authorized_keys
fi'

# prepare_ssh <key|none>: ~/.ssh of the account is emptied (what an earlier
# user of an adopted account left there: rc, authorized_keys2, ...) and,
# for key, given the one authorized_keys. It is refused when ~/.ssh is a
# link, belongs to somebody else or is writable by group or others, and,
# for an adopted account, when ~/.ssh was not made by this script.
prepare_ssh() {
    local what="$1" st owner perm
    if [[ -L "$home/.ssh" ]]; then die "${home}/.ssh is a symbolic link; refusing to use it."; fi
    if [[ -e "$home/.ssh" ]]; then
        [[ -d "$home/.ssh" ]] || die "${home}/.ssh is not a directory."
        st=$(stat -c '%u %a' "$home/.ssh")
        owner=${st% *}; perm=${st#* }
        if [[ "$owner" != "${HOME_OWNER:-$uid}" ]]; then die "${home}/.ssh belongs to UID ${owner}, not to '${ACCOUNT}'; refusing to use it."; fi
        if (( ( 8#$perm & 022 ) != 0 )); then die "${home}/.ssh is writable by its group or others (mode ${perm}); refusing to use it."; fi
        if [[ "$ORIGIN" == "adopted" && "$(state_get ssh_dir)" != "1" ]]; then
            die "${home}/.ssh of the adopted account '${ACCOUNT}' was not made by tacctl; refusing to use it. Remove the account by hand (userdel -r ${ACCOUNT}) and run the command again."
        fi
    fi
    if [[ "$what" == "key" ]]; then
        printf '%s\n' "$PUBKEY" | as_account "$SSH_SNIPPET" "$home" key || die "Could not write ${home}/.ssh/authorized_keys as '${ACCOUNT}'."
        if [[ ! -f "$home/.ssh/authorized_keys" || -L "$home/.ssh/authorized_keys" || -L "$home/.ssh" ]]; then
            die "${home}/.ssh/authorized_keys is not what was written."
        fi
        state_write "$uid" 1 || die "Could not write the record of '${ACCOUNT}' in ${STATE_DIR}."
        if command -v selinuxenabled >/dev/null 2>&1 && selinuxenabled 2>/dev/null && command -v restorecon >/dev/null 2>&1; then
            restorecon -R "$home/.ssh" || true
        fi
    elif [[ -e "$home/.ssh" ]]; then
        as_account "$SSH_SNIPPET" "$home" none </dev/null || die "Could not empty ${home}/.ssh as '${ACCOUNT}'."
    fi
}

# Every step before the last is done first; the sudoers line comes last.
if [[ "$AUTH" == "key" ]]; then
    usermod -p '!' "$ACCOUNT" || die "Could not lock the password of '${ACCOUNT}' (usermod failed)."
    prepare_ssh key
    info "The public key is in ${home}/.ssh/authorized_keys; the password is locked."
else
    prepare_ssh none
    info "Set the password of '${ACCOUNT}' now. It is typed into this host's own passwd and never reaches tacctl."
    passwd "$ACCOUNT" || die "passwd failed; no password was set."
    pw=$(getent shadow "$ACCOUNT" | cut -d: -f2)
    case "$pw" in
        ""|"!"*|"*"*) die "No password was set for '${ACCOUNT}'." ;;
    esac
fi

PREV_LINE=$(sudoers_own_line)
if [[ "$PREV_LINE" == "$SUDOERS_LINE" ]]; then
    info "sudoers-line: unchanged"
else
    SUDOERS_TOUCHED=1
    if ! sudoers_write "$SUDOERS_LINE"; then
        SUDOERS_TOUCHED=0
        die "visudo rejected the sudoers line for '${ACCOUNT}'."
    fi
    if [[ -n "$PREV_LINE" ]]; then info "sudoers-line: changed"; else info "sudoers-line: added"; fi
fi
info "Sudoers: ${SUDOERS_FILE} holds: ${SUDOERS_LINE}"
if [[ "$ROTATE_TEST" == "1" && "${TACCTL_ROTATE_FAIL_AFTER_SUDOERS:-}" == "1" ]]; then
    die "The test asked for a failure after the sudoers line."
fi

CREATED_NOW=0
SUDOERS_TOUCHED=0
info "Provisioning account '${ACCOUNT}' is ready (${AUTH} login)."
`

// rotateRemoveBody is the remove script after the header and rotateCommon.
const rotateRemoveBody = `
for c in userdel getent visudo stat; do
    command -v "$c" >/dev/null 2>&1 || die "'$c' is not installed on this host."
done

# home_refusal <name> <uid> <home>: why the home directory must stay ("" when
# it may go): it must be a real directory directly under /home (no symbolic
# link on the way), owned by the account, and no other account's home.
home_refusal() {
    local name="$1" uid="$2" home="$3" other
    if [[ "$home" != "${HOME_ROOT}/"* || "${home#"${HOME_ROOT}"/}" == */* || "${home#"${HOME_ROOT}"/}" == "" || "${home#"${HOME_ROOT}"/}" == .* ]]; then
        echo "not a directory directly under ${HOME_ROOT}"; return 0
    fi
    if [[ -L "$HOME_ROOT" ]]; then echo "${HOME_ROOT} is a symbolic link"; return 0; fi
    if [[ -L "$home" ]]; then echo "it is a symbolic link"; return 0; fi
    if [[ ! -d "$home" ]]; then echo "not a directory"; return 0; fi
    other=$(getent passwd | awk -F: -v n="$name" -v h="$home" '$1 != n && ($6 == h || index($6, h "/") == 1) { print $1; exit }')
    if [[ -n "$other" ]]; then echo "also the home of '${other}'"; return 0; fi
    if [[ "$(stat -c %u "$home")" != "${HOME_OWNER:-$uid}" ]]; then echo "owned by UID $(stat -c %u "$home"), not ${uid}"; return 0; fi
    return 0
}

# Kept homes of removed accounts are moved here, out of reach of a local
# account that is later given the same UID: root's alone, the tree owned by
# root.
REMOVED_DIR="${HOME_ROOT}/.tacctl-removed"

# keep_home <name> <home>: the home moves to REMOVED_DIR/<name>-<YYYYmmdd-HHMMSS>,
# owned by root:root (links changed, never followed), its top 0700. It stays
# where it is (and says why) when REMOVED_DIR is not a real directory of
# root's, the home is on another file system than ${HOME_ROOT}, or the name
# is taken.
keep_home() {
    local name="$1" home="$2" dest
    dest="${REMOVED_DIR}/${name}-$(date +%Y%m%d-%H%M%S)"
    if [[ -L "$REMOVED_DIR" || ( -e "$REMOVED_DIR" && ! -d "$REMOVED_DIR" ) ]]; then
        warn "home kept in place: ${home} (${REMOVED_DIR} is not a real directory); move it out of reach of new accounts by hand."
        return 0
    fi
    if [[ "$(stat -c %d "$home")" != "$(stat -c %d "$HOME_ROOT")" ]]; then
        warn "home kept in place: ${home} (a separate file system); make it root's by hand: chown -hR root:root ${home}"
        return 0
    fi
    if [[ -e "$dest" || -L "$dest" ]]; then
        warn "home kept in place: ${home} (${dest} exists)."
        return 0
    fi
    if ! { { [[ -d "$REMOVED_DIR" ]] || mkdir -m 0700 "$REMOVED_DIR"; } && chown root:root "$REMOVED_DIR" && chmod 0700 "$REMOVED_DIR"; }; then
        warn "home kept in place: ${home} (${REMOVED_DIR} could not be prepared)."
        return 0
    fi
    if ! mv -T -- "$home" "$dest"; then
        warn "home kept in place: ${home} (it could not be moved to ${REMOVED_DIR})."
        return 0
    fi
    if ! { chown -hR root:root -- "$dest" && chmod 0700 "$dest"; }; then
        warn "home kept: ${dest}, but it could not all be made root's; check it: chown -hR root:root ${dest}"
        return 0
    fi
    info "home kept: ${dest}"
}

existing=$(getent passwd "$ACCOUNT" || true)

# Only the grant: an adopted account whose proof failed stays, without sudo.
if [[ "$SUDOERS_ONLY" == "1" ]]; then
    sudoers_drop || die "The sudoers line of '${ACCOUNT}' could not be taken out of ${SUDOERS_FILE}."
    info "Took the sudoers line of '${ACCOUNT}' out of ${SUDOERS_FILE}; the account itself was left."
    exit 0
fi

if [[ -z "$existing" ]]; then
    sudoers_drop
    state_forget
    info "There is no account '${ACCOUNT}' on this host; nothing to remove there."
    exit 0
fi
uid=$(cut -d: -f3 <<< "$existing")
pgid=$(cut -d: -f4 <<< "$existing")
home=$(cut -d: -f6 <<< "$existing")
if [[ "$ACCOUNT" == "root" || "$uid" == "0" ]]; then
    die "Refusing to remove '${ACCOUNT}' (UID ${uid}). Nothing was changed."
fi
if uid_forbidden "$uid"; then
    die "The account '${ACCOUNT}' has UID ${uid}, inside tacctl's UID range or one it used before: it belongs to 'host sync'. Nothing was changed."
fi
if [[ "${SUDO_USER:-}" == "$ACCOUNT" ]]; then
    die "This session is logged in as '${ACCOUNT}'. Nothing was changed."
fi

# Grants other than the provisioning line stay, and are said.
for g in sudo wheel admin; do
    case " $(id -nG "$ACCOUNT" 2>/dev/null || true) " in
        *" $g "*) warn "'${ACCOUNT}' was in the group '${g}' (it leaves with the account)." ;;
    esac
done
# shellcheck disable=SC2086
others=$({ grep -lE "^${ACCOUNT}[[:space:]]" $SUDOERS_SCAN 2>/dev/null | grep -vxF "$SUDOERS_FILE"; } || true)
if [[ -n "$others" ]]; then
    warn "These sudoers files name '${ACCOUNT}' and were left as they are: ${others//$'\n'/ }"
fi

refusal=""
if [[ -e "$home" || -L "$home" ]] && [[ -n "$home" && "$home" != "/" ]]; then
    refusal=$(home_refusal "$ACCOUNT" "$uid" "$home")
fi

# The grant goes first: if userdel cannot run, the account is at least
# without sudo (and expired, below).
sudoers_drop || die "The sudoers line of '${ACCOUNT}' could not be taken out of ${SUDOERS_FILE}; nothing else was changed."
usermod -e 1 "$ACCOUNT" || true
if command -v pkill >/dev/null 2>&1; then
    pkill -TERM -u "$ACCOUNT" || true
    sleep 1
    pkill -KILL -u "$ACCOUNT" || true
fi
if ! userdel "$ACCOUNT"; then
    die "Could not delete '${ACCOUNT}' (userdel failed; still logged in?). Its sudoers line is gone and the account is expired; remove it by hand: userdel ${ACCOUNT}"
fi
group=$(getent group "$ACCOUNT" || true)
if [[ -n "$group" ]]; then
    gid=$(cut -d: -f3 <<< "$group"); members=$(cut -d: -f4 <<< "$group")
    if [[ "$gid" == "$uid" || "$gid" == "$pgid" ]] && [[ -z "$members" && -z "$(getent passwd | awk -F: -v g="$gid" '$4 == g { print $1; exit }')" ]]; then
        groupdel "$ACCOUNT" || true
    fi
fi
state_forget
info "Deleted the account '${ACCOUNT}' (UID ${uid})."

if [[ -z "$home" || "$home" == "/" ]]; then exit 0; fi
if [[ "$REMOVE_HOME" == "1" && -z "$refusal" && -d "$home" ]]; then
    rm -rf --one-file-system -- "$home"
    info "Deleted home ${home}."
elif [[ -n "$refusal" ]]; then
    warn "home kept in place: ${home} (${refusal})"
elif [[ -e "$home" || -L "$home" ]]; then
    keep_home "$ACCOUNT" "$home"
fi
`
