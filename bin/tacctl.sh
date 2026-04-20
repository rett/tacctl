#!/usr/bin/env bash
#
# Tacquito TACACS+ Server — Management Script
#
# Manage local TACACS+ users and server configuration.
# Changes are applied to /etc/tacquito/tacquito.yaml and hot-reloaded automatically.
#
# Usage:
#   ./tacctl.sh user list
#   ./tacctl.sh user add <username> <group> [--scopes <name>[,<name>...]]
#   ./tacctl.sh user remove <username>
#   ./tacctl.sh user passwd <username>
#   ./tacctl.sh user disable <username>
#   ./tacctl.sh user enable <username>
#   ./tacctl.sh user verify <username>
#   ./tacctl.sh user scopes <username> {list|add|remove|set|clear}
#   ./tacctl.sh scopes {list|show|add|remove|rename|default}
#   ./tacctl.sh scopes prefixes <name> {list|add|remove|clear}
#   ./tacctl.sh scopes secret   <name> {show|set|generate}
#   ./tacctl.sh config show
#   ./tacctl.sh config cisco   [--scope <name>]
#   ./tacctl.sh config juniper [--scope <name>]
#
set -euo pipefail
if [[ $EUID -ne 0 && "${1:-}" != "hash" ]]; then
    exec sudo "$0" "$@"
fi
umask 077

CONFIG="/etc/tacquito/tacquito.yaml"
BACKUP_DIR="/etc/tacquito/backups"
PASSWORD_DATES_DIR="/etc/tacquito/backups/password-dates"
ACCT_LOG="/var/log/tacquito/accounting.log"
PASSWORD_MAX_AGE_DAYS=90
PASSWORD_MAX_AGE_FILE="/etc/tacquito/password-max-age"
BCRYPT_COST=12
BCRYPT_COST_FILE="/etc/tacquito/bcrypt-cost"
PASSWORD_MIN_LENGTH=12
PASSWORD_MIN_LENGTH_FILE="/etc/tacquito/password-min-length"
SECRET_MIN_LENGTH=16
SECRET_MIN_LENGTH_FILE="/etc/tacquito/secret-min-length"
MGMT_ACL_FILE="/etc/tacquito/mgmt-acl.conf"
MGMT_ACL_NAMES_FILE="/etc/tacquito/mgmt-acl-names.conf"
CISCO_ACL_NAME_DEFAULT="VTY-ACL"
JUNIPER_ACL_NAME_DEFAULT="MGMT-SSH-ACL"
PRIVILEGE_FILE="/etc/tacquito/cisco-privileges.conf"
DEFAULT_SCOPE_FILE="/etc/tacquito/default-scope"
DEFAULT_SCOPE_FRESH="lab"  # name used on fresh installs; upgrades keep existing scope name
CONFIG_DIR="/etc/tacquito"
LOG_DIR="/var/log/tacquito"
SERVICE_FILE="/etc/systemd/system/tacquito.service"

# --- System lifecycle constants ---
GO_VERSION="1.26.2"
TACQUITO_REPO="https://github.com/facebookincubator/tacquito.git"
TACQUITO_SRC="/opt/tacquito-src"
TACQUITO_BIN="/usr/local/bin/tacquito"
HASHGEN_BIN="/usr/local/bin/tacquito-hashgen"
DEPLOY_DIR="/opt/tacctl"
MANAGE_REPO="https://github.com/rett/tacctl.git"
GO_BIN="/usr/local/go/bin/go"

# Load custom password max age if set and readable. -r (not -f) so non-root
# commands like `tacctl hash` don't fail when invoked by a user who can't
# read the file; they just keep the default.
if [[ -r "$PASSWORD_MAX_AGE_FILE" ]]; then
    PASSWORD_MAX_AGE_DAYS=$(cat "$PASSWORD_MAX_AGE_FILE" 2>/dev/null || echo "$PASSWORD_MAX_AGE_DAYS")
fi

# Load custom bcrypt cost. Default 12 follows OWASP 2025 guidance (≈300ms
# on modern CPUs). Existing hashes at lower cost continue to verify —
# bcrypt encodes cost in the hash itself. Clamp to the safe range [10,14]
# to avoid accidental DoS or downgrade.
if [[ -r "$BCRYPT_COST_FILE" ]]; then
    BCRYPT_COST=$(cat "$BCRYPT_COST_FILE" 2>/dev/null || echo "$BCRYPT_COST")
fi
if ! [[ "$BCRYPT_COST" =~ ^[0-9]+$ ]] || [[ "$BCRYPT_COST" -lt 10 || "$BCRYPT_COST" -gt 14 ]]; then
    BCRYPT_COST=12
fi

# Load custom password minimum length. Default 12 follows OWASP 2025
# guidance. Clamp to [8, 64]: 8 is the NIST 800-63 floor, 64 is the
# practical ceiling for memorable input.
if [[ -r "$PASSWORD_MIN_LENGTH_FILE" ]]; then
    PASSWORD_MIN_LENGTH=$(cat "$PASSWORD_MIN_LENGTH_FILE" 2>/dev/null || echo "$PASSWORD_MIN_LENGTH")
fi
if ! [[ "$PASSWORD_MIN_LENGTH" =~ ^[0-9]+$ ]] || [[ "$PASSWORD_MIN_LENGTH" -lt 8 || "$PASSWORD_MIN_LENGTH" -gt 64 ]]; then
    PASSWORD_MIN_LENGTH=12
fi

# Load custom shared-secret minimum length. Default 16 follows Cisco's
# TACACS+ best-practice guidance. Clamp to [16, 128]: shorter than 16
# would silently downgrade Cisco's recommendation, longer than 128 is
# impractical and risks shell-quoting issues on devices.
if [[ -r "$SECRET_MIN_LENGTH_FILE" ]]; then
    SECRET_MIN_LENGTH=$(cat "$SECRET_MIN_LENGTH_FILE" 2>/dev/null || echo "$SECRET_MIN_LENGTH")
fi
if ! [[ "$SECRET_MIN_LENGTH" =~ ^[0-9]+$ ]] || [[ "$SECRET_MIN_LENGTH" -lt 16 || "$SECRET_MIN_LENGTH" -gt 128 ]]; then
    SECRET_MIN_LENGTH=16
fi

# --- Disabled-user hash marker ---
# For disabled users we write a well-formed but unverifiable bcrypt hash
# rather than the legacy literal "DISABLED". The marker is '$2b$12$' +
# 53 '.' chars (all-zero salt + all-zero digest) — valid bcrypt
# structure that no real password can match. Stored hex-encoded.
#
# Legacy "DISABLED" values are still recognized on read (see is_disabled_hash).
# Hex of "$2b$12$" + "." × 53:
DISABLED_MARKER_HEX="24326224313224"
DISABLED_MARKER_HEX+="2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"
DISABLED_MARKER_HEX+="2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e"

# Return 0 if $1 is a disabled-user hash (legacy or new marker).
is_disabled_hash() {
    [[ "$1" == "DISABLED" || "$1" == "$DISABLED_MARKER_HEX" ]]
}

# --- Validate a regex pattern ---
# Used to gate user-supplied --match values for command rules.
validate_regex() {
    local pattern="$1"
    if ! python3 -c "import re,sys; re.compile(sys.argv[1])" "$pattern" 2>/dev/null; then
        error "Invalid regex: '${pattern}'"
        exit 1
    fi
}

# --- Validate a Cisco privilege-exec command string ---
# Cisco command paths can contain spaces ("show running-config",
# "terminal monitor"). Allow letters, digits, spaces, '-', '_'. Reject
# leading/trailing whitespace, control chars, and shell metacharacters
# that could break the emitted device config.
validate_priv_command_string() {
    local cmd="$1"
    if [[ -z "$cmd" ]]; then
        error "Privilege command must not be empty."
        exit 1
    fi
    if [[ "$cmd" =~ ^[[:space:]] || "$cmd" =~ [[:space:]]$ ]]; then
        error "Privilege command has leading/trailing whitespace: '${cmd}'"
        exit 1
    fi
    if [[ ! "$cmd" =~ ^[a-zA-Z][a-zA-Z0-9\ _-]+$ ]]; then
        error "Invalid privilege command '${cmd}'."
        error "Use letters, digits, spaces, '-', '_' (e.g. 'show running-config', 'terminal monitor')."
        exit 1
    fi
    if [[ ${#cmd} -gt 64 ]]; then
        error "Privilege command too long (${#cmd} chars; max 64)."
        exit 1
    fi
}

# --- Read all `<group>|<cmd>` mappings ---
# Strips comments and blanks. Missing file yields no output.
read_all_privileges() {
    [[ -r "$PRIVILEGE_FILE" ]] || return 0
    awk '
        { sub(/#.*/, "") }
        { gsub(/^[[:space:]]+|[[:space:]]+$/, "") }
        NF { print }
    ' "$PRIVILEGE_FILE"
}

# --- Read the priv-exec command list for one group ---
# Emits one cmd per line. Empty output = group has no explicit mappings
# (caller decides whether to fall back to a default set or emit nothing).
read_group_privileges() {
    local group="$1"
    read_all_privileges | awk -F'|' -v g="$group" '$1 == g { print substr($0, length(g) + 2) }'
}

# --- Default priv-exec command set per built-in group ---
# Conservative: only the move-DOWN cases (priv-15 commands moved to a
# lower level so operator-class users can run them). Move-UP cases
# (e.g. ping at default priv 1 → priv 7) are deliberately omitted —
# they would silently restrict commands from lower-priv groups.
default_privileges_for_group() {
    local group="$1"
    case "$group" in
        readonly)
            # Priv 1 is the floor; nothing legitimately moves into it.
            echo ""
            ;;
        operator)
            # Move show-config family DOWN from priv 15 to priv 7 so
            # operators can read state without superuser rights.
            printf '%s\n' \
                "show running-config" \
                "show startup-config"
            ;;
        superuser)
            # Priv 15 is the ceiling; all commands available by default.
            echo ""
            ;;
        *)
            echo ""
            ;;
    esac
}

# --- Append/replace a group's full priv-exec list ---
# new_list is a newline-separated set of command strings (or empty to
# wipe the group). Atomic replacement of just the lines for $group.
write_group_privileges() {
    local group="$1"
    local new_list="$2"
    mkdir -p "$(dirname "$PRIVILEGE_FILE")"
    local tmp
    tmp=$(mktemp)
    # 1. Carry forward header + every line that is NOT for this group.
    if [[ -f "$PRIVILEGE_FILE" ]]; then
        awk -F'|' -v g="$group" '
            /^[[:space:]]*#/ { print; next }
            /^[[:space:]]*$/ { print; next }
            $1 == g { next }
            { print }
        ' "$PRIVILEGE_FILE" > "$tmp"
    else
        {
            echo "# tacctl-managed Cisco priv-exec command mappings."
            echo "# Format: <group>|<command>   (one mapping per line)"
            echo "# Edit via: tacctl group privilege <list|add|remove|clear|seed>"
        } > "$tmp"
    fi
    # 2. Append the new lines (if any) for this group. `local line` so we
    # don't clobber a caller's `cmd`, etc.
    if [[ -n "$new_list" ]]; then
        local line
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            echo "${group}|${line}" >> "$tmp"
        done <<< "$new_list"
    fi
    mv "$tmp" "$PRIVILEGE_FILE"
    chmod 644 "$PRIVILEGE_FILE"
}

# --- Validate a TACACS+ command name (the cmd= value sent by the device) ---
# Allow * (wildcard / catchall) plus typical Cisco / Junos verb tokens.
validate_command_name() {
    local name="$1"
    if [[ "$name" == "*" ]]; then
        return 0
    fi
    if [[ ! "$name" =~ ^[A-Za-z][A-Za-z0-9_-]{0,31}$ ]]; then
        error "Invalid command name '${name}'."
        error "Use a literal cmd token (e.g. 'show', 'configure') or '*' for the catchall."
        exit 1
    fi
}

# --- Read a group's command rules from the YAML ---
# Emits one rule per line as `name|action|match1,match2,...`. A trailing
# `*` catchall (always present when commands: exists) is included.
# Empty output = group has no commands: block (= unrestricted).
read_group_commands() {
    local group="$1"
    python3 - "$CONFIG" "$group" <<'PY' 2>/dev/null
import re, sys
cfg = open(sys.argv[1]).read()
group = sys.argv[2]
# Bound the group block: from "<group>: &<group>\n" to the next blank
# line or the next top-level YAML key.
m = re.search(
    r'^' + re.escape(group) + r': &' + re.escape(group) + r'\n((?:[ \t].*\n)+)',
    cfg, re.MULTILINE,
)
if not m:
    sys.exit(0)
body = m.group(1)
# Find the commands: block (indented under the group).
cm = re.search(r'^  commands:\n((?:    -.*\n(?:      .*\n)*)+)', body, re.MULTILINE)
if not cm:
    sys.exit(0)
rules_text = cm.group(1)
# Split into per-rule chunks. Each rule starts with "    - name:" .
chunks = re.findall(
    r'    - name:\s*(?P<name>"[^"]*"|\S+)\s*\n'
    r'(?:      match:\s*\[(?P<match>[^\]]*)\]\s*\n)?'
    r'      action:\s*\*action_(?P<action>permit|deny)\s*\n',
    rules_text,
)
for name, match, action in chunks:
    name = name.strip().strip('"')
    matches = []
    if match.strip():
        matches = [m.strip().strip('"') for m in re.findall(r'"([^"]+)"', match)]
    print(f"{name}|{action}|{','.join(matches)}")
PY
}

# --- Read a group's default action ---
# Encoded as the action of the trailing `name: "*"` rule. If there's no
# commands: block at all, the effective default is "permit" (= no
# restriction = current behavior).
read_group_default_action() {
    local group="$1"
    local last_rule
    last_rule=$(read_group_commands "$group" | tail -1)
    if [[ -z "$last_rule" ]]; then
        echo "permit"
        return
    fi
    local last_name="${last_rule%%|*}"
    if [[ "$last_name" == "*" ]]; then
        # action is the second |-separated field
        echo "$last_rule" | awk -F'|' '{print $2}'
    else
        # Group has rules but no catchall — shouldn't happen if writes
        # go through tacctl, but treat as "deny" since tacquito returns
        # FAIL on no-match.
        echo "deny"
    fi
}

# --- Return 0 if any group in the YAML has a commands: block ---
any_group_has_commands() {
    grep -q "^  commands:" "$CONFIG" 2>/dev/null
}

# --- List all group names defined in the YAML ---
list_all_groups() {
    python3 -c "
import re, sys
cfg = open(sys.argv[1]).read()
m = re.search(r'^# --- Groups ---\s*\n(.*?)(?=^# --- Users|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.exit(0)
for g in re.findall(r'^(\w+): &\1\n', m.group(1), re.MULTILINE):
    print(g)
" "$CONFIG"
}

# --- Get a group's Cisco priv-lvl ---
get_group_privlvl() {
    local group="$1"
    python3 -c "
import re, sys
cfg = open(sys.argv[1]).read()
group = sys.argv[2]
m = re.search(
    r'^' + re.escape(group) + r': &' + re.escape(group) + r'\n((?:[ \t].*\n)+)',
    cfg, re.MULTILINE,
)
if not m:
    sys.exit(0)
sm = re.search(r'\*exec_(\w+)', m.group(1))
if not sm:
    sys.exit(0)
svc = sm.group(1)
vm = re.search(r'exec_' + svc + r':.*?values:\s*\[(\d+)\]', cfg, re.DOTALL)
if vm:
    print(vm.group(1))
" "$CONFIG" "$group"
}

# --- Write/replace a group's commands: block ---
# rules_arg format: pipe-separated rules joined with newlines, each rule
# `name|action|match1,match2,...`. An empty rules_arg removes the
# commands: section entirely.
write_group_commands() {
    local group="$1"
    local rules_arg="$2"
    python3 - "$CONFIG" "$group" "$rules_arg" <<'PY'
import re, sys, tempfile, os
cfg_path, group, rules_arg = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = open(cfg_path).read()

def render_rules(text):
    if not text.strip():
        return ""
    out = ["  commands:\n"]
    for line in text.split("\n"):
        if not line.strip():
            continue
        parts = line.split("|", 2)
        name = parts[0]
        action = parts[1] if len(parts) > 1 else "permit"
        matches = parts[2].split(",") if len(parts) > 2 and parts[2] else []
        out.append(f'    - name: "{name}"\n')
        if matches:
            quoted = ", ".join(f'"{m}"' for m in matches if m)
            out.append(f"      match: [{quoted}]\n")
        out.append(f"      action: *action_{action}\n")
    return "".join(out)

new_block = render_rules(rules_arg)

# Locate group body. Match "<group>: &<group>\n" followed by indented
# lines until a non-indented line (or EOF).
gpat = re.compile(
    r'(^' + re.escape(group) + r': &' + re.escape(group) + r'\n)((?:[ \t].*\n)+)',
    re.MULTILINE,
)
gm = gpat.search(cfg)
if not gm:
    sys.stderr.write(f"group '{group}' not found\n")
    sys.exit(1)
header, body = gm.group(1), gm.group(2)

# Strip any existing commands: block (and its indented children).
body_no_cmd = re.sub(
    r'^  commands:\n(?:    -.*\n(?:      .*\n)*)+',
    "", body, flags=re.MULTILINE,
)

# Insert new commands: block just before the accounter line, or at end
# of body if no accounter.
if new_block:
    if re.search(r'^  accounter:', body_no_cmd, re.MULTILINE):
        new_body = re.sub(
            r'(^  accounter:.*\n)',
            new_block + r'\1', body_no_cmd, count=1, flags=re.MULTILINE,
        )
    else:
        new_body = body_no_cmd.rstrip("\n") + "\n" + new_block
else:
    new_body = body_no_cmd

cfg_new = cfg[:gm.start()] + header + new_body + cfg[gm.end():]
tmp = tempfile.NamedTemporaryFile("w", dir=os.path.dirname(cfg_path), delete=False)
tmp.write(cfg_new)
tmp.close()
os.rename(tmp.name, cfg_path)
PY
}

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${GREEN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# --- Version (resolved from the git repo that holds this script) ---
get_version() {
    local script_dir
    script_dir=$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")
    git -C "${script_dir}/.." describe --tags --always --dirty 2>/dev/null || echo "unknown"
}

# Normalize DEPLOY_DIR perms after git clone/pull. The script runs with
# umask 077 by default, so git creates files 0600 -- which blocks non-root
# users from reading README.md and templates. `a+rX` adds world read and
# directory traversal without granting exec on data files.
normalize_deploy_perms() {
    [[ -d "$DEPLOY_DIR" ]] || return 0
    chmod -R a+rX "$DEPLOY_DIR" 2>/dev/null || true
}

# Install the man page from <src> to /usr/share/man/man1/tacctl.1.gz and
# refresh mandb. Silent no-op if the source file is missing (keeps older
# repo checkouts working) or if mandb is unavailable (`man tacctl` still
# works directly without mandb).
install_man_page() {
    local src="$1"
    [[ -f "$src" ]] || return 0
    mkdir -p /usr/share/man/man1
    gzip -c "$src" > /usr/share/man/man1/tacctl.1.gz
    chmod 644 /usr/share/man/man1/tacctl.1.gz
    mandb -q 2>/dev/null || true
}

# --- Pre-flight ---
preflight() {
    if [[ ! -f "$CONFIG" ]]; then
        error "Config not found at ${CONFIG}. Is tacquito installed?"
        exit 1
    fi
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        error "python3-bcrypt not installed. Install it first."
        exit 1
    fi
}

# --- Resolve template file (user override → repo default) ---
SCRIPT_DIR="$(cd "$(dirname "$(readlink -f "$0")")" && pwd)"
TEMPLATE_DIR_LOCAL="/etc/tacquito/templates"
TEMPLATE_DIR_REPO="$(cd "${SCRIPT_DIR}/../config/templates" 2>/dev/null && pwd)"

resolve_template() {
    local name="$1"
    if [[ -f "${TEMPLATE_DIR_LOCAL}/${name}.template" ]]; then
        echo "${TEMPLATE_DIR_LOCAL}/${name}.template"
    elif [[ -n "$TEMPLATE_DIR_REPO" && -f "${TEMPLATE_DIR_REPO}/${name}.template" ]]; then
        echo "${TEMPLATE_DIR_REPO}/${name}.template"
    fi
}

# --- Restart service after config changes ---
# sed -i and python rewrites change the file inode, breaking fsnotify hot-reload.
restart_service() {
    systemctl restart tacquito 2>/dev/null && info "Service restarted." || warn "Service restart failed — run: sudo systemctl restart tacquito"
}

# --- Track password change date ---
record_password_date() {
    local username="$1"
    mkdir -p "$PASSWORD_DATES_DIR"
    chmod 750 "$PASSWORD_DATES_DIR"
    chown tacquito:tacquito "$PASSWORD_DATES_DIR" 2>/dev/null || true
    date +%Y-%m-%d > "${PASSWORD_DATES_DIR}/${username}.date"
}

get_password_date() {
    local username="$1"
    local datefile="${PASSWORD_DATES_DIR}/${username}.date"
    if [[ -f "$datefile" ]]; then
        cat "$datefile"
    else
        echo "unknown"
    fi
}

# Most recent login timestamp for a user, or "never". Parses the accounting
# log for JSON lines that pair "User":"<name>" with cmd=login (Flags:2 START).
# Session stops (cmd=logout / cmd=exit on Flags:4) are excluded.
get_last_login() {
    local username="$1"
    [[ -r "$ACCT_LOG" ]] || { echo "never"; return; }
    local ts
    ts=$(grep -F "\"User\":\"${username}\"" "$ACCT_LOG" 2>/dev/null \
        | grep -F 'cmd=login' \
        | tail -1 \
        | grep -oE '[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' \
        | head -1)
    if [[ -z "$ts" ]]; then
        echo "never"
    else
        echo "${ts//\//-}"
    fi
}

# --- Backup config before changes ---
BACKUP_RETENTION=30

backup_config() {
    mkdir -p "$BACKUP_DIR"
    chmod 750 "$BACKUP_DIR"
    chown tacquito:tacquito "$BACKUP_DIR" 2>/dev/null || true
    local ts
    ts=$(date +%Y%m%d_%H%M%S)
    cp "$CONFIG" "${BACKUP_DIR}/tacquito.yaml.${ts}"
    chmod 640 "${BACKUP_DIR}/tacquito.yaml.${ts}"
    chown tacquito:tacquito "${BACKUP_DIR}/tacquito.yaml.${ts}" 2>/dev/null || true
    info "Config backed up to ${BACKUP_DIR}/tacquito.yaml.${ts}"

    # Prune old backups, keep last $BACKUP_RETENTION
    local count
    count=$(ls -1 "${BACKUP_DIR}"/tacquito.yaml.* 2>/dev/null | wc -l)
    if [[ "$count" -gt "$BACKUP_RETENTION" ]]; then
        ls -1t "${BACKUP_DIR}"/tacquito.yaml.* | tail -n +$((BACKUP_RETENTION + 1)) | xargs rm -f
    fi
}

# --- Generate bcrypt hex hash from password ---
# Password is passed via stdin (not argv) so it never lands in
# /proc/<pid>/cmdline, which is world-readable on Linux by default.
generate_hash() {
    local password="$1"
    printf '%s' "$password" | python3 -c '
import bcrypt, binascii, sys
pw = sys.stdin.buffer.read()
rounds = int(sys.argv[1])
h = bcrypt.hashpw(pw, bcrypt.gensalt(rounds=rounds))
print(binascii.hexlify(h).decode())
' "$BCRYPT_COST"
}

# --- Normalize a bcrypt hash to the hex-encoded form tacquito reads ---
# Accepts either:
#   - raw form ('$2b$...', '$2a$...', '$2y$...') — hex-encoded on emit
#   - already hex-encoded (e.g. `tacctl hash` output) — lower-cased on emit
# Prints the hex-encoded result on stdout, or nothing if the input is
# not a recognizable bcrypt hash. Caller treats empty output as rejection.
normalize_bcrypt_hash() {
    local input="$1"
    # Route the candidate hash through stdin so it does not appear on argv
    # (/proc/<pid>/cmdline). The raw `$2b$...` form is a credential-equivalent
    # offline-crack target; the hex form is also stored in the YAML but we
    # keep the subprocess boundary tight regardless.
    printf '%s' "$input" | python3 -c '
import binascii, re, sys
s = sys.stdin.read()
# Raw form: "$2a$..", "$2b$..", "$2y$..". Hex-encode for storage.
if re.match(r"^\$2[aby]\$", s):
    print(binascii.hexlify(s.encode()).decode())
    sys.exit(0)
# Hex form must hex-decode to the raw prefix.
try:
    decoded = binascii.unhexlify(s).decode("ascii")
    if re.match(r"^\$2[aby]\$", decoded):
        print(s.lower())
        sys.exit(0)
except (binascii.Error, ValueError, UnicodeDecodeError):
    pass
'
}

# --- Verify a password against a stored hash ---
# Password via stdin (see generate_hash rationale). Hash travels via argv
# because it is already on-disk in the config; not additionally sensitive.
# checkpw returns bool; we must honor it (previous code printed MATCH for
# any input as long as the hash parsed).
verify_hash() {
    local password="$1"
    local hexhash="$2"
    # Password goes through stdin; the stored hash goes through /dev/fd
    # process substitution so neither shows up on argv. The hash already
    # lives in tacquito.yaml (mode 0640) so leaking to /proc/cmdline is a
    # low-severity issue, but the pattern is uniform across secret handling.
    printf '%s' "$password" | python3 - <(printf '%s' "$hexhash") <<'PY' 2>/dev/null || echo "FAIL"
import bcrypt, binascii, sys
pw = sys.stdin.buffer.read()
with open(sys.argv[1]) as f:
    hexhash = f.read()
try:
    h = binascii.unhexlify(hexhash)
except (binascii.Error, ValueError):
    print("INVALID_HASH")
    sys.exit(0)
try:
    if bcrypt.checkpw(pw, h):
        print("MATCH")
    else:
        print("NO_MATCH")
except ValueError:
    print("INVALID_HASH")
PY
}

# --- Validate class/value names ---
validate_class_name() {
    local value="$1"
    if [[ ! "$value" =~ ^[A-Za-z0-9_-]+$ ]]; then
        error "Invalid name '${value}'. Only letters, numbers, underscores, and hyphens are allowed."
        exit 1
    fi
}

# --- Validate username ---
validate_username() {
    local value="$1"
    if [[ ! "$value" =~ ^[a-zA-Z0-9_-]+$ ]]; then
        error "Username must contain only letters, numbers, underscores, and hyphens."
        exit 1
    fi
}

# --- Validate CIDR notation ---
validate_cidr() {
    local value="$1"
    if ! python3 -c "import ipaddress,sys; ipaddress.ip_network(sys.argv[1],strict=False)" "$value" 2>/dev/null; then
        error "Invalid CIDR: '${value}'"
        exit 1
    fi
}

# --- Convert an IPv4 CIDR to Cisco wildcard-mask form (10.1.0.0/16 -> "10.1.0.0 0.0.255.255") ---
# IPv6 inputs return empty — callers decide whether to skip or warn.
cidr_to_cisco_wildcard() {
    local value="$1"
    python3 -c "
import ipaddress, sys
n = ipaddress.ip_network(sys.argv[1], strict=False)
if n.version != 4:
    sys.exit(0)
print(f'{n.network_address} {n.hostmask}')
" "$value" 2>/dev/null
}

# --- Read the mgmt-ACL permit list ---
# Emits one CIDR per stdout line. Strips '# ...' comments, trailing
# whitespace, and blank lines. Missing file yields no output.
read_mgmt_acl_cidrs() {
    [[ -r "$MGMT_ACL_FILE" ]] || return 0
    # Strip comments + blank lines, then canonicalize each CIDR so
    # dedup / display is representation-agnostic.
    awk '
        { sub(/#.*/, "") }
        { gsub(/[[:space:]]+$/, "") }
        NF { print $1 }
    ' "$MGMT_ACL_FILE" | python3 -c "
import ipaddress, sys
for line in sys.stdin:
    s = line.strip()
    if not s:
        continue
    try:
        print(ipaddress.ip_network(s, strict=False))
    except ValueError:
        print(s)
"
}

# --- Write the mgmt-ACL file from a newline-separated CIDR list ---
# Replaces the entire file with a self-documenting header followed by
# canonical CIDR entries sorted by specificity. An empty input deletes
# the file entirely. Entries are deduped and sorted via Python.
write_mgmt_acl_cidrs() {
    local list="$1"
    if [[ -z "$(printf '%s\n' "$list" | awk 'NF')" ]]; then
        rm -f "$MGMT_ACL_FILE"
        return 0
    fi
    mkdir -p "$(dirname "$MGMT_ACL_FILE")"
    local tmp
    tmp=$(mktemp)
    {
        echo "# tacctl-managed mgmt ACL permit list."
        echo "# One CIDR per line. '#' comments allowed."
        echo "# Edit via: tacctl config mgmt-acl <add|remove|list|clear>"
        printf '%s\n' "$list" | python3 -c "
import ipaddress, sys
def key_fn(c):
    n = ipaddress.ip_network(c, strict=False)
    # Primary: version (v4 before v6). Secondary: broadcast address
    # ascending — disjoint ranges sort by end-of-range, and overlapping
    # subnets naturally fall just above their supernet (the subnet
    # ends earlier than the range containing it). Tertiary: network
    # address, for determinism across same-end-address edge cases.
    return (n.version, int(n.broadcast_address), int(n.network_address))
cidrs = []
for line in sys.stdin:
    s = line.strip()
    if not s:
        continue
    try:
        cidrs.append(str(ipaddress.ip_network(s, strict=False)))
    except ValueError:
        continue
for c in sorted(set(cidrs), key=key_fn):
    print(c)
"
    } > "$tmp"
    mv "$tmp" "$MGMT_ACL_FILE"
    chmod 644 "$MGMT_ACL_FILE"
}

# --- Read an mgmt-ACL name override (cisco|juniper) with default fallback ---
# Storage format at $MGMT_ACL_NAMES_FILE is simple `key=value` lines;
# unknown keys and blank lines ignored.
read_mgmt_acl_name() {
    local which="$1" default=""
    case "$which" in
        cisco)   default="$CISCO_ACL_NAME_DEFAULT" ;;
        juniper) default="$JUNIPER_ACL_NAME_DEFAULT" ;;
        *)       echo ""; return 0 ;;
    esac
    local value=""
    if [[ -r "$MGMT_ACL_NAMES_FILE" ]]; then
        value=$(awk -F= -v k="$which" '
            /^[[:space:]]*#/ { next }
            /^[[:space:]]*$/ { next }
            $1 == k { sub(/[[:space:]]+$/, "", $2); print $2; exit }
        ' "$MGMT_ACL_NAMES_FILE")
    fi
    echo "${value:-$default}"
}

# --- Validate an ACL name for Cisco / Juniper use ---
# Both vendors accept letters, digits, `_`, `-`; names must start with a
# letter; keep length <= 63 to match common IOS / Junos limits.
validate_acl_name() {
    local name="$1"
    if [[ -z "$name" ]]; then
        error "ACL name must not be empty."
        exit 1
    fi
    if [[ ${#name} -gt 63 ]]; then
        error "ACL name too long (${#name} chars; max 63)."
        exit 1
    fi
    if [[ ! "$name" =~ ^[A-Za-z][A-Za-z0-9_-]*$ ]]; then
        error "Invalid ACL name '${name}'. Must start with a letter and contain only letters, digits, '_', '-'."
        exit 1
    fi
}

# --- Write an mgmt-ACL name override (cisco|juniper) ---
write_mgmt_acl_name() {
    local which="$1" name="$2"
    mkdir -p "$(dirname "$MGMT_ACL_NAMES_FILE")"
    local tmp
    tmp=$(mktemp)
    # Preserve other keys; overwrite/insert the target key.
    local replaced="false"
    if [[ -f "$MGMT_ACL_NAMES_FILE" ]]; then
        awk -F= -v k="$which" -v v="$name" '
            BEGIN { done = 0 }
            /^[[:space:]]*#/ { print; next }
            /^[[:space:]]*$/ { print; next }
            $1 == k { print k "=" v; done = 1; next }
            { print }
            END { if (!done) print k "=" v }
        ' "$MGMT_ACL_NAMES_FILE" > "$tmp"
        replaced="true"
    else
        {
            echo "# tacctl-managed mgmt-ACL names (used by 'tacctl config cisco' / 'juniper')."
            echo "# Edit via: tacctl config mgmt-acl cisco-name <name>"
            echo "#           tacctl config mgmt-acl juniper-name <name>"
            echo "${which}=${name}"
        } > "$tmp"
    fi
    mv "$tmp" "$MGMT_ACL_NAMES_FILE"
    chmod 644 "$MGMT_ACL_NAMES_FILE"
    if [[ "$replaced" == "true" ]]; then
        info "Set ${which}-name = '${name}'."
    else
        info "Initialized ${MGMT_ACL_NAMES_FILE} with ${which}-name = '${name}'."
    fi
}

# --- Validate listen address (host:port or [ipv6]:port) against network family ---
validate_listen_address() {
    local net="$1" addr="$2"
    if ! python3 - "$net" "$addr" <<'PY' 2>/dev/null
import ipaddress, re, sys
net, addr = sys.argv[1], sys.argv[2]
m = re.match(r'^\[([^\]]+)\]:(\d+)$', addr)
if m:
    host, port = m.group(1), int(m.group(2))
else:
    m = re.match(r'^([^:]*):(\d+)$', addr)
    if not m:
        sys.exit(1)
    host, port = m.group(1), int(m.group(2))
if not 1 <= port <= 65535:
    sys.exit(1)
if host:
    ip = ipaddress.ip_address(host)
    if net == "tcp" and ip.version != 4:
        sys.exit(1)
    if net == "tcp6" and ip.version != 6:
        sys.exit(1)
PY
    then
        error "Invalid ${net} address: '${addr}'"
        return 1
    fi
}

# --- Systemd service drop-in helpers ---
# User-customized flags (-network, -address, -level) live as Environment=
# entries in a drop-in so that `tacctl upgrade` can safely replace the main
# service unit without clobbering them. Template defaults are in
# config/tacquito.service; the drop-in only records overrides.
OVERRIDE_DIR="/etc/systemd/system/tacquito.service.d"
OVERRIDE_FILE="${OVERRIDE_DIR}/tacctl-overrides.conf"

# Read an Environment= override; echo empty if not set.
# `|| true` absorbs grep's exit-1-on-no-match so `pipefail + set -e`
# callers don't abort when the override file doesn't exist / is empty.
read_service_override() {
    local key="$1"
    { grep -oP "^Environment=\"${key}=\K[^\"]*" "$OVERRIDE_FILE" 2>/dev/null || true; } | tail -1
}

# Write (or replace) an Environment= override for the given key.
set_service_override() {
    local key="$1" value="$2"
    mkdir -p "$OVERRIDE_DIR"
    if [[ ! -f "$OVERRIDE_FILE" ]] || ! grep -q "^\[Service\]" "$OVERRIDE_FILE"; then
        local tmp; tmp=$(mktemp)
        echo "[Service]" > "$tmp"
        [[ -f "$OVERRIDE_FILE" ]] && cat "$OVERRIDE_FILE" >> "$tmp"
        mv "$tmp" "$OVERRIDE_FILE"
    fi
    sed -i "/^Environment=\"${key}=/d" "$OVERRIDE_FILE"
    echo "Environment=\"${key}=${value}\"" >> "$OVERRIDE_FILE"
}

# Remove a single override key; drop the file (and dir) if no overrides remain.
clear_service_override() {
    local key="$1"
    [[ -f "$OVERRIDE_FILE" ]] || return 0
    sed -i "/^Environment=\"${key}=/d" "$OVERRIDE_FILE"
    if ! grep -q "^Environment=" "$OVERRIDE_FILE"; then
        rm -f "$OVERRIDE_FILE"
        rmdir "$OVERRIDE_DIR" 2>/dev/null || true
    fi
}

# --- Replace a user's hash in config (safe from sed injection) ---
# Hash travels via argv (already stored in readable config on disk).
replace_user_hash() {
    local username="$1"
    local new_hash="$2"
    # bcrypt hash is a one-way digest, but keeping it off argv matches the
    # same process-substitution pattern used for raw secrets — a leaked
    # hash is an offline-crack target and the /proc/<pid>/cmdline exposure
    # is free to close.
    python3 - "$CONFIG" "$username" <(printf '%s' "$new_hash") <<'PY'
import re, sys, tempfile, os
config_path, username, hash_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(hash_path) as f:
    new_hash = f.read()
config = open(config_path).read()
pattern = r'(bcrypt_' + re.escape(username) + r':.*?hash:\s*)\S+'
config = re.sub(pattern, r'\g<1>' + new_hash, config, count=1, flags=re.DOTALL)
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(config_path), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, config_path)
PY
}

# --- Check if user exists ---
user_exists() {
    local username="$1"
    grep -qP "^bcrypt_${username}:" "$CONFIG"
}

# --- Get user's hash ---
get_user_hash() {
    local username="$1"
    # Find the bcrypt anchor for this user and extract the hash value
    grep -A4 "^bcrypt_${username}:" "$CONFIG" | grep "hash:" | awk '{print $2}'
}

# --- Get user's group ---
get_user_group() {
    local username="$1"
    python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'- name: ' + re.escape(sys.argv[2]) + r'\n.*?groups: \[\*(\w+)\]', config, re.DOTALL)
print(m.group(1) if m else 'unknown')
" "$CONFIG" "$username"
}

# --- Read password with asterisk masking ---
read_password_masked() {
    local prompt="${1:-Password: }"
    local password="" char=""
    printf "%s" "$prompt" >&2
    while IFS= read -rsn1 char; do
        # Enter pressed
        if [[ -z "$char" ]]; then
            break
        fi
        # Backspace / delete
        if [[ "$char" == $'\x7f' || "$char" == $'\b' ]]; then
            if [[ -n "$password" ]]; then
                password="${password%?}"
                printf '\b \b' >&2
            fi
        else
            password+="$char"
            printf '*' >&2
        fi
    done
    echo "" >&2
    echo "$password"
}

# --- Validate password strength for a user-chosen password ---
# Auto-generated passwords bypass this (they're always long + mixed).
# Returns 0 on accept, 1 on reject (with error printed).
validate_password_strength() {
    local password="$1"
    local username="${2:-}"

    if [[ "${#password}" -lt "$PASSWORD_MIN_LENGTH" ]]; then
        error "Password is ${#password} characters; minimum is ${PASSWORD_MIN_LENGTH}."
        return 1
    fi

    local lower="${password,,}"
    # Reject the usual suspects. Lowercase-fold first so variants ("Admin",
    # "ADMIN") all match. Not a dictionary check — just the handful that
    # dominate breach corpora.
    case "$lower" in
        admin|administrator|root|password|password1|passw0rd|\
        tacacs|tacacs+|tacplus|tacquito|\
        cisco|cisco123|juniper|juniper1|\
        changeme|welcome|welcome1|letmein|qwerty*|abc123*|\
        12345*|00000*|aaaaaa*)
            error "Password is on the common-weak list. Choose another."
            return 1
            ;;
    esac

    if [[ -n "$username" && "$lower" == "${username,,}" ]]; then
        error "Password must not equal the username."
        return 1
    fi

    return 0
}

# --- Prompt for password ---
# If $1 is given, it's the username — used for password-equals-username checks.
prompt_password() {
    local username="${1:-}"
    local password=""
    password=$(read_password_masked "  Enter password (leave blank to auto-generate): ")
    if [[ -z "$password" ]]; then
        password=$(openssl rand -base64 18)
        echo -e "  Generated password: ${BOLD}${password}${NC}" >&2
    else
        if ! validate_password_strength "$password" "$username"; then
            exit 1
        fi
        local confirm=""
        confirm=$(read_password_masked "  Confirm password: ")
        if [[ "$password" != "$confirm" ]]; then
            echo -e "  ${RED}Passwords do not match.${NC}" >&2
            exit 1
        fi
    fi
    echo "$password"
}

# =====================================================================
#  COMMANDS
# =====================================================================

# --- LIST ---
cmd_list() {
    echo ""
    echo -e "${BOLD}Tacquito Users${NC}"
    echo "--------------------------------------------"
    printf "  ${BOLD}%-20s %-15s %-10s %-12s %-30s${NC}\n" "USERNAME" "GROUP" "STATUS" "PW CHANGED" "SCOPES"
    echo "  -----------------------------------------------------------------------------------------------"

    # Use Python for reliable YAML-ish parsing. Pull scopes via yaml.safe_load
    # since that field can span multiple forms ([\"a\",\"b\"] or block list);
    # the other fields stay on the regex path for consistency with prior output.
    python3 -c "
import re, sys, yaml

config_path = sys.argv[1]
config = open(config_path).read()

# Extract only the users: section for the regex pass.
users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
if not users_match:
    sys.exit(0)
users_section = users_match.group(1)

# Build a scopes map via safe_load so we don't have to teach the regex about
# every YAML list form.
scopes_map = {}
try:
    with open(config_path) as f:
        d = yaml.safe_load(f) or {}
    for u in (d.get('users') or []):
        name = u.get('name')
        if name:
            scopes_map[name] = u.get('scopes') or []
except Exception:
    pass

DISABLED_MARKER = sys.argv[2]
for m in re.finditer(r'- name: (\S+)\n.*?groups: \[\*(\w+)\]', users_section, re.DOTALL):
    username = m.group(1)
    group = m.group(2)

    auth_match = re.search(r'^bcrypt_' + re.escape(username) + r':.*?hash:\s*(\S+)', config, re.MULTILINE | re.DOTALL)
    if auth_match:
        h = auth_match.group(1)
        status = 'disabled' if h == 'DISABLED' or h == DISABLED_MARKER else 'active'
    else:
        status = 'unknown'

    scopes = scopes_map.get(username, [])
    print(f'{username}|{group}|{status}|' + ','.join(scopes))
" "$CONFIG" "$DISABLED_MARKER_HEX" | sort | while IFS='|' read -r username group status scopes_csv; do
        local color="$GREEN"
        [[ "$status" == "disabled" ]] && color="$RED"
        [[ "$status" == "unknown" ]] && color="$YELLOW"
        local pw_date
        pw_date=$(get_password_date "$username")
        local scopes_display=""
        if [[ -z "$scopes_csv" ]]; then
            scopes_display="(none)"
        else
            # Truncate >3 scopes with "(…+N)" suffix.
            local IFS_old="$IFS"
            IFS=',' read -ra _SC <<< "$scopes_csv"
            IFS="$IFS_old"
            if (( ${#_SC[@]} > 3 )); then
                scopes_display="${_SC[0]},${_SC[1]},${_SC[2]} (…+$(( ${#_SC[@]} - 3 )))"
            else
                scopes_display="$scopes_csv"
            fi
        fi
        printf "  %-20s %-15s ${color}%-10s${NC} %-12s %-30s\n" "$username" "$group" "$status" "$pw_date" "$scopes_display"
    done

    echo ""
}

# --- ADD ---
cmd_add() {
    local username="${1:-}"
    local group="${2:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user add <username> <group> [--hash <bcrypt-hash>] [--scopes <name>[,<name>...]]"
        exit 1
    fi
    validate_username "$username"
    # Validate group exists in config
    if ! grep -q "^${group}: &${group}$" "$CONFIG"; then
        local available
        available=$(grep -oP '^\w+(?=: &\w)' "$CONFIG" | grep -v "^bcrypt_\|^exec_\|^junos_\|^file_\|^authenticator\|^action\|^accounter\|^handler\|^provider" | tr '\n' '|' | sed 's/|$//')
        error "Group '${group}' does not exist. Available: ${available}"
        error "Usage: tacctl user add <username> <group>"
        exit 1
    fi
    if user_exists "$username"; then
        error "User '${username}' already exists."
        exit 1
    fi

    # Parse optional flags: --hash <value>, --scopes <csv>
    local hash=""
    local scopes_csv=""
    shift 2 || true
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --hash)
                hash="${2:-}"
                if [[ -z "$hash" ]]; then
                    error "Usage: tacctl user add <username> <group> --hash <bcrypt-hash>"
                    exit 1
                fi
                local normalized
                normalized=$(normalize_bcrypt_hash "$hash")
                if [[ -z "$normalized" ]]; then
                    error "Invalid bcrypt hash."
                    error "Accepted forms:"
                    error "  - hex-encoded (from 'tacctl hash'): 24326224313224..."
                    error "  - raw (from bcrypt libs):           \$2b\$12\$..."
                    exit 1
                fi
                hash="$normalized"
                shift 2
                ;;
            --scopes)
                scopes_csv="${2:-}"
                if [[ -z "$scopes_csv" ]]; then
                    error "Usage: tacctl user add <username> <group> --scopes <name>[,<name>...]"
                    exit 1
                fi
                shift 2
                ;;
            *)
                error "Unknown argument: '$1'"
                error "Usage: tacctl user add <username> <group> [--hash <bcrypt-hash>] [--scopes <name>[,<name>...]]"
                exit 1
                ;;
        esac
    done

    # Determine scopes list. If --scopes given, validate each name exists; else
    # fall back to default-scope marker (or sole-scope / hardcoded seed name).
    local scope_names=""
    if [[ -n "$scopes_csv" ]]; then
        local s
        IFS=',' read -ra _REQ <<< "$scopes_csv"
        for s in "${_REQ[@]}"; do
            s=$(echo "$s" | xargs)
            [[ -z "$s" ]] && continue
            if ! scope_exists "$s"; then
                error "Scope '${s}' does not exist. Available: $(list_scopes | paste -sd' ')"
                exit 1
            fi
            # within-input dedupe
            if ! printf '%s\n' "$scope_names" | grep -qxF "$s" 2>/dev/null; then
                scope_names+="${scope_names:+$'\n'}${s}"
            fi
        done
        [[ -z "$scope_names" ]] && { error "No valid scope names provided."; exit 1; }
    else
        scope_names=$(read_default_scope)
        if [[ -z "$scope_names" ]]; then
            error "No scopes exist and no default scope is set."
            error "Create one first: tacctl scopes add <name> --prefixes <cidrs>"
            exit 1
        fi
    fi
    # Build JSON array form for the YAML writer (safe strings — scope names
    # already validated via scope_exists, which only allows existing YAML names).
    local scopes_json
    scopes_json=$(printf '%s\n' "$scope_names" | awk 'NF' | awk 'BEGIN{printf "["} NR>1{printf ", "} {printf "\"%s\"", $0} END{printf "]"}')

    echo ""
    echo -e "  Adding user: ${BOLD}${username}${NC} (${group})"

    if [[ -z "$hash" ]]; then
        local password
        password=$(prompt_password "$username")
        hash=$(generate_hash "$password")
        unset password
    else
        info "Using pre-generated bcrypt hash."
    fi

    backup_config

    # Insert authenticator anchor and user entry using Python. The bcrypt
    # hash goes through a /dev/fd pipe so it never appears in
    # /proc/<pid>/cmdline; the other args (username, group, scopes_json)
    # are non-secret and stay on argv for readability.
    python3 - "$CONFIG" "$username" <(printf '%s' "$hash") "$group" "$scopes_json" <<'PY'
import sys, tempfile, os

config_path = sys.argv[1]
username = sys.argv[2]
hash_path = sys.argv[3]
group = sys.argv[4]
scopes_json = sys.argv[5]
with open(hash_path) as f:
    hash_val = f.read()
config = open(config_path).read()

# Insert authenticator block before '# --- Services ---'. Normalize the
# whitespace at the seam: strip trailing newlines from what's already
# there, then apply a deterministic '\n\n' (= one blank line) before
# and after the new block so spacing stays consistent regardless of
# whatever the prior insert (or original template) left behind.
auth_block = (
    f'bcrypt_{username}: &bcrypt_{username}\n'
    f'  type: *authenticator_type_bcrypt\n'
    f'  options:\n'
    f'    hash: {hash_val}\n'
)
marker = '# --- Services ---'
idx = config.index(marker)
prefix = config[:idx].rstrip('\n')
config = prefix + '\n\n' + auth_block.rstrip('\n') + '\n\n' + config[idx:]

# Insert user entry before '# --- Secret Providers ---'. Same
# normalize-and-apply approach as auth_block above.
user_block = (
    f'  # {username}\n'
    f'  - name: {username}\n'
    f'    scopes: {scopes_json}\n'
    f'    groups: [*{group}]\n'
    f'    authenticator: *bcrypt_{username}\n'
    f'    accounter: *file_accounter\n'
)
marker2 = '# --- Secret Providers ---'
idx2 = config.index(marker2)
prefix2 = config[:idx2].rstrip('\n')
config = prefix2 + '\n\n' + user_block.rstrip('\n') + '\n\n' + config[idx2:]

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(config_path), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, config_path)
PY

    # Fix ownership
    chown tacquito:tacquito "$CONFIG"

    restart_service
    record_password_date "$username"
    local scopes_display
    scopes_display=$(printf '%s\n' "$scope_names" | awk 'NF' | paste -sd,)
    info "User '${username}' added (${group}) with scopes: ${scopes_display}"
    echo ""
}

# --- REMOVE ---
cmd_remove() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user remove <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    echo ""
    read -rp "  Remove user '${username}'? This cannot be undone. [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    backup_config

    # Remove the authenticator anchor block (bcrypt_<username> through next blank line or next anchor)
    sed -i "/^bcrypt_${username}:/,/^$/d" "$CONFIG"

    # Remove the user entry block (from "# <username>" or "- name: <username>" to next "- name:" or section)
    # First try removing a comment line above the user entry
    sed -i "/^  # ${username}$/d" "$CONFIG"
    # Remove the user entry itself (multi-line block)
    python3 -c "
import sys
lines = open(sys.argv[1]).readlines()
out = []
skip = False
for i, line in enumerate(lines):
    if line.strip() == '- name: ${username}':
        skip = True
        continue
    if skip:
        if line.startswith('  - name:') or not line.startswith('    '):
            skip = False
        else:
            continue
    out.append(line)
import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.writelines(out)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG"

    # Clean up double blank lines
    sed -i '/^$/N;/^\n$/d' "$CONFIG"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "User '${username}' removed."
    echo ""
}

# --- PASSWD (change password) ---
cmd_passwd() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user passwd <username> [--hash <bcrypt-hash>]"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    # Check for --hash flag (pre-generated bcrypt hash)
    local hash=""
    if [[ "${2:-}" == "--hash" ]]; then
        hash="${3:-}"
        if [[ -z "$hash" ]]; then
            error "Usage: tacctl user passwd <username> --hash <bcrypt-hash>"
            exit 1
        fi
        local normalized
        normalized=$(normalize_bcrypt_hash "$hash")
        if [[ -z "$normalized" ]]; then
            error "Invalid bcrypt hash."
            error "Accepted forms:"
            error "  - hex-encoded (from 'tacctl hash'): 24326224313224..."
            error "  - raw (from bcrypt libs):           \$2b\$12\$..."
            exit 1
        fi
        hash="$normalized"
    fi

    echo ""
    echo -e "  Changing password for: ${BOLD}${username}${NC}"

    if [[ -z "$hash" ]]; then
        local password
        password=$(prompt_password "$username")
        hash=$(generate_hash "$password")
        unset password
    else
        info "Using pre-generated bcrypt hash."
    fi

    backup_config

    replace_user_hash "$username" "$hash"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    record_password_date "$username"
    info "Password changed for '${username}'."
    echo ""
}

# --- DISABLE ---
cmd_disable() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user disable <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local current_hash
    current_hash=$(get_user_hash "$username")
    if is_disabled_hash "$current_hash"; then
        warn "User '${username}' is already disabled."
        exit 0
    fi

    backup_config

    # Save the real hash to a sidecar file for re-enabling
    mkdir -p "${BACKUP_DIR}/disabled"
    chmod 700 "${BACKUP_DIR}/disabled"
    echo "$current_hash" > "${BACKUP_DIR}/disabled/${username}.hash"
    chmod 600 "${BACKUP_DIR}/disabled/${username}.hash"

    replace_user_hash "$username" "$DISABLED_MARKER_HEX"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "User '${username}' disabled. Use 'enable' to restore access."
    echo ""
}

# --- ENABLE ---
cmd_enable() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user enable <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local current_hash
    current_hash=$(get_user_hash "$username")
    if ! is_disabled_hash "$current_hash"; then
        warn "User '${username}' is not disabled."
        exit 0
    fi

    local saved_hash_file="${BACKUP_DIR}/disabled/${username}.hash"
    if [[ ! -f "$saved_hash_file" ]]; then
        error "No saved hash found for '${username}'. Set a new password instead:"
        error "  tacctl user passwd ${username}"
        exit 1
    fi

    local saved_hash
    saved_hash=$(cat "$saved_hash_file")

    backup_config

    replace_user_hash "$username" "$saved_hash"
    rm -f "$saved_hash_file"

    chown tacquito:tacquito "$CONFIG"

    restart_service
    info "User '${username}' re-enabled with previous password."
    echo ""
}

# --- SHOW (read-only detail view; no password prompt) ---
cmd_show() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user show <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    local group stored_hash status pw_date pw_age last_login
    group=$(get_user_group "$username")
    stored_hash=$(get_user_hash "$username")
    if is_disabled_hash "$stored_hash"; then
        status="disabled"
    else
        status="active"
    fi
    pw_date=$(get_password_date "$username")
    if [[ "$pw_date" != "unknown" ]]; then
        pw_age=$(( ( $(date +%s) - $(date -d "$pw_date" +%s) ) / 86400 ))
    fi
    last_login=$(get_last_login "$username")

    # Resolve Cisco priv-lvl and Juniper class for the user's group by
    # walking the YAML services chain. Falls back to empty on any error.
    local yaml_info priv_lvl juniper_class
    yaml_info=$(python3 - "$CONFIG" "$group" <<'PY' 2>/dev/null || echo '|'
import yaml, sys
try:
    with open(sys.argv[1]) as f:
        c = yaml.safe_load(f)
    g = c.get(sys.argv[2], {}) or {}
    priv = ''
    jclass = ''
    for s in g.get('services', []) or []:
        if s.get('name') == 'exec':
            for sv in s.get('set_values', []) or []:
                if sv.get('name') == 'priv-lvl':
                    v = sv.get('values') or []
                    if v:
                        priv = v[0]
        elif s.get('name') == 'junos-exec':
            for sv in s.get('set_values', []) or []:
                if sv.get('name') == 'local-user-name':
                    v = sv.get('values') or []
                    if v:
                        jclass = v[0]
    print(f'{priv}|{jclass}')
except Exception:
    print('|')
PY
)
    IFS='|' read -r priv_lvl juniper_class <<< "$yaml_info"

    # Hash fingerprint: the hash is stored hex-encoded in the YAML ("24326224313024..." = "$2b$10$..."). Decode the first 7 bcrypt chars (14 hex chars) to surface algorithm + cost without disclosing salt or digest.
    local hash_prefix=""
    if [[ -n "$stored_hash" ]] && ! is_disabled_hash "$stored_hash"; then
        hash_prefix=$(echo "${stored_hash:0:14}" | xxd -r -p 2>/dev/null)
    fi

    echo ""
    echo -e "  ${BOLD}User:${NC}             ${username}"
    echo -e "  ${BOLD}Group:${NC}            ${group}"
    if [[ "$status" == "disabled" ]]; then
        echo -e "  ${BOLD}Status:${NC}           ${RED}disabled${NC}"
    else
        echo -e "  ${BOLD}Status:${NC}           ${GREEN}active${NC}"
    fi
    if [[ -n "$pw_age" ]]; then
        echo -e "  ${BOLD}Password changed:${NC} ${pw_date} (${pw_age} days ago)"
    else
        echo -e "  ${BOLD}Password changed:${NC} ${pw_date}"
    fi
    echo -e "  ${BOLD}Last login:${NC}       ${last_login}"
    [[ -n "$priv_lvl" ]]      && echo -e "  ${BOLD}Cisco priv-lvl:${NC}   ${priv_lvl}"
    [[ -n "$juniper_class" ]] && echo -e "  ${BOLD}Juniper class:${NC}    ${juniper_class}"
    echo -e "  ${BOLD}Hash type:${NC}        ${hash_prefix}"
    local user_scopes
    user_scopes=$(read_user_scopes "$username")
    if [[ -z "$user_scopes" ]]; then
        echo -e "  ${BOLD}Scopes:${NC}           ${RED}(none — cannot authenticate on any device)${NC}"
    else
        local first=1
        while IFS= read -r s; do
            [[ -z "$s" ]] && continue
            local label=""
            if scope_exists "$s"; then
                label="$s"
            else
                label="${RED}${s} (ORPHAN)${NC}"
            fi
            if (( first )); then
                echo -e "  ${BOLD}Scopes:${NC}           ${label}"
                first=0
            else
                echo -e "                    ${label}"
            fi
        done <<< "$user_scopes"
    fi
    echo ""
}

# --- VERIFY (test a password against stored hash) ---
cmd_verify() {
    local username="${1:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user verify <username>"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    # Show user details
    local group
    group=$(get_user_group "$username")
    local stored_hash
    stored_hash=$(get_user_hash "$username")
    local status="active"
    is_disabled_hash "$stored_hash" && status="disabled"
    local pw_date
    pw_date=$(get_password_date "$username")

    echo ""
    echo -e "  ${BOLD}User:${NC}           ${username}"
    echo -e "  ${BOLD}Group:${NC}          ${group}"
    if [[ "$status" == "disabled" ]]; then
        echo -e "  ${BOLD}Status:${NC}         ${RED}disabled${NC}"
        echo -e "  ${BOLD}PW changed:${NC}     ${pw_date}"
        echo ""
        error "User is disabled — cannot verify password."
        exit 1
    fi
    echo -e "  ${BOLD}Status:${NC}         ${GREEN}active${NC}"
    echo -e "  ${BOLD}PW changed:${NC}     ${pw_date}"
    echo ""

    local password
    password=$(read_password_masked "  Enter password to verify: ")

    local result
    result=$(verify_hash "$password" "$stored_hash")
    unset password

    # SUDO_UID is the invoking user's uid when run via sudo; falls back to
    # the current EUID (root/0) for direct-as-root invocations.
    local caller_uid="${SUDO_UID:-$EUID}"
    local caller_name="${SUDO_USER:-root}"

    if [[ "$result" == "MATCH" ]]; then
        logger -t tacctl -p auth.info \
            "verify OK user=${username} by=${caller_name}(uid=${caller_uid})" 2>/dev/null || true
        info "Password is correct."
    else
        # Rate-limit failures so the CLI isn't usable as a local bcrypt
        # oracle. 500ms is cheap for humans, expensive for scripted guessing.
        sleep 0.5
        logger -t tacctl -p auth.warning \
            "verify FAIL user=${username} result=${result} by=${caller_name}(uid=${caller_uid})" 2>/dev/null || true
        error "Password does not match."
    fi
    echo ""
}

# --- RENAME ---
cmd_rename() {
    local oldname="${1:-}"
    local newname="${2:-}"

    if [[ -z "$oldname" || -z "$newname" ]]; then
        error "Usage: tacctl user rename <old-username> <new-username>"
        exit 1
    fi
    validate_username "$oldname"
    validate_username "$newname"
    if ! user_exists "$oldname"; then
        error "User '${oldname}' does not exist."
        exit 1
    fi
    if user_exists "$newname"; then
        error "User '${newname}' already exists."
        exit 1
    fi

    backup_config

    # Use Python for reliable multi-reference rename
    python3 -c "
import re, sys

oldname = sys.argv[2]
newname = sys.argv[3]

config = open(sys.argv[1]).read()

# Rename bcrypt anchor: 'bcrypt_old: &bcrypt_old' -> 'bcrypt_new: &bcrypt_new'
config = config.replace(f'bcrypt_{oldname}: &bcrypt_{oldname}', f'bcrypt_{newname}: &bcrypt_{newname}')

# Rename authenticator reference: '*bcrypt_old' -> '*bcrypt_new'
config = config.replace(f'*bcrypt_{oldname}', f'*bcrypt_{newname}')

# Rename user entry: '- name: old' -> '- name: new'
config = re.sub(rf'^(\s+- name: ){re.escape(oldname)}$', rf'\g<1>{newname}', config, flags=re.MULTILINE)

# Rename comment if present: '# old' -> '# new'
config = re.sub(rf'^(\s+# ){re.escape(oldname)}$', rf'\g<1>{newname}', config, flags=re.MULTILINE)

import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG" "$oldname" "$newname"

    chown tacquito:tacquito "$CONFIG"

    # Rename password date file
    if [[ -f "${PASSWORD_DATES_DIR}/${oldname}.date" ]]; then
        mv "${PASSWORD_DATES_DIR}/${oldname}.date" "${PASSWORD_DATES_DIR}/${newname}.date"
    fi

    restart_service
    info "User renamed: ${oldname} -> ${newname}"
    echo ""
}

# --- MOVE (change user's group) ---
cmd_move() {
    local username="${1:-}"
    local newgroup="${2:-}"

    if [[ -z "$username" || -z "$newgroup" ]]; then
        error "Usage: tacctl move <username> <new-group>"
        exit 1
    fi
    validate_username "$username"
    validate_class_name "$newgroup"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi
    if ! grep -q "^${newgroup}: &${newgroup}$" "$CONFIG"; then
        local available
        available=$(grep -oP '^\w+(?=: &\w)' "$CONFIG" | grep -v "^bcrypt_\|^exec_\|^junos_\|^file_\|^authenticator\|^action\|^accounter\|^handler\|^provider" | tr '\n' '|' | sed 's/|$//' || true)
        error "Group '${newgroup}' does not exist. Available: ${available}"
        exit 1
    fi

    local oldgroup
    oldgroup=$(get_user_group "$username")
    if [[ "$oldgroup" == "$newgroup" ]]; then
        info "User '${username}' is already in group '${newgroup}'."
        return
    fi

    backup_config

    # Replace the group reference in the user entry
    python3 -c "
import re, sys
config = open(sys.argv[1]).read()
username = sys.argv[2]
oldgroup = sys.argv[3]
newgroup = sys.argv[4]

# Find the user block and replace the group
pattern = r'(- name: ' + re.escape(username) + r'\n.*?groups: \[\*)' + re.escape(oldgroup) + r'(\])'
config = re.sub(pattern, r'\g<1>' + newgroup + r'\2', config, flags=re.DOTALL)

import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG" "$username" "$oldgroup" "$newgroup"

    chown tacquito:tacquito "$CONFIG"
    restart_service
    info "User '${username}' moved: ${oldgroup} -> ${newgroup}"
    echo ""
}

# =====================================================================
#  CONFIG COMMANDS
# =====================================================================

# --- Helper: get current value from config using Python ---
get_config_value() {
    local key="$1"
    python3 -c "
import re, sys

config = open(sys.argv[1]).read()
key = sys.argv[2]

if key == 'juniper-ro':
    m = re.search(r'junos_exec_readonly:.*?values:\s*\[\"?([^\"\]\n]+)', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'juniper-rw':
    m = re.search(r'junos_exec_superuser:.*?values:\s*\[\"?([^\"\]\n]+)', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'cisco-ro':
    m = re.search(r'exec_readonly:.*?values:\s*\[(\d+)\]', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'cisco-op':
    m = re.search(r'exec_operator:.*?values:\s*\[(\d+)\]', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'cisco-rw':
    m = re.search(r'exec_superuser:.*?values:\s*\[(\d+)\]', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'juniper-op':
    m = re.search(r'junos_exec_operator:.*?values:\s*\[\"?([^\"\]\n]+)', config, re.DOTALL)
    print(m.group(1) if m else 'NOT FOUND')
elif key == 'address':
    # read from systemd unit
    import subprocess
    r = subprocess.run(['systemctl', 'show', 'tacquito', '--property=ExecStart'], capture_output=True, text=True)
    m2 = re.search(r'-address\s+(\S+)', r.stdout)
    print(m2.group(1) if m2 else ':49')
" "$CONFIG" "$key"
}

# --- CONFIG SHOW ---
cmd_config_show() {
    echo ""
    echo -e "${BOLD}Tacquito Configuration${NC}"
    echo "--------------------------------------------"

    local juniper_ro juniper_op juniper_rw cisco_ro cisco_op cisco_rw
    juniper_ro=$(get_config_value "juniper-ro")
    juniper_op=$(get_config_value "juniper-op")
    juniper_rw=$(get_config_value "juniper-rw")
    cisco_ro=$(get_config_value "cisco-ro")
    cisco_op=$(get_config_value "cisco-op")
    cisco_rw=$(get_config_value "cisco-rw")

    # Scopes — one block per scope showing its secret length + prefixes.
    local default_scope
    default_scope=$(read_default_scope)
    local all_scopes
    all_scopes=$(list_scopes)
    echo ""
    echo -e "  ${BOLD}Scopes:${NC}"
    if [[ -z "$all_scopes" ]]; then
        echo -e "    ${RED}(none configured)${NC}"
    else
        while IFS= read -r scope; do
            [[ -z "$scope" ]] && continue
            local s_secret s_len s_pfx n_users marker=""
            s_secret=$(read_scope_secret "$scope")
            s_len=${#s_secret}
            n_users=$(count_users_in_scope "$scope")
            [[ "$scope" == "$default_scope" ]] && marker="  ${CYAN}(default)${NC}"
            echo -e "    ${BOLD}${scope}${NC}${marker}"
            echo -e "      Secret:             ${s_len} chars"
            echo -e "      Users:              ${n_users}"
            echo -e "      Prefixes:"
            s_pfx=$(read_scope_prefixes "$scope")
            if [[ -z "$s_pfx" ]]; then
                echo -e "        ${RED}(empty — no clients can auth against this scope)${NC}"
            else
                echo "$s_pfx" | while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    echo "        - ${c}"
                done
            fi
        done <<< "$all_scopes"
    fi
    echo ""
    echo -e "  ${BOLD}Cisco (priv-lvl):${NC}"
    echo -e "    Read-only:          ${cisco_ro}"
    echo -e "    Operator:           ${cisco_op}"
    echo -e "    Super-user:         ${cisco_rw}"
    echo ""
    echo -e "  ${BOLD}Juniper (local-user-name):${NC}"
    echo -e "    Read-only class:    ${juniper_ro}"
    echo -e "    Operator class:     ${juniper_op}"
    echo -e "    Super-user class:   ${juniper_rw}"

    # Show allow/deny lists
    local allow_list deny_list
    allow_list=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^prefix_allow:\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    print(', '.join(re.findall(r'\"([^\"]+)\"', m.group(1))))
else:
    print('')
" "$CONFIG" || true)
    deny_list=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^prefix_deny:\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    print(', '.join(re.findall(r'\"([^\"]+)\"', m.group(1))))
else:
    print('')
" "$CONFIG" || true)

    echo ""
    echo -e "  ${BOLD}Connection Filters:${NC} ${CYAN}(deny takes precedence over allow)${NC}"
    if [[ -n "$allow_list" ]]; then
        echo -e "    Allow:              ${allow_list}"
    else
        echo -e "    Allow:              ${CYAN}(all)${NC}"
    fi
    if [[ -n "$deny_list" ]]; then
        echo -e "    Deny:               ${deny_list}"
    else
        echo -e "    Deny:               ${CYAN}(none)${NC}"
    fi

    echo ""
    echo -e "  ${BOLD}Config file:${NC}          ${CONFIG}"
    echo -e "  ${BOLD}Service status:${NC}       $(systemctl is-active tacquito 2>/dev/null || echo 'unknown')"

    # Show listening port (TACACS+ = port 49)
    local listen
    listen=$(ss -tlnp 2>/dev/null | grep ":49 " | awk '{print $4}' | head -1)
    if [[ -n "$listen" ]]; then
        echo -e "  ${BOLD}Listening on:${NC}         ${listen}"
    else
        echo -e "  ${BOLD}Listening on:${NC}         ${RED}port 49 not detected${NC}"
    fi
    echo ""
}

# --- CONFIG SECRET ---
# --- Read the current shared secret from the YAML (may be empty) ---
# --- Legacy 'config secret' — REMOVED ---
# Scope-owned properties now live under 'tacctl scopes secret <name>'.
# This stub prints an explicit redirect so muscle-memory and scripted
# callers learn where to go instead of hitting a generic dispatcher
# error. It does not mutate state.
cmd_config_secret() {
    error "'tacctl config secret' was removed in this release."
    error "Scope-owned secrets now live under 'tacctl scopes':"
    error "  tacctl scopes secret <name> show"
    error "  tacctl scopes secret <name> set <value>"
    error "  tacctl scopes secret <name> generate"
    error ""
    error "Default scope: $(read_default_scope || echo '(unset)')"
    error "Available:     $(list_scopes | paste -sd' ')"
    exit 2
}

# =====================================================================
#  SCOPE HELPERS — multi-scope YAML access
# =====================================================================
#
# A "scope" in tacctl corresponds to one `secrets:` list entry in
# /etc/tacquito/tacquito.yaml. Each scope is a named (prefixes,
# shared-secret) bundle; users carry a list of scope names in their
# `scopes:` YAML field and can auth only from devices matching a scope
# they're a member of.
#
# These helpers use yaml.safe_load for reads (robust against anchor
# expansion, field reordering, etc.) and regex-based surgical edits for
# writes (to preserve YAML anchors like *authenticator_type_bcrypt that
# safe_dump would otherwise inline).

# --- Read the default-scope marker ---
# Returns the configured default scope name. Falls back to the name of
# the sole secrets: entry if the marker file is missing and there's
# exactly one scope. Empty output if no scopes exist yet.
read_default_scope() {
    if [[ -r "$DEFAULT_SCOPE_FILE" ]]; then
        local v
        v=$(cat "$DEFAULT_SCOPE_FILE" 2>/dev/null | head -1 | xargs)
        if [[ -n "$v" ]] && scope_exists "$v"; then
            echo "$v"
            return
        fi
    fi
    # Fallback: if there's exactly one scope, it's the implicit default.
    local names
    names=$(list_scopes)
    if [[ -n "$names" && $(printf '%s\n' "$names" | wc -l) -eq 1 ]]; then
        echo "$names"
    fi
}

# --- Write the default-scope marker ---
# Caller is responsible for verifying the name exists as a scope first.
write_default_scope() {
    local name="$1"
    mkdir -p "$(dirname "$DEFAULT_SCOPE_FILE")"
    printf '%s\n' "$name" > "$DEFAULT_SCOPE_FILE"
    chmod 644 "$DEFAULT_SCOPE_FILE"
}

# --- List all scope names (one per line) ---
list_scopes() {
    [[ -r "$CONFIG" ]] || return 0
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
# Under flat emission one logical scope spans N secrets[] entries; dedupe
# by name preserving first-appearance order so callers see the logical view.
seen = set()
for s in (d.get('secrets') or []):
    name = s.get('name')
    if name and name not in seen:
        seen.add(name)
        print(name)
" "$CONFIG" 2>/dev/null
}

# --- Return 0 if the named scope exists ---
scope_exists() {
    local name="$1"
    [[ -n "$name" ]] || return 1
    list_scopes | grep -qxF "$name"
}

# --- Read one scope's CIDR prefixes (canonical, one per line) ---
# Aggregates across every secrets[] entry whose name matches (flat emission
# can spread a scope's prefixes across multiple entries). Output is sorted
# by the standard (version, broadcast, network) key so the caller sees a
# stable, specificity-ordered list.
read_scope_prefixes() {
    local name="$1"
    python3 -c "
import yaml, json, ipaddress, re, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
collected = []
for s in (d.get('secrets') or []):
    if s.get('name') != target:
        continue
    opts = s.get('options') or {}
    pfx = opts.get('prefixes')
    if not pfx:
        continue
    try:
        arr = json.loads(pfx)
    except Exception:
        arr = re.findall(r'\"([^\"]+)\"', pfx)
    for c in arr:
        try:
            collected.append(ipaddress.ip_network(c, strict=False))
        except ValueError:
            pass
seen = set()
uniq = []
for n in collected:
    if n not in seen:
        seen.add(n)
        uniq.append(n)
uniq.sort(key=lambda n: (n.version, int(n.broadcast_address), int(n.network_address)))
for n in uniq:
    print(n)
" "$CONFIG" "$name" 2>/dev/null
}

# --- Read one scope's shared-secret key (raw value) ---
read_scope_secret() {
    local name="$1"
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
for s in (d.get('secrets') or []):
    if s.get('name') == target:
        sec = s.get('secret') or {}
        print(sec.get('key') or '')
        break
" "$CONFIG" "$name" 2>/dev/null
}

# --- Read one user's scope list (one scope name per line) ---
read_user_scopes() {
    local username="$1"
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
for u in (d.get('users') or []):
    if u.get('name') == target:
        for s in (u.get('scopes') or []):
            print(s)
        break
" "$CONFIG" "$username" 2>/dev/null
}

# --- Count users referencing a given scope ---
count_users_in_scope() {
    local scope="$1"
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
c = 0
for u in (d.get('users') or []):
    if target in (u.get('scopes') or []):
        c += 1
print(c)
" "$CONFIG" "$scope" 2>/dev/null
}

# --- List users referencing a given scope (one per line) ---
list_users_in_scope() {
    local scope="$1"
    python3 -c "
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
target = sys.argv[2]
for u in (d.get('users') or []):
    if target in (u.get('scopes') or []):
        print(u.get('name'))
" "$CONFIG" "$scope" 2>/dev/null
}

# --- Return the scope that currently owns a given canonical CIDR, or empty ---
# Canonical here means input is already normalized (e.g. 10.1.0.0/16, lowercase).
# Matches on canonical ip_network equality — two string variants that canonicalize
# to the same network compare equal. First match wins (scopes are unique by name,
# and the point of this helper is to enforce one-scope-per-prefix).
scope_owning_prefix() {
    local cidr="$1"
    [[ -n "$cidr" ]] || return 0
    python3 - "$CONFIG" "$cidr" <<'PY' 2>/dev/null
import yaml, json, ipaddress, re, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
try:
    target = ipaddress.ip_network(sys.argv[2], strict=False)
except ValueError:
    sys.exit(0)
for s in (d.get('secrets') or []):
    name = s.get('name')
    pfx = (s.get('options') or {}).get('prefixes') or ''
    try:
        arr = json.loads(pfx) if pfx else []
    except Exception:
        arr = re.findall(r'"([^"]+)"', pfx)
    for c in arr:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        if n == target:
            print(name)
            sys.exit(0)
PY
}

# --- Reorder secrets: entries globally by prefix specificity ---
# Tacquito walks the secrets: slice in YAML order and returns the first
# provider whose prefix contains the client IP (loader.go:212-220). To get
# "narrowest wins" across scopes, we emit one entry per (scope, prefix) and
# sort every entry by its single prefix's (version, broadcast, network)
# key ascending. v4 before v6; smaller broadcast first (= narrower / more
# specific / subnets above supernets); network address tiebreaks.
#
# Assumes flat form — one prefix per entry (enforced by flatten_secrets_if_needed
# and by the add/set writers). Entries without a parseable prefix sort last.
# Idempotent; no-op when already in order.
reorder_secrets_by_prefix_specificity() {
    python3 - "$CONFIG" <<'PY'
import re, sys, tempfile, os, ipaddress
path = sys.argv[1]
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.exit(0)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)
lead, entries = [], []
for ch in chunks:
    if re.search(r'^  -\s+name:\s*\S+', ch, re.MULTILINE):
        entries.append(ch)
    else:
        lead.append(ch)

SENTINEL = (99, 2**128, 2**128)

def chunk_key(ch):
    pm = re.search(r'prefixes:\s*\|\s*\n\s*\[(.*?)\]', ch, re.DOTALL)
    if not pm:
        return SENTINEL
    cidrs = re.findall(r'"([^"]+)"', pm.group(1))
    # Under flat emission each chunk has exactly one prefix. Take the first
    # if we somehow see more (pre-flatten state): behaves as before (min).
    best = None
    for c in cidrs:
        try:
            n = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        k = (n.version, int(n.broadcast_address), int(n.network_address))
        if best is None or k < best:
            best = k
    return best if best is not None else SENTINEL

entries.sort(key=chunk_key)
new_body = ''.join(lead) + ''.join(entries)
if new_body == body:
    sys.exit(0)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- One-time migration: flatten multi-prefix entries to one entry per prefix ---
# Any `secrets:` entry with more than one prefix is split into N entries, all
# sharing the original name + secret.key + handler + type + options skeleton,
# each carrying one prefix. After splitting, the global specificity sort is
# applied so the on-disk order matches tacquito's first-match walk.
#
# Called at install-time (after template copy) and upgrade-time. Idempotent.
flatten_secrets_if_needed() {
    python3 - "$CONFIG" <<'PY'
import re, sys, tempfile, os
path = sys.argv[1]
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.exit(0)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)
lead, entries = [], []
for ch in chunks:
    if re.search(r'^  -\s+name:\s*\S+', ch, re.MULTILINE):
        entries.append(ch)
    else:
        lead.append(ch)

def split_entry(ch):
    # Extract the prefix list and the surrounding template.
    pm = re.search(r'(prefixes:\s*\|\s*\n\s*\[)(.*?)(\])', ch, re.DOTALL)
    if not pm:
        return [ch]  # no prefixes block — leave as-is
    cidrs = re.findall(r'"([^"]+)"', pm.group(2))
    if len(cidrs) <= 1:
        return [ch]  # already flat (or empty)
    pre, _, post = ch[:pm.start(2)], pm.group(2), ch[pm.end(3):]
    out = []
    for c in cidrs:
        new_list = f'\n          "{c}"\n        '
        # Reassemble: `prefixes: |\n        [` + new_list + `]` + post
        new_chunk = pre + new_list + pm.group(3) + post
        out.append(new_chunk)
    return out

flat = []
changed = False
for e in entries:
    parts = split_entry(e)
    if len(parts) != 1:
        changed = True
    flat.extend(parts)

if not changed:
    sys.exit(0)

new_body = ''.join(lead) + ''.join(flat)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
    # Apply specificity sort in a second pass; cheap and idempotent.
    reorder_secrets_by_prefix_specificity
}

# --- Write: replace every entry for a scope with one-per-prefix chunks ---
# Flat emission: remove every secrets[] entry whose name matches <scope>,
# then insert a fresh chunk per prefix in <csv>, all sharing the scope's
# existing key + the standard handler/type skeleton. Key is read from the
# first existing entry before deletion. Empty csv deletes the scope from
# the secrets block entirely (callers should gate this via the user-ref
# guard for non-destructive semantics).
set_scope_prefixes() {
    local scope="$1"
    local csv="$2"
    python3 - "$CONFIG" "$scope" "$csv" <<'PY'
import re, sys, tempfile, os, ipaddress
path, scope, csv = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = open(path).read()

raw = [c.strip() for c in csv.split(',') if c.strip()]
nets = []
seen = set()
for c in raw:
    try:
        n = ipaddress.ip_network(c, strict=False)
    except ValueError:
        continue
    if n in seen:
        continue
    seen.add(n)
    nets.append(n)
nets.sort(key=lambda n: (n.version, int(n.broadcast_address), int(n.network_address)))

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.stderr.write("no secrets: block\n")
    sys.exit(1)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)

# Preserve the first matching chunk's key (invariant: all entries for a scope
# share the same key). Also capture lead (non-entry) chunks to keep leading
# whitespace / comments.
existing_key = None
lead, other_entries = [], []
for ch in chunks:
    if re.search(r'^  -\s+name:\s*' + re.escape(scope) + r'\s*$', ch, re.MULTILINE):
        if existing_key is None:
            km = re.search(r'key:\s*"([^"]*)"', ch)
            if km:
                existing_key = km.group(1)
        continue  # drop this chunk
    if re.search(r'^  -\s+name:\s*\S+', ch, re.MULTILINE):
        other_entries.append(ch)
    else:
        lead.append(ch)

if existing_key is None:
    sys.stderr.write(f"scope '{scope}' not found\n")
    sys.exit(1)

def build_entry(name, key, cidr):
    return (
        f'  - name: {name}\n'
        f'    secret:\n'
        f'      group: tacquito\n'
        f'      key: "{key}"\n'
        f'    handler:\n'
        f'      type: *handler_type_start\n'
        f'    type: *provider_type_prefix\n'
        f'    options:\n'
        f'      prefixes: |\n'
        f'        [\n'
        f'          "{cidr}"\n'
        f'        ]\n'
    )

new_entries = [build_entry(scope, existing_key, str(n)) for n in nets]
new_body = ''.join(lead) + ''.join(other_entries) + ''.join(new_entries)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Write: replace shared-secret key on every entry whose name matches ---
# Flat emission spreads one logical scope across N entries; every one of
# them must carry the same key. A single-match update would leave the
# scope's other entries on the old key — auth would then non-deterministically
# succeed or fail depending on which (scope, prefix) entry tacquito matched
# first.
set_scope_secret() {
    local scope="$1"
    local value="$2"
    # Keep the secret off argv AND off the environment — both leak via /proc
    # (cmdline and environ) and via `ps e`. Pass the value through an
    # anonymous pipe via process substitution: /proc/<pid>/cmdline sees only
    # the ephemeral /dev/fd/N path, not the content, and the content is
    # scoped to this python subprocess (no other process inherits it).
    # Stdin stays free for the heredoc that carries the script.
    python3 - "$CONFIG" "$scope" <(printf '%s' "$value") <<'PY'
import re, sys, tempfile, os
path, scope, secret_path = sys.argv[1], sys.argv[2], sys.argv[3]
with open(secret_path) as f:
    value = f.read()
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.stderr.write("no secrets: block\n")
    sys.exit(1)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)
updated = 0
for i, ch in enumerate(chunks):
    if re.search(r'^  -\s+name:\s*' + re.escape(scope) + r'\s*$', ch, re.MULTILINE):
        new_ch, n = re.subn(
            r'(key:\s*")[^"]*(")',
            lambda _m: _m.group(1) + value + _m.group(2),
            ch, count=1,
        )
        if n > 0:
            chunks[i] = new_ch
            updated += 1
if updated == 0:
    sys.stderr.write(f"scope '{scope}' not found\n")
    sys.exit(1)

new_body = ''.join(chunks)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Add a new scope to the secrets: list (flat form) ---
# Emits one entry per prefix, all with the same name + key. Entries are
# appended at the end; the caller is expected to run
# reorder_secrets_by_prefix_specificity afterward so the global slice
# order matches the first-match-wins invariant.
add_scope() {
    local name="$1"
    local prefixes_csv="$2"  # canonical + validated by caller
    local secret_key="$3"
    # Secret goes through /dev/fd via process substitution; argv only carries
    # the ephemeral fd path. Protects /proc/<pid>/cmdline from the raw key.
    python3 - "$CONFIG" "$name" "$prefixes_csv" <(printf '%s' "$secret_key") <<'PY'
import re, sys, tempfile, os, ipaddress
path, name, pfx_csv, secret_path = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
with open(secret_path) as f:
    secret_key = f.read()
cfg = open(path).read()

raw = [c.strip() for c in pfx_csv.split(',') if c.strip()]
nets = []
seen = set()
for c in raw:
    try:
        n = ipaddress.ip_network(c, strict=False)
    except ValueError:
        continue
    if n in seen:
        continue
    seen.add(n)
    nets.append(n)
nets.sort(key=lambda n: (n.version, int(n.broadcast_address), int(n.network_address)))

def build_entry(cidr):
    return (
        f'  - name: {name}\n'
        f'    secret:\n'
        f'      group: tacquito\n'
        f'      key: "{secret_key}"\n'
        f'    handler:\n'
        f'      type: *handler_type_start\n'
        f'    type: *provider_type_prefix\n'
        f'    options:\n'
        f'      prefixes: |\n'
        f'        [\n'
        f'          "{cidr}"\n'
        f'        ]\n'
    )

entry_block = ''.join(build_entry(str(n)) for n in nets)

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    new_cfg = cfg.rstrip() + '\n\nsecrets:\n' + entry_block
else:
    header, body = m.group(1), m.group(2)
    if body.endswith('\n') and not body.endswith('\n\n'):
        new_body = body + entry_block
    else:
        new_body = body.rstrip('\n') + '\n' + entry_block
    new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Delete every entry whose name matches (flat form may span N chunks) ---
remove_scope() {
    local name="$1"
    python3 - "$CONFIG" "$name" <<'PY'
import re, sys, tempfile, os
path, name = sys.argv[1], sys.argv[2]
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.exit(0)
header, body = m.group(1), m.group(2)

chunks = re.split(r'(?=^  - )', body, flags=re.MULTILINE)
new_chunks = []
dropped = 0
for ch in chunks:
    if re.search(r'^  -\s+name:\s*' + re.escape(name) + r'\s*$', ch, re.MULTILINE):
        dropped += 1
        continue
    new_chunks.append(ch)

if dropped == 0:
    sys.stderr.write(f"scope '{name}' not found\n")
    sys.exit(1)

new_body = ''.join(new_chunks)
new_cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Rename every matching entry + rewrite every user's scopes: reference ---
# Global re_sub in the secrets block covers all flat chunks that share the
# old name; a single count=1 substitution would leave stragglers behind.
rename_scope() {
    local old_name="$1"
    local new_name="$2"
    python3 - "$CONFIG" "$old_name" "$new_name" <<'PY'
import re, sys, tempfile, os
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = open(path).read()

m = re.search(r'^(secrets:\s*\n)(.*?)(?=^\S|\Z)', cfg, re.MULTILINE | re.DOTALL)
if not m:
    sys.stderr.write("no secrets: block\n")
    sys.exit(1)
header, body = m.group(1), m.group(2)
new_body, n = re.subn(
    r'^(  -\s+name:\s*)' + re.escape(old) + r'(\s*)$',
    r'\g<1>' + new + r'\2',
    body, flags=re.MULTILINE,
)
if n == 0:
    sys.stderr.write(f"scope '{old}' not found\n")
    sys.exit(1)

cfg = cfg[:m.start()] + header + new_body + cfg[m.end():]

# Update every user's scopes: list — only the old name is replaced.
def repl(match):
    inside = match.group(1)
    items = re.findall(r'"([^"]+)"', inside)
    items = [new if it == old else it for it in items]
    return 'scopes: [' + ', '.join(f'"{it}"' for it in items) + ']'
cfg = re.sub(r'scopes:\s*\[([^\]]*)\]', repl, cfg)

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Replace one user's scopes: field with a new CSV ---
set_user_scopes() {
    local username="$1"
    local csv="$2"  # comma-separated scope names; empty wipes to []
    python3 - "$CONFIG" "$username" "$csv" <<'PY'
import re, sys, tempfile, os
path, username, csv = sys.argv[1], sys.argv[2], sys.argv[3]
cfg = open(path).read()

items = [c.strip() for c in csv.split(',') if c.strip()]
new_line = 'scopes: [' + ', '.join(f'"{s}"' for s in items) + ']'

# Find the user entry and replace its scopes: line.
# User entry shape:
#   - name: <username>\n    scopes: [...]\n    groups: [...]\n    ...
# Scope to that user's block before doing the scopes: replace.
pattern = re.compile(
    r'(-\s+name:\s*' + re.escape(username) + r'\s*\n(?:\s+[^\n]*\n)*?\s+)scopes:\s*\[[^\]]*\]',
)
new_cfg, n = pattern.subn(r'\1' + new_line.replace('\\', r'\\'), cfg, count=1)
if n == 0:
    # User exists but has no scopes: field — insert one immediately after `- name:`
    ins_pattern = re.compile(r'(-\s+name:\s*' + re.escape(username) + r'\s*\n)(\s+)')
    im = ins_pattern.search(cfg)
    if not im:
        sys.stderr.write(f"user '{username}' not found\n")
        sys.exit(1)
    indent = im.group(2)
    new_cfg = cfg[:im.end(1)] + indent + new_line + '\n' + cfg[im.end(2):]

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(path), delete=False)
tmp.write(new_cfg)
tmp.close()
os.rename(tmp.name, path)
PY
}

# --- Read the secret-provider prefixes (one canonical CIDR per line) ---
# Canonicalizes each entry on read so dedup comparisons and display are
# representation-agnostic regardless of how the YAML was last written.
# --- Echo the canonical string form of a CIDR (or empty on invalid) ---
# IPv4: `10.1.5.5/24` → `10.1.5.0/24` (host bits zeroed).
# IPv6: `2001:DB8::/32` → `2001:db8::/32` (lower-cased, compressed).
# Used to dedup equivalent representations and give YAML storage a
# single canonical representation.
canonicalize_cidr() {
    python3 -c "
import ipaddress, sys
try:
    n = ipaddress.ip_network(sys.argv[1], strict=False)
    print(n)
except (ValueError, IndexError):
    pass
" "$1" 2>/dev/null
}

# --- Sort a newline-separated CIDR list by specificity (most-specific first) ---
# Tie-break: IPv4 before IPv6, then numeric network address ascending.
# Non-CIDR input lines are dropped silently (caller should validate first).
sort_cidrs_by_specificity() {
    python3 -c "
import ipaddress, sys
lines = sys.stdin.read().splitlines()
def key(c):
    n = ipaddress.ip_network(c, strict=False)
    return (n.version, int(n.broadcast_address), int(n.network_address))
valid = []
for line in lines:
    s = line.strip()
    if not s:
        continue
    try:
        ipaddress.ip_network(s, strict=False)
        valid.append(s)
    except ValueError:
        continue
for c in sorted(valid, key=key):
    print(c)
"
}

# --- Parse a comma-separated CIDR list into newline-separated output ---
# Validates every entry (aborts on invalid). Trims whitespace. Canonicalizes
# each entry (host bits stripped, IPv6 lower-cased). Dedupes within the
# input on the canonical form. Empty input → empty output.
# Order matches input order (dedupe preserves first occurrence); callers
# that need sort-by-specificity apply it downstream at write time.
parse_cidr_list() {
    local input="$1"
    local seen=""
    local cidr canonical
    IFS=',' read -ra CIDRS <<< "$input"
    for cidr in "${CIDRS[@]}"; do
        cidr=$(echo "$cidr" | xargs)
        [[ -z "$cidr" ]] && continue
        validate_cidr "$cidr"
        canonical=$(canonicalize_cidr "$cidr")
        [[ -z "$canonical" ]] && continue  # validate_cidr already errored; defensive
        # within-input dedupe on canonical form
        if ! printf '%s\n' "$seen" | grep -qxF "$canonical"; then
            seen+="${seen:+$'\n'}${canonical}"
        fi
    done
    echo "$seen"
}

# --- Legacy 'config prefixes' — REMOVED ---
# Scope-owned prefixes now live under 'tacctl scopes prefixes <name>'.
# This stub prints an explicit redirect so muscle-memory and scripted
# callers learn where to go instead of hitting a generic dispatcher
# error. It does not mutate state.
cmd_config_prefixes() {
    error "'tacctl config prefixes' was removed in this release."
    error "Scope-owned prefixes now live under 'tacctl scopes':"
    error "  tacctl scopes prefixes <name> list"
    error "  tacctl scopes prefixes <name> add    <cidr>[,<cidr>...]"
    error "  tacctl scopes prefixes <name> remove <cidr>[,<cidr>...]"
    error "  tacctl scopes prefixes <name> clear"
    error ""
    error "Default scope: $(read_default_scope || echo '(unset)')"
    error "Available:     $(list_scopes | paste -sd' ')"
    exit 2
}

# --- CONFIG CISCO (show working device config) ---
cmd_config_cisco() {
    # Parse --scope <name>
    local scope=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scope)
                scope="${2:-}"
                [[ -z "$scope" ]] && { error "Usage: tacctl config cisco [--scope <name>]"; exit 1; }
                shift 2
                ;;
            *)
                error "Unknown argument: '$1'"
                error "Usage: tacctl config cisco [--scope <name>]"
                exit 1
                ;;
        esac
    done
    if [[ -z "$scope" ]]; then
        scope=$(read_default_scope)
        if [[ -z "$scope" ]]; then
            error "No default scope set and no --scope provided."
            error "Run 'tacctl scopes default <name>' or pass --scope <name>."
            exit 1
        fi
    elif ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi
    local secret server_ip
    secret=$(read_scope_secret "$scope")
    server_ip=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -z "$server_ip" ]]; then
        server_ip="<TACQUITO_SERVER_IP>"
    fi

    # Compute "other scopes" list for the header.
    local other_scopes
    other_scopes=$(list_scopes | grep -vxF "$scope" | paste -sd,)

    # Collect all groups with their priv-lvl
    local group_info
    group_info=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
groups_match = re.search(r'^# --- Groups ---\s*\n(.*?)(?=^# --- Users|\Z)', config, re.MULTILINE | re.DOTALL)
if not groups_match:
    sys.exit(0)
for m in re.finditer(r'^(\w+): &\1\n  name: \1\n  services:\n(.*?)  accounter:', groups_match.group(1), re.MULTILINE | re.DOTALL):
    name = m.group(1)
    pm = re.search(r'\*exec_(\w+)', m.group(2))
    if pm:
        svc = pm.group(1)
        sm = re.search(r'exec_' + svc + r':.*?values:\s*\[(\d+)\]', config, re.DOTALL)
        if sm:
            print(f'{name}|{sm.group(1)}')
" "$CONFIG")

    # Build the privilege-exec block from per-group mappings
    # (managed via 'tacctl group privilege'). For each group with priv-lvl
    # in 2-14, emit either its explicit mappings or a conservative built-in
    # default (move-DOWN commands only). De-dupe across multiple groups
    # sharing the same priv-lvl: IOS only needs one line per (level, cmd).
    local PRIVILEGE_COMMANDS=""
    local seen_pairs=""
    while IFS='|' read -r gname privlvl; do
        [[ -z "$gname" ]] && continue
        [[ "$privlvl" == "1" || "$privlvl" == "15" ]] && continue
        local cmds explicit
        explicit=$(read_group_privileges "$gname")
        if [[ -n "$explicit" ]]; then
            cmds="$explicit"
        else
            cmds=$(default_privileges_for_group "$gname")
        fi
        [[ -z "$cmds" ]] && continue
        local block_for_group="! --- ${gname} — Privilege Level ${privlvl} Commands ---"$'\n'
        local emitted_any="false"
        while IFS= read -r cmd; do
            [[ -z "$cmd" ]] && continue
            local pair="${privlvl}|${cmd}"
            # Dedup across groups sharing the same priv-lvl.
            if printf '%s\n' "$seen_pairs" | grep -qxF "$pair"; then
                continue
            fi
            seen_pairs+="${pair}"$'\n'
            block_for_group+="privilege exec level ${privlvl} ${cmd}"$'\n'
            emitted_any="true"
        done <<< "$cmds"
        if [[ "$emitted_any" == "true" ]]; then
            PRIVILEGE_COMMANDS+="${block_for_group}!"$'\n'
        fi
    done <<< "$group_info"

    local GROUP_SUMMARY=""
    while IFS='|' read -r gname privlvl; do
        [[ -z "$gname" ]] && continue
        GROUP_SUMMARY+="  ${gname}: priv-lvl ${privlvl}"$'\n'
    done <<< "$group_info"

    # Build the VTY-ACL block from the shared mgmt-acl list. IPv6 CIDRs
    # (if any) are skipped here — v6 would need an `ipv6 access-list`
    # and is not yet supported.
    #
    # Empty-list intentionally emits NO access-list (and a commented-out
    # access-class below). Emitting a placeholder permit was misleading:
    # pasting the output silently installed a bogus permit the operator
    # didn't configure. Comments are no-ops on IOS, so the empty-state
    # output is still safe to paste — it simply leaves the vty lines
    # unchanged until mgmt-acl is populated.
    local cisco_acl_name
    cisco_acl_name=$(read_mgmt_acl_name cisco)

    # Per-command authorization: emit `aaa authorization commands N`
    # only when at least one group has a commands: section in the YAML.
    # Without that gate, devices would still log normally; with it, IOS
    # asks tacquito for every command at each priv-lvl.
    local AUTHZ_COMMANDS_BLOCK=""
    if any_group_has_commands; then
        AUTHZ_COMMANDS_BLOCK="! Per-command authorization (managed by 'tacctl group commands').
aaa authorization commands 1 default group TACACS-GROUP local
aaa authorization commands 7 default group TACACS-GROUP local
aaa authorization commands 15 default group TACACS-GROUP local"
    else
        AUTHZ_COMMANDS_BLOCK="! Per-command authorization not enabled.
! To restrict commands per group, use 'tacctl group commands'."
    fi

    local VTY_ACL_BLOCK VTY_ACCESS_CLASS mgmt_entries=""
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        local wildcard
        wildcard=$(cidr_to_cisco_wildcard "$entry")
        if [[ -n "$wildcard" ]]; then
            mgmt_entries+="  permit ${wildcard}"$'\n'
        fi
    done < <(read_mgmt_acl_cidrs)
    if [[ -n "$mgmt_entries" ]]; then
        VTY_ACL_BLOCK="ip access-list standard ${cisco_acl_name}
  remark Managed by tacctl — edit with 'tacctl config mgmt-acl'
${mgmt_entries}  deny   any log"
        VTY_ACCESS_CLASS="  access-class ${cisco_acl_name} in"
    else
        VTY_ACL_BLOCK="! ${cisco_acl_name} not emitted — mgmt-acl list is empty.
! Populate it on the tacquito server with
!   tacctl config mgmt-acl add <cidr>
! then re-run 'tacctl config cisco' to get the access-list block."
        VTY_ACCESS_CLASS="! access-class ${cisco_acl_name} in   ! uncomment after populating mgmt-acl"
    fi

    echo ""
    echo -e "${BOLD}Cisco IOS / IOS-XE Configuration${NC}  (scope: ${scope})"
    if [[ -n "$other_scopes" ]]; then
        echo -e "${YELLOW}(other scopes: ${other_scopes} — use --scope <name> to emit those)${NC}"
    fi
    echo -e "${YELLOW}Copy and paste into the device:${NC}"
    echo "--------------------------------------------"
    echo ""

    local template_file
    template_file=$(resolve_template "cisco")
    # Filter the device-config emission through `awk 'NF'` so blank
    # lines introduced by multi-line `${VAR}` substitution don't reach
    # the operator. `!` separator lines have NF=1 so they survive.
    {
        if [[ -n "$template_file" ]]; then
            export SERVER_IP="$server_ip" SECRET="$secret" PRIVILEGE_COMMANDS GROUP_SUMMARY VTY_ACL_BLOCK VTY_ACCESS_CLASS AUTHZ_COMMANDS_BLOCK
            envsubst '${SERVER_IP} ${SECRET} ${PRIVILEGE_COMMANDS} ${GROUP_SUMMARY} ${VTY_ACL_BLOCK} ${VTY_ACCESS_CLASS} ${AUTHZ_COMMANDS_BLOCK}' < "$template_file"
        else
            cat <<EOF
! --- TACACS+ Server & AAA ---
service password-encryption
!
aaa new-model
!
! Optional: pin TACACS+ client to a known source interface.
! Uncomment and replace with your management interface, e.g.:
! ip tacacs source-interface Loopback0
!
tacacs server TACACS
  address ipv4 ${server_ip}
  key ${secret}
  single-connection
  timeout 5
!
aaa group server tacacs+ TACACS-GROUP
  server name TACACS
!
aaa authentication login default group TACACS-GROUP local
aaa authorization exec default group TACACS-GROUP local if-authenticated
aaa accounting exec default start-stop group TACACS-GROUP
aaa accounting commands 1 default start-stop group TACACS-GROUP
aaa accounting commands 7 default start-stop group TACACS-GROUP
aaa accounting commands 15 default start-stop group TACACS-GROUP
!
${AUTHZ_COMMANDS_BLOCK}
!
${PRIVILEGE_COMMANDS}
${VTY_ACL_BLOCK}
!
line con 0
  login authentication default
  exec-timeout 60 0
!
line vty 0 15
  login authentication default
  transport input ssh
${VTY_ACCESS_CLASS}
  exec-timeout 60 0
EOF
        fi
    } | awk 'NF'

    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → Privilege Level Mapping:${NC}"
    echo -n "$GROUP_SUMMARY"
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - The 'local' fallback ensures access if TACACS+ is unreachable"
    echo "  - Ensure a local admin account exists as a backup"
    echo "  - Uncomment 'ip tacacs source-interface ...' to pin the TACACS+ client source"
    echo "  - ${cisco_acl_name} permits are managed with 'tacctl config mgmt-acl add <cidr>'"
    echo "  - For Type 6 (AES) key encryption, run on the device first:"
    echo "      conf t ; key config-key password-encrypt <master-key>"
    echo "      password encryption aes"
    echo "    then re-enter the tacacs key. (Type 7 is trivially reversible.)"
    echo "  - Manage 'privilege exec level' mappings with 'tacctl group privilege add ...'"
    echo "    (defaults move only the verified priv-15 commands DOWN; nothing is moved UP)"
    if [[ -n "$template_file" ]]; then
        echo "  - Using template: ${template_file}"
    fi
    echo ""
}

# --- CONFIG JUNIPER (show working device config) ---
cmd_config_juniper() {
    # Parse --scope <name>
    local scope=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --scope)
                scope="${2:-}"
                [[ -z "$scope" ]] && { error "Usage: tacctl config juniper [--scope <name>]"; exit 1; }
                shift 2
                ;;
            *)
                error "Unknown argument: '$1'"
                error "Usage: tacctl config juniper [--scope <name>]"
                exit 1
                ;;
        esac
    done
    if [[ -z "$scope" ]]; then
        scope=$(read_default_scope)
        if [[ -z "$scope" ]]; then
            error "No default scope set and no --scope provided."
            error "Run 'tacctl scopes default <name>' or pass --scope <name>."
            exit 1
        fi
    elif ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist. Available: $(list_scopes | paste -sd' ')"
        exit 1
    fi
    local secret server_ip
    secret=$(read_scope_secret "$scope")
    server_ip=$(ip -4 route get 1.0.0.0 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')
    if [[ -z "$server_ip" ]]; then
        server_ip="<TACQUITO_SERVER_IP>"
    fi

    # Compute "other scopes" list for the header.
    local other_scopes
    other_scopes=$(list_scopes | grep -vxF "$scope" | paste -sd,)

    # Collect all groups with their Juniper class and suggested Junos login class
    local group_juniper
    group_juniper=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
groups_match = re.search(r'^# --- Groups ---\s*\n(.*?)(?=^# --- Users|\Z)', config, re.MULTILINE | re.DOTALL)
if not groups_match:
    sys.exit(0)
for m in re.finditer(r'^(\w+): &\1\n  name: \1\n  services:\n(.*?)  accounter:', groups_match.group(1), re.MULTILINE | re.DOTALL):
    name = m.group(1)
    jm = re.search(r'\*junos_exec_(\w+)', m.group(2))
    if jm:
        svc = jm.group(1)
        jcm = re.search(r'junos_exec_' + svc + r':.*?values:\s*\[\"([^\"]+)\"\]', config, re.DOTALL)
        if jcm:
            jclass = jcm.group(1)
            # Suggest a Junos login class based on group name
            if 'super' in name or 'admin' in name:
                junos_class = 'super-user'
            elif 'readonly' in name or 'read' in name:
                junos_class = 'read-only'
            else:
                junos_class = 'operator'
            print(f'{name}|{jclass}|{junos_class}')
" "$CONFIG")

    # Build dynamic sections
    local TEMPLATE_USERS=""
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        TEMPLATE_USERS+="set system login user ${jclass} class ${junos_class}"$'\n'
    done <<< "$group_juniper"
    TEMPLATE_USERS="${TEMPLATE_USERS%$'\n'}"

    local TACPLUS_CONFIG
    # `delete` first because Junos `set ... authentication-order` is
    # additive against an existing ordered list.
    # source-address pins the client source IP so prefix-based ACLs on
    # tacquito have a stable match. Emitted as a commented example —
    # pasting <MGMT_IP> literally fails; the operator must substitute
    # the device's management interface address (e.g. lo0 or fxp0).
    TACPLUS_CONFIG="delete system authentication-order
set system authentication-order [ tacplus password ]
set system tacplus-server ${server_ip} secret ${secret}
set system tacplus-server ${server_ip} single-connection
# Optional: pin client source IP for prefix-ACL matching on tacquito.
# Replace 10.0.0.1 with the device's management interface address, e.g.:
#   set system tacplus-server ${server_ip} source-address 10.0.0.1
set system accounting events [ login change-log interactive-commands ]
set system accounting destination tacplus"

    # Build the Juniper mgmt-acl block from the shared permit list.
    # When populated, emit live `set firewall …` commands so the filter
    # gets created in the candidate config on paste. The `set interfaces
    # lo0 … filter input` APPLY line stays commented, because that is
    # where the blackhole risk lives — an unreviewed lo0 filter can drop
    # BGP / OSPF / IS-IS to the RE. Defining the filter without applying
    # it is safe; the operator uncomments the apply line after review.
    # IPv6 CIDRs are skipped for now (filter would need family inet6).
    local juniper_acl_name
    juniper_acl_name=$(read_mgmt_acl_name juniper)
    local MGMT_ACL_BLOCK mgmt_terms=""
    local mgmt_has_any="false"
    while IFS= read -r entry; do
        [[ -z "$entry" ]] && continue
        # Skip v6 — family inet filter only accepts v4 source-addresses.
        [[ "$entry" == *:* ]] && continue
        mgmt_has_any="true"
        mgmt_terms+="set firewall family inet filter ${juniper_acl_name} term permit-mgmt from source-address ${entry}"$'\n'
    done < <(read_mgmt_acl_cidrs)
    if [[ "$mgmt_has_any" == "true" ]]; then
        MGMT_ACL_BLOCK="# Restrict SSH / NETCONF to the configured mgmt subnets.
# These 'set firewall' lines define the filter in the candidate config.
# Activate it by uncommenting the 'set interfaces lo0 …' line below
# after reviewing — a misapplied lo0 filter can blackhole BGP / OSPF /
# IS-IS to the RE.
${mgmt_terms}set firewall family inet filter ${juniper_acl_name} term permit-mgmt from protocol tcp
set firewall family inet filter ${juniper_acl_name} term permit-mgmt from destination-port [ ssh 830 ]
set firewall family inet filter ${juniper_acl_name} term permit-mgmt then accept
set firewall family inet filter ${juniper_acl_name} term deny-mgmt from protocol tcp
set firewall family inet filter ${juniper_acl_name} term deny-mgmt from destination-port [ ssh 830 ]
set firewall family inet filter ${juniper_acl_name} term deny-mgmt then { log; discard; }
set firewall family inet filter ${juniper_acl_name} term default-accept then accept
#
# Apply (review first):
# set interfaces lo0 unit 0 family inet filter input ${juniper_acl_name}"
    else
        MGMT_ACL_BLOCK="# mgmt-acl empty — configure with 'tacctl config mgmt-acl add <cidr>' on the tacquito server
# to emit a source-restricted lo0 firewall filter here."
    fi

    local VERIFY_COMMANDS
    VERIFY_COMMANDS="  show configuration system tacplus-server
  show configuration system authentication-order"
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        VERIFY_COMMANDS+=$'\n'"  show configuration system login user ${jclass}"
    done <<< "$group_juniper"

    local GROUP_SUMMARY=""
    while IFS='|' read -r gname jclass junos_class; do
        [[ -z "$gname" ]] && continue
        GROUP_SUMMARY+="  ${gname}: ${jclass} (${junos_class})"$'\n'
    done <<< "$group_juniper"

    # Build the per-class allow-commands / deny-commands block from
    # group commands rules (managed via 'tacctl group commands').
    # Junos enforces these patterns LOCALLY on each device, not via
    # TACACS+ — a config push is required after every change.
    #
    # v1 simplification: per-rule `match` regexes are dropped. Each
    # rule's `name` becomes part of an aggregated regex. Operators
    # needing finer control should hand-edit the Junos class
    # afterwards.
    local CLASS_COMMAND_RULES=""
    if any_group_has_commands; then
        CLASS_COMMAND_RULES="# Per-command authorization (enforced LOCALLY by Junos, not via TACACS+).
# Push these on every device after 'tacctl group commands' changes."$'\n'
        while IFS='|' read -r gname jclass junos_class; do
            [[ -z "$gname" ]] && continue
            local rules
            rules=$(read_group_commands "$gname")
            [[ -z "$rules" ]] && continue
            local permit_names="" deny_names="" rule_default
            rule_default=$(read_group_default_action "$gname")
            while IFS='|' read -r rname raction rmatch; do
                [[ -z "$rname" || "$rname" == "*" ]] && continue
                if [[ "$raction" == "permit" ]]; then
                    permit_names+="${permit_names:+|}${rname}"
                else
                    deny_names+="${deny_names:+|}${rname}"
                fi
            done <<< "$rules"
            CLASS_COMMAND_RULES+="# class '${jclass}' (group '${gname}', default ${rule_default})"$'\n'
            if [[ -n "$permit_names" ]]; then
                CLASS_COMMAND_RULES+="set system login class ${jclass} allow-commands \"^(${permit_names})( .*)?\$\""$'\n'
            fi
            if [[ -n "$deny_names" ]]; then
                CLASS_COMMAND_RULES+="set system login class ${jclass} deny-commands \"^(${deny_names})( .*)?\$\""$'\n'
            fi
            if [[ "$rule_default" == "deny" && -z "$permit_names" ]]; then
                CLASS_COMMAND_RULES+="# Default action is 'deny' but no allow-commands set —"$'\n'
                CLASS_COMMAND_RULES+="# this class will be unable to run anything. Add explicit"$'\n'
                CLASS_COMMAND_RULES+="# permits with 'tacctl group commands add ${gname} <name> --action permit'."$'\n'
            fi
        done <<< "$group_juniper"
        # Trim trailing newline so envsubst doesn't double-blank.
        CLASS_COMMAND_RULES="${CLASS_COMMAND_RULES%$'\n'}"
    else
        CLASS_COMMAND_RULES="# Per-command authorization not configured.
# To restrict commands per group, use 'tacctl group commands' on the tacquito server."
    fi

    echo ""
    echo -e "${BOLD}Juniper Junos Configuration${NC}  (scope: ${scope})"
    if [[ -n "$other_scopes" ]]; then
        echo -e "${YELLOW}(other scopes: ${other_scopes} — use --scope <name> to emit those)${NC}"
    fi
    echo -e "${YELLOW}Copy and paste into the device (configure mode):${NC}"
    echo "--------------------------------------------"
    echo ""

    local template_file
    template_file=$(resolve_template "juniper")
    if [[ -n "$template_file" ]]; then
        export SERVER_IP="$server_ip" SECRET="$secret" TEMPLATE_USERS TACPLUS_CONFIG MGMT_ACL_BLOCK CLASS_COMMAND_RULES VERIFY_COMMANDS GROUP_SUMMARY
        envsubst '${SERVER_IP} ${SECRET} ${TEMPLATE_USERS} ${TACPLUS_CONFIG} ${MGMT_ACL_BLOCK} ${CLASS_COMMAND_RULES} ${VERIFY_COMMANDS} ${GROUP_SUMMARY}' < "$template_file"
    else
        echo "# Step 1: Create template users (REQUIRED)"
        echo "$TEMPLATE_USERS"
        echo ""
        echo "# Step 2: Configure TACACS+"
        echo "$TACPLUS_CONFIG"
        echo ""
        echo "# Step 3: (optional) Per-class command rules"
        echo "$CLASS_COMMAND_RULES"
        echo ""
        echo "# Step 4: (optional) Management ACL"
        echo "$MGMT_ACL_BLOCK"
        echo ""
        echo "# Step 5: Commit"
        echo "commit"
    fi

    echo ""
    echo "--------------------------------------------"
    echo -e "${YELLOW}Group → Juniper Class Mapping:${NC}"
    echo -n "$GROUP_SUMMARY"
    echo ""
    echo -e "${YELLOW}Notes:${NC}"
    echo "  - Template users MUST exist before TACACS+ logins will work"
    echo "  - The 'password' fallback in authentication-order ensures local access"
    echo "  - If a login fails silently, the template user is likely missing"
    echo "  - Adjust the Junos class (read-only/operator/super-user) as needed"
    echo "  - Uncomment and edit the source-address line to pin the client"
    echo "    source IP for prefix-ACL matching on tacquito"
    echo "  - Junos replaces the plaintext 'secret' with '\$9\$...' on commit,"
    echo "    but it sits in the candidate config until then — commit promptly"
    echo "    and protect the commit archive (/config/rescue.conf, juniper.conf.*)."
    if [[ -n "$template_file" ]]; then
        echo "  - Using template: ${template_file}"
    fi
    echo ""
    echo -e "${BOLD}Verify after commit:${NC}"
    echo "$VERIFY_COMMANDS"
    echo ""
}

# --- CONFIG BRANCH ---
cmd_config_branch() {
    local new_branch="${1:-}"

    if [[ ! -d "${DEPLOY_DIR}/.git" ]]; then
        error "Deploy directory not found at ${DEPLOY_DIR}."
        exit 1
    fi

    local current_branch
    current_branch=$(git -C "$DEPLOY_DIR" branch --show-current 2>/dev/null)

    if [[ -z "$new_branch" ]]; then
        echo ""
        echo -e "  ${BOLD}Current branch:${NC} ${current_branch}"
        echo ""
        echo "  Available remote branches:"
        git -C "$DEPLOY_DIR" fetch --quiet 2>/dev/null || true
        git -C "$DEPLOY_DIR" branch -r 2>/dev/null | grep -v HEAD | sed 's|origin/||' | while IFS= read -r b; do
            b=$(echo "$b" | xargs)
            if [[ "$b" == "$current_branch" ]]; then
                echo -e "    ${GREEN}* ${b}${NC}"
            else
                echo "      ${b}"
            fi
        done
        echo ""
        return
    fi

    if [[ "$new_branch" == "$current_branch" ]]; then
        info "Already on branch '${new_branch}'."
        return
    fi

    # Fetch and switch
    git -C "$DEPLOY_DIR" fetch --quiet 2>/dev/null || true
    if ! git -C "$DEPLOY_DIR" rev-parse --verify "origin/${new_branch}" &>/dev/null; then
        error "Branch '${new_branch}' does not exist on remote."
        exit 1
    fi

    git -C "$DEPLOY_DIR" checkout -- . 2>/dev/null || true
    git -C "$DEPLOY_DIR" checkout "$new_branch" &>/dev/null || git -C "$DEPLOY_DIR" checkout -b "$new_branch" "origin/${new_branch}" &>/dev/null
    git -C "$DEPLOY_DIR" pull --quiet 2>/dev/null || true
    chmod 755 "${DEPLOY_DIR}/bin/tacctl.sh"

    info "Switched to branch '${new_branch}'."
    info "Run 'tacctl upgrade' to apply any changes."
    echo ""
}

# --- CONFIG ALLOW/DENY PREFIX FILTERS ---
cmd_config_prefix_filter() {
    local key="$1"
    local subcmd="${2:-}"
    local cidr="${3:-}"
    local label
    [[ "$key" == "prefix_allow" ]] && label="allow" || label="deny"

    case "$subcmd" in
        ""|-h|--help|help)
            local entries
            entries=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^' + sys.argv[2] + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    print(len(re.findall(r'\"([^\"]+)\"', m.group(1))))
else:
    print(0)
" "$CONFIG" "$key" 2>/dev/null || echo 0)
            echo ""
            echo -e "${BOLD}tacctl config ${label}${NC} — connection IP ACL (${label} list)"
            echo ""
            echo "Usage:"
            echo "  tacctl config ${label} list                          Show current ${label} list"
            echo "  tacctl config ${label} add    <cidr>[,<cidr>...]     Add one or more CIDRs"
            echo "  tacctl config ${label} remove <cidr>[,<cidr>...]     Remove one or more CIDRs"
            echo "  tacctl config ${label} clear                         Wipe all (confirms)"
            echo ""
            echo "Current entries: ${entries}"
            echo "Note: 'deny' takes precedence over 'allow'. Both empty = all connections accepted."
            echo ""
            return
            ;;
        list)
            echo ""
            echo -e "${BOLD}Connection ${label} list${NC}"
            echo "--------------------------------------------"
            local entries
            entries=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^' + sys.argv[2] + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    for c in re.findall(r'\"([^\"]+)\"', m.group(1)):
        print(c)
else:
    print('EMPTY')
" "$CONFIG" "$key" || true)
            if [[ "$entries" == "EMPTY" ]]; then
                if [[ "$label" == "allow" ]]; then
                    echo "  (empty — all connections allowed)"
                else
                    echo "  (empty — no connections denied)"
                fi
            else
                echo "$entries" | while IFS= read -r entry; do
                    echo "  - ${entry}"
                done
            fi
            echo ""
            echo -e "  ${CYAN}Note: deny takes precedence over allow.${NC}"
            echo ""
            ;;
        add)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config ${label} add <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested added="" skipped=""
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_prefix_list "$key")
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    skipped+="${skipped:+ }${c}"
                else
                    added+="${added:+$'\n'}${c}"
                    current=$(printf '%s\n%s\n' "$current" "$c")
                fi
            done <<< "$requested"
            if [[ -z "$added" ]]; then
                info "No new CIDRs to add to ${label} list (already present: ${skipped})."
                echo ""
                return
            fi
            backup_config
            write_prefix_list "$key" "$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} to ${label} list: $(printf '%s\n' "$added" | paste -sd' ')"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            echo ""
            ;;
        remove)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config ${label} remove <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested removed="" missing=""
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_prefix_list "$key")
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    removed+="${removed:+$'\n'}${c}"
                    current=$(printf '%s\n' "$current" | grep -vxF "$c" || true)
                else
                    missing+="${missing:+ }${c}"
                fi
            done <<< "$requested"
            if [[ -z "$removed" ]]; then
                warn "Nothing to remove from ${label} list (not present: ${missing})."
                exit 0
            fi
            backup_config
            write_prefix_list "$key" "$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} from ${label} list: $(printf '%s\n' "$removed" | paste -sd' ')"
            [[ -n "$missing" ]] && info "(Not present, skipped: ${missing})"
            echo ""
            ;;
        clear)
            local current n
            current=$(read_prefix_list "$key")
            if [[ -z "$current" ]]; then
                info "${label} list is already empty."
                return
            fi
            n=$(printf '%s\n' "$current" | wc -l)
            # Clearing either list removes a restriction — be explicit
            # about what the resulting posture is.
            if [[ "$label" == "allow" ]]; then
                warn "Clearing the allow list fails open: all source IPs become eligible"
                warn "to connect (subject to 'deny' and the secret-provider prefixes)."
            else
                warn "Clearing the deny list removes all per-IP deny overrides;"
                warn "any source matching 'allow' (or all, if allow is empty) can connect."
            fi
            read -rp "  Clear all ${n} ${label}-list entr$( [[ $n -eq 1 ]] && echo "y" || echo "ies" )? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            backup_config
            write_prefix_list "$key" ""
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Cleared ${label} list (${n} entr$( [[ $n -eq 1 ]] && echo "y" || echo "ies" ) removed)."
            echo ""
            ;;
        *)
            echo ""
            echo "Usage: tacctl config ${label} <list|add|remove|clear> [cidr[,cidr...]]"
            echo ""
            exit 1
            ;;
    esac
}

# --- Read a prefix_allow / prefix_deny inline list (canonical CIDR per line) ---
read_prefix_list() {
    local key="$1"
    python3 -c "
import ipaddress, re, sys
config = open(sys.argv[1]).read()
m = re.search(r'^' + sys.argv[2] + r':\s*\[(.*?)\]', config, re.MULTILINE)
if m and m.group(1).strip():
    for c in re.findall(r'\"([^\"]+)\"', m.group(1)):
        try:
            print(ipaddress.ip_network(c, strict=False))
        except ValueError:
            print(c)
" "$CONFIG" "$key"
}

# --- Write/replace a prefix_allow / prefix_deny inline list ---
# csv may be empty — in that case the key line is removed entirely.
# Entries are canonicalized and sorted by specificity (most-specific
# prefix first) before being emitted, matching the storage convention
# used by set_secret_prefixes.
write_prefix_list() {
    local key="$1"
    local csv="$2"
    python3 -c "
import ipaddress, re, sys, tempfile, os
config = open(sys.argv[1]).read()
key = sys.argv[2]
raw = [c.strip() for c in sys.argv[3].split(',') if c.strip()]
# Canonicalize + sort by specificity
def key_fn(c):
    n = ipaddress.ip_network(c, strict=False)
    # Primary: version (v4 before v6). Secondary: broadcast address
    # ascending — disjoint ranges sort by end-of-range, and overlapping
    # subnets naturally fall just above their supernet (the subnet
    # ends earlier than the range containing it). Tertiary: network
    # address, for determinism across same-end-address edge cases.
    return (n.version, int(n.broadcast_address), int(n.network_address))
entries = []
for c in raw:
    try:
        entries.append(str(ipaddress.ip_network(c, strict=False)))
    except ValueError:
        pass
entries = sorted(set(entries), key=key_fn)
m = re.search(r'^' + key + r':\s*\[(.*?)\]', config, re.MULTILINE)
if entries:
    new_val = ', '.join('\"' + e + '\"' for e in entries)
    new_line = key + ': [' + new_val + ']'
    if m:
        config = config.replace(m.group(0), new_line)
    else:
        config = config.rstrip() + '\n\n' + new_line + '\n'
else:
    if m:
        config = config.replace(m.group(0) + '\n', '')
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG" "$key" "$csv"
}

# --- CONFIG MGMT-ACL (permit list for Cisco VTY-ACL + Juniper lo0 filter) ---
# Stored at $MGMT_ACL_FILE as a flat file (one CIDR per line). This is
# tacctl-internal — never read by tacquito — so no service restart is
# needed when the list changes. Survives upgrades because it lives
# outside the template tree that `tacctl upgrade` rewrites.
cmd_config_mgmt_acl() {
    local subcmd="${1:-}"
    # $2 is either a CIDR (add/remove) or an ACL name (cisco-name/juniper-name).
    # Keep the legacy name `cidr` since most branches use it that way.
    local cidr="${2:-}"

    case "$subcmd" in
        ""|-h|--help|help)
            local n=0
            [[ -r "$MGMT_ACL_FILE" ]] && n=$(read_mgmt_acl_cidrs | wc -l)
            local cisco_name juniper_name
            cisco_name=$(read_mgmt_acl_name cisco)
            juniper_name=$(read_mgmt_acl_name juniper)
            echo ""
            echo -e "${BOLD}tacctl config mgmt-acl${NC} — shared Cisco VTY-ACL + Juniper lo0-filter permits"
            echo ""
            echo "Usage:"
            echo "  tacctl config mgmt-acl list                          Show current permits"
            echo "  tacctl config mgmt-acl add    <cidr>[,<cidr>...]     Add one or more CIDRs"
            echo "  tacctl config mgmt-acl remove <cidr>[,<cidr>...]     Remove one or more CIDRs"
            echo "  tacctl config mgmt-acl clear                         Wipe all permits (confirms)"
            echo "  tacctl config mgmt-acl cisco-name [name]             Show or set the Cisco ACL name (default ${CISCO_ACL_NAME_DEFAULT})"
            echo "  tacctl config mgmt-acl juniper-name [name]           Show or set the Juniper filter name (default ${JUNIPER_ACL_NAME_DEFAULT})"
            echo ""
            echo "Storage: ${MGMT_ACL_FILE} (survives 'tacctl upgrade')."
            echo "Names:   ${MGMT_ACL_NAMES_FILE}"
            echo "         cisco=${cisco_name}  juniper=${juniper_name}"
            echo "Current entries: ${n}"
            echo ""
            return
            ;;
        list)
            echo ""
            echo -e "${BOLD}Management ACL (shared Cisco VTY-ACL + Juniper lo0 filter source)${NC}"
            echo "--------------------------------------------"
            local entries
            entries=$(read_mgmt_acl_cidrs)
            if [[ -z "$entries" ]]; then
                echo "  (empty)"
                echo ""
                echo "  Add with: tacctl config mgmt-acl add <cidr>"
                echo "  Cisco/Juniper output uses a scaffold/comment until populated."
            else
                echo "$entries" | while IFS= read -r entry; do
                    echo "  - ${entry}"
                done
            fi
            echo ""
            ;;
        add)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config mgmt-acl add <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested added="" skipped=""
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_mgmt_acl_cidrs)
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    skipped+="${skipped:+ }${c}"
                else
                    added+="${added:+$'\n'}${c}"
                    current=$(printf '%s\n%s\n' "$current" "$c")
                fi
            done <<< "$requested"
            if [[ -z "$added" ]]; then
                info "No new CIDRs to add (already present: ${skipped})."
                echo ""
                return
            fi
            # Rewrite the whole file — canonical + sorted, with header.
            write_mgmt_acl_cidrs "$current"
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} to mgmt-acl: $(printf '%s\n' "$added" | paste -sd' ')"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            info "Re-run 'tacctl config cisco' / 'tacctl config juniper' to see the new output."
            echo ""
            ;;
        remove)
            if [[ -z "$cidr" ]]; then
                error "Usage: tacctl config mgmt-acl remove <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested removed="" missing=""
            requested=$(parse_cidr_list "$cidr")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            if [[ ! -f "$MGMT_ACL_FILE" ]]; then
                warn "Nothing to remove — mgmt-acl file does not exist."
                exit 0
            fi
            local current
            current=$(read_mgmt_acl_cidrs)
            while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$c"; then
                    removed+="${removed:+$'\n'}${c}"
                    current=$(printf '%s\n' "$current" | grep -vxF "$c" || true)
                else
                    missing+="${missing:+ }${c}"
                fi
            done <<< "$requested"
            if [[ -z "$removed" ]]; then
                warn "Nothing to remove (not present: ${missing})."
                exit 0
            fi
            write_mgmt_acl_cidrs "$current"
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} from mgmt-acl: $(printf '%s\n' "$removed" | paste -sd' ')"
            [[ -n "$missing" ]] && info "(Not present, skipped: ${missing})"
            echo ""
            ;;
        clear)
            if [[ ! -f "$MGMT_ACL_FILE" ]]; then
                info "Already empty."
                echo ""
                return
            fi
            read -rp "  Clear all mgmt-acl entries? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            rm -f "$MGMT_ACL_FILE"
            info "mgmt-acl cleared."
            echo ""
            ;;
        cisco-name|juniper-name)
            local which="${subcmd%-name}"
            local default_val current_val
            if [[ "$which" == "cisco" ]]; then
                default_val="$CISCO_ACL_NAME_DEFAULT"
            else
                default_val="$JUNIPER_ACL_NAME_DEFAULT"
            fi
            current_val=$(read_mgmt_acl_name "$which")
            if [[ -z "$cidr" ]]; then
                echo ""
                echo "  ${which}-name: ${current_val}"
                if [[ "$current_val" == "$default_val" ]]; then
                    echo "  (default — override with 'tacctl config mgmt-acl ${subcmd} <name>')"
                else
                    echo "  (override in ${MGMT_ACL_NAMES_FILE})"
                fi
                echo ""
                return
            fi
            # Second positional arg = new name
            local new_name="$cidr"
            validate_acl_name "$new_name"
            if [[ "$new_name" == "$current_val" ]]; then
                info "${which}-name already '${new_name}'; no change."
                echo ""
                return
            fi
            write_mgmt_acl_name "$which" "$new_name"
            info "Re-run 'tacctl config ${which}' to see the new name in the output."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            error "Run 'tacctl config mgmt-acl' with no arguments for help."
            exit 1
            ;;
    esac
}

# =====================================================================
#  SCOPE COMMANDS (tacctl scopes ...)
# =====================================================================

cmd_scopes() {
    local subcmd="${1:-}"
    shift 2>/dev/null || true
    case "$subcmd" in
        ""|-h|--help|help) cmd_scopes_usage ;;
        list)              cmd_scopes_list ;;
        show)              cmd_scopes_show "$@" ;;
        add)               cmd_scopes_add "$@" ;;
        remove)            cmd_scopes_remove "$@" ;;
        rename)            cmd_scopes_rename "$@" ;;
        default)           cmd_scopes_default "$@" ;;
        lookup)            cmd_scopes_lookup "$@" ;;
        prefixes)          cmd_scopes_prefixes_dispatch "$@" ;;
        secret)            cmd_scopes_secret_dispatch "$@" ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            cmd_scopes_usage
            exit 1
            ;;
    esac
}

cmd_scopes_usage() {
    local count=0 default_val
    count=$(list_scopes | wc -l)
    default_val=$(read_default_scope)
    echo ""
    echo -e "${BOLD}tacctl scopes${NC} — named (CIDR-prefixes, shared-secret) bundles"
    echo ""
    echo "Usage:"
    echo "  tacctl scopes list                                        Summary of all scopes"
    echo "  tacctl scopes show <name>                                 Detailed view"
    echo "  tacctl scopes add <name> --prefixes <cidrs>               Create a new scope"
    echo "                       [--secret <value>|generate]"
    echo "                       [--default]"
    echo "  tacctl scopes remove <name> [--force]                     Delete a scope (confirms)"
    echo "  tacctl scopes rename <old> <new>                          Rename (updates user references)"
    echo "  tacctl scopes default [<name>]                            Show or set the default scope"
    echo "  tacctl scopes lookup <ip|cidr>                            Show which scope owns an address"
    echo ""
    echo "  tacctl scopes prefixes <scope> list|add|remove|clear      Manage a scope's CIDR list"
    echo "  tacctl scopes secret   <scope> show|set|generate          Manage a scope's shared secret"
    echo ""
    echo "Current scopes: ${count}"
    echo "Default scope:  ${default_val:-<unset>}"
    echo ""
}

cmd_scopes_list() {
    echo ""
    echo -e "${BOLD}Scopes${NC}"
    echo "--------------------------------------------"
    local default_val
    default_val=$(read_default_scope)
    local names
    names=$(list_scopes)
    if [[ -z "$names" ]]; then
        echo "  (no scopes configured)"
        echo ""
        return
    fi
    local first=1
    while IFS= read -r name; do
        [[ -z "$name" ]] && continue
        local pfx_list user_count is_default_marker
        pfx_list=$(read_scope_prefixes "$name")
        user_count=$(count_users_in_scope "$name")
        is_default_marker=""
        [[ "$name" == "$default_val" ]] && is_default_marker="  ${CYAN}(default)${NC}"
        (( first )) || echo ""
        first=0
        echo -e "  ${BOLD}${name}${NC}${is_default_marker}"
        echo -e "    Users:    ${user_count}"
        if [[ -z "$pfx_list" ]]; then
            echo -e "    Prefixes: ${RED}(empty — no clients can auth)${NC}"
        else
            local pfx_count
            pfx_count=$(printf '%s\n' "$pfx_list" | wc -l)
            echo -e "    Prefixes: ${pfx_count}"
            echo "$pfx_list" | while IFS= read -r c; do
                [[ -z "$c" ]] && continue
                echo "      - ${c}"
            done
        fi
    done <<< "$names"
    echo ""
}

cmd_scopes_show() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scopes show <name>"
        exit 1
    fi
    if ! scope_exists "$name"; then
        error "Scope '${name}' does not exist."
        exit 1
    fi
    local secret_val secret_len secret_line
    secret_val=$(read_scope_secret "$name")
    secret_len=${#secret_val}
    if [[ -z "$secret_val" ]]; then
        secret_line="${RED}(unset)${NC}"
    elif [[ "$secret_val" == *REPLACE* ]]; then
        secret_line="${secret_val}  ${RED}(PLACEHOLDER — run 'tacctl scopes secret ${name} generate')${NC}"
    elif [[ "$secret_len" -lt "$SECRET_MIN_LENGTH" ]]; then
        secret_line="${secret_val}  ${RED}(${secret_len} chars, below min ${SECRET_MIN_LENGTH})${NC}"
    else
        secret_line="${secret_val}  ${GREEN}(${secret_len} chars)${NC}"
    fi
    local default_val
    default_val=$(read_default_scope)
    local is_default="no"
    [[ "$name" == "$default_val" ]] && is_default="yes"
    echo ""
    echo -e "${BOLD}Scope:${NC} ${name}"
    echo "--------------------------------------------"
    echo -e "  ${BOLD}Default:${NC}       ${is_default}"
    echo -e "  ${BOLD}Secret:${NC}        ${secret_line}"
    echo -e "  ${BOLD}Prefixes:${NC}"
    local pfx
    pfx=$(read_scope_prefixes "$name")
    if [[ -z "$pfx" ]]; then
        echo "    (none — no clients can match this scope)"
    else
        echo "$pfx" | while IFS= read -r c; do
            [[ -z "$c" ]] && continue
            echo "    - ${c}"
        done
    fi
    echo -e "  ${BOLD}Users:${NC}"
    local users
    users=$(list_users_in_scope "$name")
    if [[ -z "$users" ]]; then
        echo "    (none)"
    else
        echo "$users" | while IFS= read -r u; do
            echo "    - ${u}"
        done
    fi
    echo ""
}

cmd_scopes_add() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scopes add <name> --prefixes <cidrs> [--secret <value>|generate] [--default]"
        exit 1
    fi
    shift
    if ! [[ "$name" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,31}$ ]]; then
        error "Invalid scope name '${name}'. Use letters/digits/_-, starting with a letter."
        exit 1
    fi
    if scope_exists "$name"; then
        error "Scope '${name}' already exists."
        exit 1
    fi

    local prefixes="" secret_arg="" make_default="false"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --prefixes) prefixes="${2:-}"; shift 2 ;;
            --secret)   secret_arg="${2:-}"; shift 2 ;;
            --default)  make_default="true"; shift ;;
            *) error "Unknown flag: '$1'"; exit 1 ;;
        esac
    done

    if [[ -z "$prefixes" ]]; then
        error "--prefixes <cidrs> is required (comma-separated list)."
        exit 1
    fi
    local canon
    canon=$(parse_cidr_list "$prefixes")
    [[ -z "$canon" ]] && { error "No valid CIDRs in --prefixes."; exit 1; }

    # One-scope-per-prefix invariant: every CIDR must belong to exactly one
    # scope, otherwise tacquito's first-match-wins selector makes the losing
    # scope's users silently unable to auth from that device. Abort before
    # writing anything.
    local collisions=""
    while IFS= read -r c; do
        [[ -z "$c" ]] && continue
        local owner
        owner=$(scope_owning_prefix "$c")
        if [[ -n "$owner" ]]; then
            collisions+="${collisions:+$'\n'}    - ${c}  (already in scope '${owner}')"
        fi
    done <<< "$canon"
    if [[ -n "$collisions" ]]; then
        error "Cannot create scope '${name}': prefix(es) already claimed:"
        while IFS= read -r line; do error "$line"; done <<< "$collisions"
        error "Each CIDR belongs to exactly one scope. Remove it from the owning"
        error "scope first with 'tacctl scopes prefixes <owner> remove <cidr>'."
        exit 1
    fi

    local csv
    csv=$(printf '%s\n' "$canon" | paste -sd,)

    local secret_value=""
    if [[ -z "$secret_arg" || "$secret_arg" == "generate" ]]; then
        secret_value=$(openssl rand -base64 24)
        info "Generated secret: ${BOLD}${secret_value}${NC}"
    else
        secret_value="$secret_arg"
        if [[ "${#secret_value}" -lt "$SECRET_MIN_LENGTH" ]]; then
            error "Secret is ${#secret_value} characters; minimum is ${SECRET_MIN_LENGTH}."
            exit 1
        fi
    fi

    backup_config
    add_scope "$name" "$csv" "$secret_value"
    reorder_secrets_by_prefix_specificity
    chown tacquito:tacquito "$CONFIG"

    if [[ "$make_default" == "true" ]]; then
        write_default_scope "$name"
        info "Scope '${name}' added and set as default."
    else
        info "Scope '${name}' added."
    fi
    restart_service
    echo ""
}

cmd_scopes_remove() {
    local name="${1:-}" force="false"
    if [[ -z "$name" ]]; then
        error "Usage: tacctl scopes remove <name> [--force]"
        exit 1
    fi
    shift 2>/dev/null || true
    [[ "${1:-}" == "--force" ]] && force="true"

    if ! scope_exists "$name"; then
        error "Scope '${name}' does not exist."
        exit 1
    fi

    local user_count
    user_count=$(count_users_in_scope "$name")
    if [[ "$user_count" -gt 0 && "$force" != "true" ]]; then
        error "Cannot remove '${name}': ${user_count} user(s) still reference it."
        error "Remove them first:"
        list_users_in_scope "$name" | sed 's/^/    tacctl user scopes /' | sed 's/$/ remove '"${name}"'/'
        error "Or pass --force to strip the scope from those users AND delete it."
        exit 1
    fi

    local default_val
    default_val=$(read_default_scope)
    if [[ "$name" == "$default_val" ]]; then
        error "Cannot remove '${name}': it is the default scope."
        error "Point the default at another scope first: tacctl scopes default <other>"
        exit 1
    fi

    warn "About to remove scope '${name}'."
    [[ "$user_count" -gt 0 ]] && warn "This will also strip '${name}' from ${user_count} user(s)."
    read -rp "  Confirm removal? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        info "Aborted."
        return
    fi

    backup_config

    # Strip the scope from any users still referencing it.
    if [[ "$user_count" -gt 0 ]]; then
        while IFS= read -r u; do
            [[ -z "$u" ]] && continue
            local current
            current=$(read_user_scopes "$u" | grep -vxF "$name" | paste -sd,)
            set_user_scopes "$u" "$current"
        done < <(list_users_in_scope "$name")
    fi

    remove_scope "$name"
    reorder_secrets_by_prefix_specificity
    chown tacquito:tacquito "$CONFIG"
    restart_service
    info "Scope '${name}' removed."
    echo ""
}

cmd_scopes_rename() {
    local old="${1:-}" new="${2:-}"
    if [[ -z "$old" || -z "$new" ]]; then
        error "Usage: tacctl scopes rename <old> <new>"
        exit 1
    fi
    if ! scope_exists "$old"; then
        error "Scope '${old}' does not exist."
        exit 1
    fi
    if scope_exists "$new"; then
        error "Scope '${new}' already exists."
        exit 1
    fi
    if ! [[ "$new" =~ ^[a-zA-Z][a-zA-Z0-9_-]{0,31}$ ]]; then
        error "Invalid new name '${new}'."
        exit 1
    fi
    backup_config
    rename_scope "$old" "$new"
    reorder_secrets_by_prefix_specificity
    # Update default-scope marker if it pointed at the old name.
    local default_val
    default_val=$(cat "$DEFAULT_SCOPE_FILE" 2>/dev/null | head -1 | xargs || true)
    if [[ "$default_val" == "$old" ]]; then
        write_default_scope "$new"
        info "Default-scope marker updated: ${old} -> ${new}"
    fi
    chown tacquito:tacquito "$CONFIG"
    restart_service
    local user_count
    user_count=$(count_users_in_scope "$new")
    info "Scope renamed: ${old} -> ${new} (${user_count} user(s) updated)."
    echo ""
}

cmd_scopes_default() {
    local name="${1:-}"
    if [[ -z "$name" ]]; then
        local current
        current=$(read_default_scope)
        echo ""
        if [[ -z "$current" ]]; then
            echo "  No default scope set (no scopes configured yet?)."
        else
            echo "  Default scope: ${current}"
        fi
        echo ""
        echo "  Usage: tacctl scopes default <name>    # set default to <name>"
        echo "  The default scope is used when:"
        echo "    - 'tacctl user add <u> <g>' is run without --scopes"
        echo "    - 'tacctl config cisco/juniper' is run without --scope"
        echo ""
        return
    fi
    if ! scope_exists "$name"; then
        error "Scope '${name}' does not exist."
        exit 1
    fi
    write_default_scope "$name"
    info "Default scope set to '${name}'."
    echo ""
}

# --- Resolve an IP or CIDR to the scope that would own it ---
# Matches tacquito's selection logic: walks the live secrets[] list in
# slice order (specificity-sorted) and returns the first scope whose
# prefix contains the query. Emits the owning scope name, the matching
# prefix, and (when the query is an IP inside a broader covering supernet)
# any additional scopes whose prefixes also contain the address — handy
# when debugging unexpected auth routing.
cmd_scopes_lookup() {
    local query="${1:-}"
    if [[ -z "$query" ]]; then
        error "Usage: tacctl scopes lookup <ip|cidr>"
        error "Examples:"
        error "  tacctl scopes lookup 10.5.1.2"
        error "  tacctl scopes lookup 10.5.0.0/16"
        exit 1
    fi
    python3 - "$CONFIG" "$query" <<'PY'
import yaml, json, ipaddress, re, sys
path, query = sys.argv[1], sys.argv[2]

# Parse query as either a single address or a CIDR network.
q_net = None
q_host = None
try:
    if '/' in query:
        q_net = ipaddress.ip_network(query, strict=False)
    else:
        q_host = ipaddress.ip_address(query)
except ValueError as e:
    print(f"ERROR: invalid address or CIDR: {e}")
    sys.exit(2)

with open(path) as f:
    d = yaml.safe_load(f) or {}

# Walk secrets[] in YAML slice order (= tacquito's match order).
matches = []  # list of (scope_name, prefix_net) in iteration order
for s in (d.get('secrets') or []):
    name = s.get('name')
    pfx = (s.get('options') or {}).get('prefixes') or ''
    try:
        arr = json.loads(pfx) if pfx else []
    except Exception:
        arr = re.findall(r'"([^"]+)"', pfx)
    for c in arr:
        try:
            pnet = ipaddress.ip_network(c, strict=False)
        except ValueError:
            continue
        # For IP queries: match if the prefix contains the host.
        # For CIDR queries: match if the prefix equals or strictly contains
        # the query (i.e. the query is within the scope's address space).
        if q_host is not None and q_host in pnet:
            matches.append((name, pnet))
        elif q_net is not None and (pnet == q_net or q_net.subnet_of(pnet)):
            matches.append((name, pnet))

if not matches:
    if q_host is not None:
        print(f"No scope owns {q_host} — no prefix in any scope contains it.")
    else:
        print(f"No scope owns {q_net} — no prefix covers the full range.")
    sys.exit(1)

# Winner: first match in slice order (matches tacquito's selector).
winner_scope, winner_pfx = matches[0]
if q_host is not None:
    print(f"  {q_host} -> scope '{winner_scope}' (via prefix {winner_pfx})")
else:
    print(f"  {q_net} -> scope '{winner_scope}' (via prefix {winner_pfx})")

# If multiple prefixes cover the query (overlapping supernets across scopes),
# show the shadow — operators often want to confirm that tacquito would
# actually pick the scope they expect.
if len(matches) > 1:
    print("")
    print("  Also covered by (shadowed — tacquito's first-match picks the one above):")
    for name, pnet in matches[1:]:
        print(f"    - scope '{name}' via prefix {pnet}")
PY
}

# --- Per-scope prefix management: tacctl scopes prefixes <scope> ... ---
cmd_scopes_prefixes_dispatch() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"
    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scopes prefixes <scope> {list|add|remove|clear} [<cidrs>]"
        exit 1
    fi
    if ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    case "$sub" in
        ""|-h|--help|help)
            local count=0
            count=$(read_scope_prefixes "$scope" | wc -l)
            echo ""
            echo -e "${BOLD}tacctl scopes prefixes ${scope}${NC} — CIDR prefix list for scope '${scope}'"
            echo ""
            echo "Usage:"
            echo "  tacctl scopes prefixes ${scope} list                        Show entries"
            echo "  tacctl scopes prefixes ${scope} add    <cidr>[,<cidr>...]   Add one or more"
            echo "  tacctl scopes prefixes ${scope} remove <cidr>[,<cidr>...]   Remove one or more"
            echo "  tacctl scopes prefixes ${scope} clear                       Wipe all (confirms)"
            echo ""
            echo "Current entries: ${count}"
            echo ""
            ;;
        list)
            echo ""
            echo -e "${BOLD}Prefixes for scope '${scope}'${NC}"
            echo "--------------------------------------------"
            local entries
            entries=$(read_scope_prefixes "$scope")
            if [[ -z "$entries" ]]; then
                echo "  (empty — no clients can match this scope)"
            else
                echo "$entries" | while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    echo "  - ${c}"
                done
            fi
            echo ""
            ;;
        add|remove)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scopes prefixes ${scope} ${sub} <cidr>[,<cidr>...]"
                exit 1
            fi
            local requested
            requested=$(parse_cidr_list "$arg")
            [[ -z "$requested" ]] && { error "No valid CIDRs provided."; exit 1; }
            local current
            current=$(read_scope_prefixes "$scope")
            local changed="" missing_or_present=""
            if [[ "$sub" == "add" ]]; then
                # Cross-scope collision check BEFORE any mutation. A CIDR owned
                # by another scope can't be silently stolen — operator must
                # remove it from the owning scope first.
                local collisions=""
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    local owner
                    owner=$(scope_owning_prefix "$c")
                    if [[ -n "$owner" && "$owner" != "$scope" ]]; then
                        collisions+="${collisions:+$'\n'}    - ${c}  (already in scope '${owner}')"
                    fi
                done <<< "$requested"
                if [[ -n "$collisions" ]]; then
                    error "Cannot add prefix(es) to scope '${scope}':"
                    while IFS= read -r line; do error "$line"; done <<< "$collisions"
                    error "Remove them from the owning scope first:"
                    error "  tacctl scopes prefixes <owner> remove <cidr>"
                    exit 1
                fi
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF "$c"; then
                        missing_or_present+="${missing_or_present:+ }${c}"
                    else
                        changed+="${changed:+$'\n'}${c}"
                        current=$(printf '%s\n%s\n' "$current" "$c")
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { info "No new CIDRs (already present in '${scope}': ${missing_or_present})."; echo ""; return; }
            else
                while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF "$c"; then
                        changed+="${changed:+$'\n'}${c}"
                        current=$(printf '%s\n' "$current" | grep -vxF "$c" || true)
                    else
                        missing_or_present+="${missing_or_present:+ }${c}"
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { warn "Nothing to remove (not present: ${missing_or_present})."; exit 0; }
            fi
            backup_config
            set_scope_prefixes "$scope" "$(printf '%s\n' "$current" | awk 'NF' | paste -sd,)"
            reorder_secrets_by_prefix_specificity
            chown tacquito:tacquito "$CONFIG"
            restart_service
            local n
            n=$(printf '%s\n' "$changed" | wc -l)
            local verb="Added"; [[ "$sub" == "remove" ]] && verb="Removed"
            info "${verb} ${n} prefix(es) for scope '${scope}': $(printf '%s\n' "$changed" | paste -sd' ')"
            [[ -n "$missing_or_present" ]] && info "(Skipped: ${missing_or_present})"
            echo ""
            ;;
        clear)
            # Flat emission: clearing all prefixes removes every entry for
            # this scope from secrets[]; the scope vanishes from YAML and
            # any users with it in their scopes[] become orphans. Mirror
            # the scopes-remove guard: refuse when users reference the
            # scope unless --force is given.
            local force="false"
            [[ "$arg" == "--force" ]] && force="true"
            local cur
            cur=$(read_scope_prefixes "$scope")
            if [[ -z "$cur" ]]; then
                info "Scope '${scope}' prefix list is already empty."
                return
            fi
            local user_count
            user_count=$(count_users_in_scope "$scope")
            if [[ "$user_count" -gt 0 && "$force" != "true" ]]; then
                error "Cannot clear prefixes for '${scope}': ${user_count} user(s) still reference it."
                error "Clearing every prefix removes the scope from the secrets list"
                error "and leaves those users with orphan scope references."
                error "Detach users first:"
                list_users_in_scope "$scope" | sed 's/^/    tacctl user scopes /' | sed 's/$/ remove '"${scope}"'/'
                error "Or pass --force to proceed and leave orphan refs (use 'tacctl config validate' to find them)."
                exit 1
            fi
            local n
            n=$(printf '%s\n' "$cur" | wc -l)
            warn "Clearing all ${n} prefix(es) from '${scope}' removes it from tacquito.yaml."
            if [[ "$user_count" -gt 0 ]]; then
                warn "${user_count} user(s) will have orphan refs to '${scope}' after this."
            fi
            read -rp "  Confirm? [y/N]: " confirm
            [[ ! "$confirm" =~ ^[Yy] ]] && { info "Aborted."; return; }
            backup_config
            set_scope_prefixes "$scope" ""
            reorder_secrets_by_prefix_specificity
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Cleared prefixes for scope '${scope}'."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl scopes prefixes ${scope}' for usage."
            exit 1
            ;;
    esac
}

# --- Per-scope secret management: tacctl scopes secret <scope> ... ---
cmd_scopes_secret_dispatch() {
    local scope="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"
    if [[ -z "$scope" ]]; then
        error "Usage: tacctl scopes secret <scope> {show|set <value>|generate}"
        exit 1
    fi
    if ! scope_exists "$scope"; then
        error "Scope '${scope}' does not exist."
        exit 1
    fi
    case "$sub" in
        ""|-h|--help|help)
            local s_len=0
            local cur
            cur=$(read_scope_secret "$scope")
            s_len=${#cur}
            echo ""
            echo -e "${BOLD}tacctl scopes secret ${scope}${NC} — shared secret for scope '${scope}'"
            echo ""
            echo "Usage:"
            echo "  tacctl scopes secret ${scope} show                Print raw value + length/posture"
            echo "  tacctl scopes secret ${scope} set <value>         Set to <value> (validated)"
            echo "  tacctl scopes secret ${scope} generate            Auto-generate + apply"
            echo ""
            echo "Current length: ${s_len} chars (min ${SECRET_MIN_LENGTH})"
            echo ""
            ;;
        show)
            local cur s_len
            cur=$(read_scope_secret "$scope")
            s_len=${#cur}
            echo ""
            echo -e "${BOLD}Scope '${scope}' — shared secret${NC}"
            echo "--------------------------------------------"
            if [[ -z "$cur" ]]; then
                echo -e "  ${RED}(unset)${NC}"
            elif [[ "$cur" == *REPLACE* ]]; then
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${RED}Length: ${s_len} chars — PLACEHOLDER (run 'tacctl scopes secret ${scope} generate')${NC}"
            elif [[ "$s_len" -lt "$SECRET_MIN_LENGTH" ]]; then
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${RED}Length: ${s_len} chars (below min ${SECRET_MIN_LENGTH})${NC}"
            else
                echo -e "  Value:  ${BOLD}${cur}${NC}"
                echo -e "  ${GREEN}Length: ${s_len} chars${NC}"
            fi
            echo ""
            ;;
        set)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl scopes secret ${scope} set <value>"
                exit 1
            fi
            if [[ "${#arg}" -lt "$SECRET_MIN_LENGTH" ]]; then
                error "Secret is ${#arg} characters; minimum is ${SECRET_MIN_LENGTH}."
                exit 1
            fi
            if [[ "$arg" =~ ^[a-z]+$ ]] || [[ "$arg" =~ ^[A-Z]+$ ]] || [[ "$arg" =~ ^[0-9]+$ ]]; then
                error "Secret is single-character-class (low entropy)."
                exit 1
            fi
            backup_config
            set_scope_secret "$scope" "$arg"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Scope '${scope}' secret updated."
            warn "Update ALL devices in scope '${scope}' with the new secret: ${arg}"
            echo ""
            ;;
        generate)
            local new_val
            new_val=$(openssl rand -base64 24)
            echo -e "  Generated: ${BOLD}${new_val}${NC}"
            backup_config
            set_scope_secret "$scope" "$new_val"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Scope '${scope}' secret updated."
            warn "Update ALL devices in scope '${scope}' with the new secret above."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl scopes secret ${scope}' for usage."
            exit 1
            ;;
    esac
}

# --- USER SCOPES: tacctl user scopes <user> list|add|remove|set|clear ---
cmd_user_scopes() {
    local username="${1:-}"
    local sub="${2:-}"
    local arg="${3:-}"

    if [[ -z "$username" ]]; then
        error "Usage: tacctl user scopes <user> {list|add|remove|set|clear} [<scope>[,<scope>...]]"
        exit 1
    fi
    validate_username "$username"
    if ! user_exists "$username"; then
        error "User '${username}' does not exist."
        exit 1
    fi

    case "$sub" in
        ""|list|-h|--help|help)
            echo ""
            echo -e "${BOLD}Scopes for user '${username}'${NC}"
            echo "--------------------------------------------"
            local cur
            cur=$(read_user_scopes "$username")
            if [[ -z "$cur" ]]; then
                echo -e "  ${RED}(none — user cannot authenticate on any device)${NC}"
            else
                echo "$cur" | while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    if scope_exists "$s"; then
                        echo "  - ${s}"
                    else
                        echo -e "  ${RED}- ${s}  (ORPHAN: scope does not exist)${NC}"
                    fi
                done
            fi
            echo ""
            if [[ -z "$sub" || "$sub" == "list" ]]; then
                return
            fi
            echo "Usage:"
            echo "  tacctl user scopes ${username} list                              Show current (default)"
            echo "  tacctl user scopes ${username} add    <scope>[,<scope>...]      Grant scope access"
            echo "  tacctl user scopes ${username} remove <scope>[,<scope>...]      Revoke scope access"
            echo "  tacctl user scopes ${username} set    <scope>[,<scope>...]      Replace full list"
            echo "  tacctl user scopes ${username} clear                             Wipe all (confirms)"
            echo ""
            return
            ;;
        add|remove|set)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl user scopes ${username} ${sub} <scope>[,<scope>...]"
                exit 1
            fi
            # Parse + validate scope names
            local requested=""
            local s
            IFS=',' read -ra SCOPES <<< "$arg"
            for s in "${SCOPES[@]}"; do
                s=$(echo "$s" | xargs)
                [[ -z "$s" ]] && continue
                if ! scope_exists "$s"; then
                    error "Scope '${s}' does not exist. Available: $(list_scopes | paste -sd' ')"
                    exit 1
                fi
                # within-input dedupe
                if ! printf '%s\n' "$requested" | grep -qxF "$s"; then
                    requested+="${requested:+$'\n'}${s}"
                fi
            done
            [[ -z "$requested" ]] && { error "No valid scope names provided."; exit 1; }

            local current new_list
            current=$(read_user_scopes "$username")
            local changed="" noop=""
            if [[ "$sub" == "set" ]]; then
                new_list=$(printf '%s\n' "$requested" | paste -sd,)
                changed="$requested"
            elif [[ "$sub" == "add" ]]; then
                new_list="$current"
                while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF "$s"; then
                        noop+="${noop:+ }${s}"
                    else
                        changed+="${changed:+$'\n'}${s}"
                        new_list=$(printf '%s\n%s\n' "$new_list" "$s")
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { info "No new scopes (already present: ${noop})."; echo ""; return; }
                new_list=$(printf '%s\n' "$new_list" | awk 'NF' | paste -sd,)
            else  # remove
                new_list="$current"
                while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    if printf '%s\n' "$current" | grep -qxF "$s"; then
                        changed+="${changed:+$'\n'}${s}"
                        new_list=$(printf '%s\n' "$new_list" | grep -vxF "$s" || true)
                    else
                        noop+="${noop:+ }${s}"
                    fi
                done <<< "$requested"
                [[ -z "$changed" ]] && { warn "Nothing to remove (not present: ${noop})."; exit 0; }
                new_list=$(printf '%s\n' "$new_list" | awk 'NF' | paste -sd,)
            fi

            backup_config
            set_user_scopes "$username" "$new_list"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            local n
            n=$(printf '%s\n' "$changed" | wc -l)
            local verb
            case "$sub" in
                add)    verb="Granted ${n} scope(s) to" ;;
                remove) verb="Revoked ${n} scope(s) from" ;;
                set)    verb="Replaced scopes on" ;;
            esac
            info "${verb} user '${username}': $(printf '%s\n' "$changed" | paste -sd' ')"
            [[ -n "$noop" ]] && info "(Skipped: ${noop})"
            if [[ -z "$new_list" ]]; then
                warn "User '${username}' now has NO scopes — they cannot auth on any device"
                warn "until you run: tacctl user scopes ${username} add <scope>"
            fi
            echo ""
            ;;
        clear)
            local current
            current=$(read_user_scopes "$username")
            if [[ -z "$current" ]]; then
                info "User '${username}' already has no scopes."
                return
            fi
            warn "WARNING: ${username} will be unable to authenticate on any device"
            warn "until you grant at least one scope with 'tacctl user scopes ${username} add <name>'"
            warn "(Distinct from 'tacctl user disable' — the password hash is preserved.)"
            read -rp "  Clear all scopes for '${username}'? [y/N]: " confirm
            [[ ! "$confirm" =~ ^[Yy] ]] && { info "Aborted."; return; }
            backup_config
            set_user_scopes "$username" ""
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Cleared scopes for user '${username}'."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl user scopes ${username}' for usage."
            exit 1
            ;;
    esac
}

# --- CONFIG dispatcher ---
cmd_config() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        show)
            cmd_config_show
            ;;
        secret)
            cmd_config_secret "$@"
            ;;
        prefixes)
            cmd_config_prefixes "$@"
            ;;
        cisco)
            cmd_config_cisco "$@"
            ;;
        juniper)
            cmd_config_juniper "$@"
            ;;
        validate)
            cmd_config_validate
            ;;
        loglevel)
            cmd_config_loglevel "$@"
            ;;
        listen)
            cmd_config_listen "$@"
            ;;
        sudoers)
            cmd_config_sudoers "$@"
            ;;
        password-age)
            cmd_config_password_age "$@"
            ;;
        bcrypt-cost)
            cmd_config_bcrypt_cost "$@"
            ;;
        password-min-length)
            cmd_config_password_min_length "$@"
            ;;
        secret-min-length)
            cmd_config_secret_min_length "$@"
            ;;
        diff)
            cmd_backup diff "$@"
            ;;
        allow)
            cmd_config_prefix_filter "prefix_allow" "$@"
            ;;
        deny)
            cmd_config_prefix_filter "prefix_deny" "$@"
            ;;
        mgmt-acl)
            cmd_config_mgmt_acl "$@"
            ;;
        branch)
            cmd_config_branch "$@"
            ;;
        *)
            echo ""
            echo -e "${BOLD}Config Commands${NC}"
            echo ""
            echo "Usage: tacctl config <subcommand> [value]"
            echo ""
            echo "Subcommands:"
            echo "  show                                 Show current configuration"
            echo "  validate                             Validate config syntax and structure"
            echo "  diff [timestamp]                     Diff current config vs last backup"
            echo "  loglevel [debug|info|error]          Show or change log level"
            echo "  listen [show|tcp|tcp6|reset] [addr]  Show, change, or reset TCP listen address"
            echo "  sudoers [show|install|remove] [grp]  Manage NOPASSWD sudoers drop-in for tacctl"
            echo "  password-age [days]                  Show or set password age warning threshold"
            echo "  bcrypt-cost [10-14]                  Show or set bcrypt cost factor (default 12)"
            echo "  password-min-length [8-64]           Show or set minimum interactive password length (default 12)"
            echo "  secret-min-length [16-128]           Show or set minimum shared-secret length (default 16)"
            echo "  allow list|add|remove|clear          Manage connection allow list (IP ACL; add/remove accept comma-lists)"
            echo "  deny list|add|remove|clear           Manage connection deny list (IP ACL; add/remove accept comma-lists)"
            echo "  mgmt-acl list|add|remove|clear       Manage Cisco VTY-ACL + Juniper lo0-filter permits"
            echo "  cisco   [--scope <name>]             Show working Cisco device configuration for a scope"
            echo "  juniper [--scope <name>]             Show working Juniper device configuration for a scope"
            echo "  branch [name]                        Show or change the tacctl repo branch"
            echo ""
            echo "Removed (use 'tacctl scopes' instead):"
            echo "  secret   — now:  tacctl scopes secret   <name> show|set|generate"
            echo "  prefixes — now:  tacctl scopes prefixes <name> list|add|remove|clear"
            echo ""
            echo "Examples:"
            echo "  tacctl config show"
            echo "  tacctl config validate"
            echo "  tacctl config loglevel debug"
            echo "  tacctl config listen tcp6 [::]:49"
            echo "  tacctl config sudoers install adm"
            echo "  tacctl config cisco --scope prod"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  GROUP COMMANDS
# =====================================================================

# --- GROUP LIST ---
cmd_group_list() {
    echo ""
    echo -e "${BOLD}Tacquito Groups${NC}"
    echo "--------------------------------------------"
    printf "  ${BOLD}%-20s %-15s %-20s %-10s${NC}\n" "GROUP" "CISCO PRIV-LVL" "JUNIPER CLASS" "USERS"
    echo "  -------------------------------------------------------------------"

    python3 -c "
import re, sys

config = open(sys.argv[1]).read()

# Find groups section
groups_match = re.search(r'^# --- Groups ---\s*\n(.*?)(?=^# --- Users|\Z)', config, re.MULTILINE | re.DOTALL)
if not groups_match:
    sys.exit(0)

groups_section = groups_match.group(1)

# Find all group definitions
for m in re.finditer(r'^(\w+): &\1\n  name: \1\n  services:\n(.*?)  accounter:', groups_section, re.MULTILINE | re.DOTALL):
    name = m.group(1)
    services = m.group(2)

    # Extract Cisco priv-lvl
    priv = 'n/a'
    pm = re.search(r'\*exec_(\w+)', services)
    if pm:
        svc_name = pm.group(1)
        sm = re.search(r'exec_' + svc_name + r':.*?values:\s*\[(\d+)\]', config, re.DOTALL)
        if sm:
            priv = sm.group(1)

    # Extract Juniper class
    jclass = 'n/a'
    jm = re.search(r'\*junos_exec_(\w+)', services)
    if jm:
        svc_name = jm.group(1)
        jcm = re.search(r'junos_exec_' + svc_name + r':.*?values:\s*\[\"([^\"]+)\"\]', config, re.DOTALL)
        if jcm:
            jclass = jcm.group(1)

    # Count users in this group
    users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
    user_count = 0
    if users_match:
        user_count = len(re.findall(r'groups: \[\*' + re.escape(name) + r'\]', users_match.group(1)))

    print(f'{name}|{priv}|{jclass}|{user_count}')
" "$CONFIG" | while IFS='|' read -r name priv jclass user_count; do
        printf "  %-20s %-15s %-20s %-10s\n" "$name" "$priv" "$jclass" "$user_count"
    done

    echo ""
}

# --- GROUP ADD ---
cmd_group_add() {
    local groupname="${1:-}"
    local privlvl="${2:-}"
    local jclass="${3:-}"

    if [[ -z "$groupname" || -z "$privlvl" || -z "$jclass" ]]; then
        error "Usage: tacctl group add <name> <cisco-priv-lvl> <juniper-class>"
        echo "  Example: tacctl group add helpdesk 5 HELPDESK-CLASS" >&2
        exit 1
    fi

    # Validate group name
    if [[ ! "$groupname" =~ ^[a-z][a-z0-9_-]*$ ]]; then
        error "Group name must be lowercase, starting with a letter."
        exit 1
    fi

    # Check if group already exists
    if grep -q "^${groupname}: &${groupname}$" "$CONFIG"; then
        error "Group '${groupname}' already exists."
        exit 1
    fi

    # Validate priv-lvl
    if ! [[ "$privlvl" =~ ^[0-9]+$ ]] || [[ "$privlvl" -lt 0 || "$privlvl" -gt 15 ]]; then
        error "Cisco privilege level must be 0-15."
        exit 1
    fi

    validate_class_name "$jclass"

    backup_config

    # Insert the new exec service, junos-exec service, and group before "# --- Groups ---"
    local groups_line
    groups_line=$(grep -n "^# --- Groups ---" "$CONFIG" | head -1 | cut -d: -f1)
    if [[ -z "$groups_line" ]]; then
        error "Cannot find groups section in config."
        exit 1
    fi

    # Build the new service + group block
    local block
    block=$(cat <<BLOCK

# Cisco exec - ${groupname} (priv-lvl ${privlvl})
exec_${groupname}: &exec_${groupname}
  name: exec
  set_values:
    - name: priv-lvl
      values: [${privlvl}]

# Juniper junos-exec - ${groupname}
# "${jclass}" must match a local template user on Juniper devices
junos_exec_${groupname}: &junos_exec_${groupname}
  name: junos-exec
  set_values:
    - name: local-user-name
      values: ["${jclass}"]

BLOCK
)

    # Insert services before "# --- Groups ---"
    python3 -c "
import sys
config = open(sys.argv[1]).read()
marker = '# --- Groups ---'
idx = config.index(marker)
new_block = sys.argv[2] + '\n'
config = config[:idx] + new_block + config[idx:]
import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG" "$block"

    # Insert group definition after the last existing group (before "# --- Users ---")
    local users_line
    users_line=$(grep -n "^# --- Users ---" "$CONFIG" | head -1 | cut -d: -f1)

    python3 -c "
import sys
lines = open(sys.argv[1]).readlines()
insert_at = int(sys.argv[2]) - 1
group_block = [
    '\n',
    sys.argv[3] + ': &' + sys.argv[3] + '\n',
    '  name: ' + sys.argv[3] + '\n',
    '  services:\n',
    '    - *exec_' + sys.argv[3] + '\n',
    '    - *junos_exec_' + sys.argv[3] + '\n',
    '  authenticator: *bcrypt_user\n',
    '  accounter: *file_accounter\n',
]
lines = lines[:insert_at] + group_block + lines[insert_at:]
import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.writelines(lines)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG" "$users_line" "$groupname"

    chown tacquito:tacquito "$CONFIG"
    restart_service

    info "Group '${groupname}' added (Cisco priv-lvl ${privlvl}, Juniper ${jclass})."
    warn "On Juniper devices, create the template user: set system login user ${jclass} class <junos-class>"
    echo ""
}

# --- GROUP REMOVE ---
cmd_group_remove() {
    local groupname="${1:-}"

    if [[ -z "$groupname" ]]; then
        error "Usage: tacctl group remove <name>"
        exit 1
    fi

    # Protect built-in groups
    if [[ "$groupname" == "readonly" || "$groupname" == "operator" || "$groupname" == "superuser" ]]; then
        error "Cannot remove built-in group '${groupname}'."
        exit 1
    fi

    # Check if group exists
    if ! grep -q "^${groupname}: &${groupname}$" "$CONFIG"; then
        error "Group '${groupname}' does not exist."
        exit 1
    fi

    # Check if any users are assigned to this group
    local user_count
    user_count=$(grep -c "groups: \[\*${groupname}\]" "$CONFIG" || true)
    if [[ "$user_count" -gt 0 ]]; then
        error "Cannot remove group '${groupname}' — ${user_count} user(s) are assigned to it."
        error "Reassign those users first."
        exit 1
    fi

    echo ""
    read -rp "  Remove group '${groupname}'? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    backup_config

    # Remove the exec service, junos-exec service, and group definition
    python3 -c "
import re, sys

groupname = sys.argv[2]
config = open(sys.argv[1]).read()

# Remove exec service block
config = re.sub(
    r'\n# Cisco exec - ' + re.escape(groupname) + r'.*?exec_' + re.escape(groupname) + r':.*?values: \[\d+\]\n',
    '\n', config, flags=re.DOTALL)

# Remove junos-exec service block
config = re.sub(
    r'\n# Juniper junos-exec - ' + re.escape(groupname) + r'.*?junos_exec_' + re.escape(groupname) + r':.*?values: \[\"[^\"]+\"\]\n',
    '\n', config, flags=re.DOTALL)

# Remove group definition block
config = re.sub(
    r'\n' + re.escape(groupname) + r': &' + re.escape(groupname) + r'\n  name: ' + re.escape(groupname) + r'\n.*?accounter: \*file_accounter\n',
    '\n', config, flags=re.DOTALL)

# Clean up double blank lines
config = re.sub(r'\n{3,}', '\n\n', config)

import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
" "$CONFIG" "$groupname"

    chown tacquito:tacquito "$CONFIG"
    restart_service

    info "Group '${groupname}' removed."
    echo ""
}

# --- GROUP EDIT ---
cmd_group_edit() {
    local groupname="${1:-}"
    local field="${2:-}"
    local value="${3:-}"

    if [[ -z "$groupname" || -z "$field" || -z "$value" ]]; then
        error "Usage: tacctl group edit <name> <priv-lvl|juniper-class> <value>"
        echo "  Example: tacctl group edit operator priv-lvl 10" >&2
        echo "  Example: tacctl group edit operator juniper-class NEW-CLASS" >&2
        exit 1
    fi

    # Check if group exists
    if ! grep -q "^${groupname}: &${groupname}$" "$CONFIG"; then
        error "Group '${groupname}' does not exist."
        exit 1
    fi

    backup_config

    case "$field" in
        priv-lvl)
            if ! [[ "$value" =~ ^[0-9]+$ ]] || [[ "$value" -lt 0 || "$value" -gt 15 ]]; then
                error "Cisco privilege level must be 0-15."
                exit 1
            fi

            # Find the exec service for this group and update its priv-lvl
            python3 -c "
import re, sys
config = open(sys.argv[1]).read()
group = sys.argv[2]
new_val = sys.argv[3]

# Find the group block and extract the exec service reference
gm = re.search(r'^' + re.escape(group) + r': &' + re.escape(group) + r'\n  name:.*?\n  services:\n(.*?)  accounter:', config, re.MULTILINE | re.DOTALL)
if not gm:
    print('ERROR:Could not find group block')
    sys.exit(1)
sm = re.search(r'\*exec_(\w+)', gm.group(1))
if not sm:
    print('ERROR:Could not find exec service for group')
    sys.exit(1)
svc = sm.group(1)

# Find the exact service block and replace only its priv-lvl value
pattern = r'(exec_' + re.escape(svc) + r': &exec_' + re.escape(svc) + r'\n  name: exec\n  set_values:\n    - name: priv-lvl\n      values: \[)\d+(\])'
config = re.sub(pattern, r'\g<1>' + new_val + r'\2', config)

import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
print('OK')
" "$CONFIG" "$groupname" "$value"

            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Group '${groupname}' Cisco priv-lvl changed to ${value}."
            ;;

        juniper-class)
            validate_class_name "$value"
            # Find the junos-exec service for this group and update its local-user-name
            python3 -c "
import re, sys
config = open(sys.argv[1]).read()
group = sys.argv[2]
new_class = sys.argv[3]

# Find the group block and extract the junos-exec service reference
gm = re.search(r'^' + re.escape(group) + r': &' + re.escape(group) + r'\n  name:.*?\n  services:\n(.*?)  accounter:', config, re.MULTILINE | re.DOTALL)
if not gm:
    print('ERROR:Could not find group block')
    sys.exit(1)
sm = re.search(r'\*junos_exec_(\w+)', gm.group(1))
if not sm:
    print('ERROR:Could not find junos-exec service for group')
    sys.exit(1)
svc = sm.group(1)

# Find the exact service block and replace only its local-user-name value
pattern = r'(junos_exec_' + re.escape(svc) + r': &junos_exec_' + re.escape(svc) + r'\n  name: junos-exec\n  set_values:\n    - name: local-user-name\n      values: \[\")([^\"]+)(\"\])'
old_match = re.search(pattern, config)
if old_match:
    old_class = old_match.group(2)
    config = re.sub(pattern, r'\g<1>' + new_class + r'\3', config)
    # Update comment if present
    config = config.replace(
        '\"' + old_class + '\" must match',
        '\"' + new_class + '\" must match'
    )

import tempfile, os
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(sys.argv[1]), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, sys.argv[1])
print('OK')
" "$CONFIG" "$groupname" "$value"

            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Group '${groupname}' Juniper class changed to ${value}."
            warn "On Juniper devices: set system login user ${value} class <junos-class>"
            ;;

        *)
            error "Unknown field '${field}'. Use: priv-lvl or juniper-class"
            exit 1
            ;;
    esac
    echo ""
}

# --- GROUP COMMANDS (per-group authorized command rules) ---
# Drives Cisco TACACS+ command authorization (live) and Juniper class
# allow/deny-commands (local enforcement, requires per-device push).
#
# Storage convention: a trailing `name: "*"` rule whose action encodes
# the group's default action. Tacquito returns FAIL for any rule that
# doesn't match, so the catchall is the sole way to express "permit
# everything not explicitly denied."
#
# Safety: when ANY group gains its first commands: section, every other
# group at the same Cisco priv-lvl is auto-seeded with a catchall
# permit. Without this, Cisco's `aaa authorization commands <level>`
# would route ALL command authz at that level through tacquito and
# users in the unconfigured group would be denied every command.
cmd_group_commands() {
    local subcmd="${1:-}"
    shift 2>/dev/null || true

    case "$subcmd" in
        ""|-h|--help|help)
            cmd_group_commands_usage
            return
            ;;
        seed)
            cmd_group_commands_seed "$@"
            return
            ;;
        list|default|add|remove|clear)
            ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            cmd_group_commands_usage
            exit 1
            ;;
    esac

    local group="${1:-}"
    shift 2>/dev/null || true

    if [[ -z "$group" ]]; then
        error "Usage: tacctl group commands ${subcmd} <group> ..."
        exit 1
    fi
    if ! grep -q "^${group}: &${group}$" "$CONFIG"; then
        error "Group '${group}' does not exist."
        exit 1
    fi

    case "$subcmd" in
        list)
            local rules default_action
            rules=$(read_group_commands "$group")
            default_action=$(read_group_default_action "$group")
            echo ""
            echo -e "${BOLD}Command rules for group '${group}'${NC}"
            echo "--------------------------------------------"
            echo -e "  Default action: ${BOLD}${default_action}${NC}"
            echo ""
            if [[ -z "$rules" ]]; then
                echo "  (no commands: section — all commands permitted)"
                echo ""
                return
            fi
            printf "  ${BOLD}%-20s %-8s %s${NC}\n" "NAME" "ACTION" "MATCH"
            echo "  -------------------------------------------------"
            local catchall_seen="false"
            while IFS='|' read -r name action match; do
                [[ -z "$name" ]] && continue
                local color="$GREEN"
                [[ "$action" == "deny" ]] && color="$RED"
                if [[ "$name" == "*" ]]; then
                    catchall_seen="true"
                    printf "  %-20s ${color}%-8s${NC} %s\n" "$name (catchall)" "$action" "$match"
                else
                    printf "  %-20s ${color}%-8s${NC} %s\n" "$name" "$action" "$match"
                fi
            done <<< "$rules"
            if [[ "$catchall_seen" == "false" ]]; then
                warn "No '*' catchall — tacquito will FAIL any unmatched command."
                warn "Set the default explicitly with 'tacctl group commands default ${group} permit|deny'."
            fi
            echo ""
            ;;
        default)
            local new_default="${1:-}"
            if [[ "$new_default" != "permit" && "$new_default" != "deny" ]]; then
                error "Usage: tacctl group commands default <group> <permit|deny>"
                exit 1
            fi
            backup_config
            seed_command_rules_safely "$group"
            update_group_catchall "$group" "$new_default"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Group '${group}' default action set to ${new_default}."
            echo ""
            ;;
        add)
            local name="${1:-}"
            shift 2>/dev/null || true
            if [[ -z "$name" ]]; then
                error "Usage: tacctl group commands add <group> <name> [--match <regex>]... [--action permit|deny]"
                exit 1
            fi
            validate_command_name "$name"
            if [[ "$name" == "*" ]]; then
                error "Use 'tacctl group commands default ${group} permit|deny' to change the catchall."
                exit 1
            fi
            local action="permit"
            local matches=""
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --match)
                        validate_regex "${2:-}"
                        matches+="${matches:+,}${2}"
                        shift 2
                        ;;
                    --action)
                        action="${2:-}"
                        if [[ "$action" != "permit" && "$action" != "deny" ]]; then
                            error "--action must be 'permit' or 'deny'."
                            exit 1
                        fi
                        shift 2
                        ;;
                    *)
                        error "Unknown flag: '$1'"
                        exit 1
                        ;;
                esac
            done

            backup_config
            seed_command_rules_safely "$group"

            # Reject duplicate (name, match) — same name with same match
            # set is a no-op. Same name with different matches is fine.
            local existing
            existing=$(read_group_commands "$group" | grep "^${name}|" || true)
            if [[ -n "$existing" ]]; then
                while IFS='|' read -r en ea em; do
                    [[ "$en" == "$name" && "$em" == "$matches" ]] && {
                        info "Rule '${name}' (match='${matches}') already present; no change."
                        echo ""
                        return
                    }
                done <<< "$existing"
            fi

            insert_command_rule "$group" "$name" "$action" "$matches"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Added rule '${name}' (action=${action}, match=[${matches}]) to group '${group}'."
            echo ""
            ;;
        remove)
            local name="${1:-}"
            if [[ -z "$name" ]]; then
                error "Usage: tacctl group commands remove <group> <name>"
                exit 1
            fi
            if [[ "$name" == "*" ]]; then
                error "Cannot remove the '*' catchall. Use 'tacctl group commands default' to change its action."
                error "Or 'tacctl group commands clear ${group}' to remove the entire commands: block."
                exit 1
            fi
            if ! read_group_commands "$group" | grep -q "^${name}|"; then
                warn "No rule named '${name}' in group '${group}'."
                exit 0
            fi
            backup_config
            remove_command_rule "$group" "$name"
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Removed rule '${name}' from group '${group}'."
            echo ""
            ;;
        clear)
            if [[ -z "$(read_group_commands "$group")" ]]; then
                info "Group '${group}' has no commands: block; nothing to clear."
                exit 0
            fi
            read -rp "  Clear all command rules for group '${group}'? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            backup_config
            write_group_commands "$group" ""
            chown tacquito:tacquito "$CONFIG"
            restart_service
            info "Cleared command rules for group '${group}'."
            warn "If other groups at the same Cisco priv-lvl still have rules,"
            warn "Cisco will deny ALL commands to '${group}' users at that level."
            warn "Either re-add a catchall ('tacctl group commands default ${group} permit')"
            warn "or clear all groups at the same priv-lvl."
            echo ""
            ;;
    esac
}

cmd_group_commands_usage() {
    echo ""
    echo -e "${BOLD}tacctl group commands${NC} — per-group authorized commands"
    echo ""
    echo "Usage:"
    echo "  tacctl group commands list <group>                              Show rules + default action"
    echo "  tacctl group commands default <group> <permit|deny>             Set default action (catchall)"
    echo "  tacctl group commands add <group> <name> [--match <regex>]...   Add a rule"
    echo "                                            [--action permit|deny]"
    echo "  tacctl group commands remove <group> <name>                     Drop a rule"
    echo "  tacctl group commands clear <group>                             Wipe rules (confirms)"
    echo "  tacctl group commands seed [<group>] [--force]                  Populate built-ins with defaults"
    echo ""
    echo "Cisco devices ask tacquito per command (live enforcement) when"
    echo "'aaa authorization commands <level>' is in the device config —"
    echo "tacctl auto-emits these lines in 'tacctl config cisco' once any"
    echo "group has rules. Juniper enforcement is LOCAL via class"
    echo "allow/deny-commands and requires a per-device config push."
    echo ""
}

# --- Default rule sets per built-in group ---
# Returns "default_action|space-separated-permit-names" for the group.
# Unknown groups return empty (the caller treats that as "no defaults").
default_rules_for_group() {
    local group="$1"
    case "$group" in
        readonly)
            echo "deny|show ping traceroute terminal exit end quit logout who where enable"
            ;;
        operator)
            echo "deny|show ping traceroute terminal exit end quit logout who where enable clear test monitor"
            ;;
        superuser)
            # No specific rules; catchall permit gives unrestricted access.
            echo "permit|"
            ;;
        *)
            echo ""
            ;;
    esac
}

# --- Apply the default rule set to one group (unconditional write) ---
apply_default_rules() {
    local group="$1"
    local spec
    spec=$(default_rules_for_group "$group")
    [[ -z "$spec" ]] && return 1
    local default_action="${spec%%|*}"
    local permit_list="${spec#*|}"
    local payload=""
    for cmd in $permit_list; do
        payload+="${cmd}|permit|"$'\n'
    done
    payload+="*|${default_action}|"
    write_group_commands "$group" "$payload"
}

# --- Seed built-in groups with reasonable default command rules ---
# Usage: tacctl group commands seed [<group>] [--force]
# - No group: seeds all three built-ins (readonly, operator, superuser).
# - With group: seeds only that group (must be a built-in).
# - Refuses to overwrite a group that already has rules unless --force.
cmd_group_commands_seed() {
    local force="false"
    local target=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force)
                force="true"
                shift
                ;;
            -*)
                error "Unknown flag: '$1'"
                cmd_group_commands_usage
                exit 1
                ;;
            *)
                if [[ -n "$target" ]]; then
                    error "seed takes at most one group name; got extra '$1'"
                    exit 1
                fi
                target="$1"
                shift
                ;;
        esac
    done

    local candidates=""
    if [[ -n "$target" ]]; then
        if [[ -z "$(default_rules_for_group "$target")" ]]; then
            error "seed only supports the built-in groups (readonly, operator, superuser)."
            error "Got '${target}'. Custom groups must be configured with 'tacctl group commands add'."
            exit 1
        fi
        candidates="$target"
    else
        candidates="readonly operator superuser"
    fi

    backup_config
    local touched="" skipped=""
    for grp in $candidates; do
        if ! grep -q "^${grp}: &${grp}$" "$CONFIG"; then
            warn "Group '${grp}' does not exist in config; skipping."
            continue
        fi
        if [[ -n "$(read_group_commands "$grp")" ]] && [[ "$force" != "true" ]]; then
            warn "Group '${grp}' already has command rules; skipping (pass --force to overwrite)."
            skipped+=" ${grp}"
            continue
        fi
        # Protect siblings before writing rules to this group — if any
        # other priv-lvl sibling lacks a commands: block, seed it with
        # the permit-* catchall to avoid lockout once Cisco emits
        # 'aaa authorization commands <level>'.
        seed_command_rules_safely "$grp"
        apply_default_rules "$grp"
        touched+=" ${grp}"
    done

    if [[ -n "$touched" ]]; then
        chown tacquito:tacquito "$CONFIG"
        restart_service
        info "Seeded default command rules for:${touched}"
        echo ""
        echo "  Review with:"
        for grp in $touched; do
            echo "    tacctl group commands list ${grp}"
        done
        echo ""
        echo "  Preview the device config with:"
        echo "    tacctl config cisco"
        echo "    tacctl config juniper"
        echo ""
    else
        info "No groups seeded."
        if [[ -n "$skipped" ]]; then
            info "(Skipped:${skipped}. Pass --force to overwrite.)"
        fi
        echo ""
    fi
}

# --- Compute and apply the group's catchall ('*' rule) action ---
update_group_catchall() {
    local group="$1"
    local action="$2"
    # Read current rules, strip any existing catchall, append the new one.
    local current cleaned
    current=$(read_group_commands "$group")
    cleaned=$(printf '%s\n' "$current" | awk -F'|' '$1 != "*" { print }')
    local payload
    payload=$(printf '%s\n*|%s|' "$cleaned" "$action" | awk 'NF')
    write_group_commands "$group" "$payload"
}

# --- Insert a new rule (before the catchall) ---
insert_command_rule() {
    local group="$1" name="$2" action="$3" matches="$4"
    local current default catchall non_catchall payload
    current=$(read_group_commands "$group")
    default=$(read_group_default_action "$group")
    catchall="*|${default}|"
    non_catchall=$(printf '%s\n' "$current" | awk -F'|' '$1 != "*" { print }')
    if [[ -n "$non_catchall" ]]; then
        payload=$(printf '%s\n%s|%s|%s\n%s\n' "$non_catchall" "$name" "$action" "$matches" "$catchall" | awk 'NF')
    else
        payload=$(printf '%s|%s|%s\n%s\n' "$name" "$action" "$matches" "$catchall" | awk 'NF')
    fi
    write_group_commands "$group" "$payload"
}

# --- Remove a rule by name (preserves catchall) ---
remove_command_rule() {
    local group="$1" name="$2"
    local current payload
    current=$(read_group_commands "$group")
    payload=$(printf '%s\n' "$current" | awk -F'|' -v n="$name" '$1 != n { print }')
    write_group_commands "$group" "$payload"
}

# --- Seed catchall-permit rules on sibling groups at the same priv-lvl ---
# When this group is about to gain its first commands: block, ensure
# every other group at the same Cisco priv-lvl ALSO has a (permit *)
# catchall — otherwise, the moment 'aaa authorization commands <level>'
# is in the device config, those siblings' users get denied everything.
#
# Safe to call repeatedly: groups that already have a commands: block
# are left alone.
seed_command_rules_safely() {
    local group="$1"
    local privlvl
    privlvl=$(get_group_privlvl "$group")
    [[ -z "$privlvl" ]] && return 0
    local seeded=""
    while IFS= read -r other; do
        [[ -z "$other" ]] && continue
        [[ "$other" == "$group" ]] && continue
        local other_priv
        other_priv=$(get_group_privlvl "$other")
        [[ "$other_priv" != "$privlvl" ]] && continue
        # Already has a commands: block? Skip.
        if [[ -n "$(read_group_commands "$other")" ]]; then
            continue
        fi
        write_group_commands "$other" "*|permit|"
        seeded+=" ${other}"
    done < <(list_all_groups)
    if [[ -n "$seeded" ]]; then
        info "Auto-seeded permit-* catchall on sibling groups at priv-lvl ${privlvl}:${seeded}"
        info "(prevents lockout once Cisco 'aaa authorization commands ${privlvl}' is applied.)"
    fi
}

# --- GROUP PRIVILEGE (Cisco priv-exec command mappings) ---
# Controls which IOS commands move to a group's priv-lvl via
# 'privilege exec level <N> <command>' lines emitted by
# 'tacctl config cisco'. Pure device-side config; tacquito itself does
# not read this file. Backward-compatible: when the file is missing or
# a group has no explicit mappings, falls back to a safe default set
# (only the verified move-DOWN commands; nothing inadvertently
# restricted from lower-priv groups).
cmd_group_privilege() {
    local subcmd="${1:-}"
    shift 2>/dev/null || true

    case "$subcmd" in
        ""|-h|--help|help)
            cmd_group_privilege_usage
            return
            ;;
        seed)
            cmd_group_privilege_seed "$@"
            return
            ;;
        list|add|remove|clear)
            ;;
        *)
            error "Unknown subcommand: '${subcmd}'"
            cmd_group_privilege_usage
            exit 1
            ;;
    esac

    local group="${1:-}"
    shift 2>/dev/null || true
    if [[ -z "$group" ]]; then
        error "Usage: tacctl group privilege ${subcmd} <group> ..."
        exit 1
    fi
    if ! grep -q "^${group}: &${group}$" "$CONFIG"; then
        error "Group '${group}' does not exist."
        exit 1
    fi

    local privlvl
    privlvl=$(get_group_privlvl "$group")
    if [[ -z "$privlvl" ]]; then
        error "Group '${group}' has no Cisco priv-lvl; nothing to map."
        exit 1
    fi

    case "$subcmd" in
        list)
            local explicit defaults
            explicit=$(read_group_privileges "$group")
            defaults=$(default_privileges_for_group "$group")
            echo ""
            echo -e "${BOLD}Cisco priv-exec mappings for group '${group}' (priv-lvl ${privlvl})${NC}"
            echo "--------------------------------------------"
            if [[ -n "$explicit" ]]; then
                echo -e "  Source: ${BOLD}explicit${NC} (${PRIVILEGE_FILE})"
                echo ""
                echo "$explicit" | while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    echo "  - ${c}"
                done
            elif [[ -n "$defaults" ]]; then
                echo -e "  Source: ${BOLD}default${NC} (no explicit mappings; using built-in safe defaults)"
                echo ""
                echo "$defaults" | while IFS= read -r c; do
                    [[ -z "$c" ]] && continue
                    echo "  - ${c}  (default)"
                done
                echo ""
                echo "  Override with: tacctl group privilege add ${group} '<command>'"
            else
                echo "  (no mappings — group's priv-lvl uses Cisco defaults)"
            fi
            echo ""
            ;;
        add)
            local input="${1:-}"
            if [[ -z "$input" ]]; then
                error "Usage: tacctl group privilege add <group> '<command>'[,'<command>'...]"
                exit 1
            fi
            # Parse comma-separated list, validating each; abort whole op
            # if any are invalid. Cisco exec commands don't contain commas,
            # so the separator is unambiguous.
            local requested="" cmd
            IFS=',' read -ra CMDS <<< "$input"
            for cmd in "${CMDS[@]}"; do
                cmd=$(echo "$cmd" | xargs)
                [[ -z "$cmd" ]] && continue
                validate_priv_command_string "$cmd"
                requested+="${requested:+$'\n'}${cmd}"
            done
            [[ -z "$requested" ]] && { error "No commands provided."; exit 1; }

            local current added="" skipped=""
            current=$(read_group_privileges "$group")
            # If empty, seed from defaults so the user's first add doesn't
            # silently drop the conservative defaults.
            if [[ -z "$current" ]]; then
                current=$(default_privileges_for_group "$group")
            fi
            while IFS= read -r cmd; do
                [[ -z "$cmd" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$cmd"; then
                    skipped+="${skipped:+, }'${cmd}'"
                else
                    added+="${added:+$'\n'}${cmd}"
                    current=$(printf '%s\n%s\n' "$current" "$cmd")
                fi
            done <<< "$requested"

            if [[ -z "$added" ]]; then
                info "No new mappings to add for group '${group}' (already present: ${skipped})."
                echo ""
                return
            fi
            write_group_privileges "$group" "$current"
            local n
            n=$(printf '%s\n' "$added" | wc -l)
            info "Added ${n} priv-exec mapping(s) for group '${group}' (level ${privlvl}):"
            printf '%s\n' "$added" | sed "s/^/    - /"
            [[ -n "$skipped" ]] && info "(Already present, unchanged: ${skipped})"
            echo ""
            ;;
        remove)
            local input="${1:-}"
            if [[ -z "$input" ]]; then
                error "Usage: tacctl group privilege remove <group> '<command>'[,'<command>'...]"
                exit 1
            fi
            local requested="" cmd
            IFS=',' read -ra CMDS <<< "$input"
            for cmd in "${CMDS[@]}"; do
                cmd=$(echo "$cmd" | xargs)
                [[ -z "$cmd" ]] && continue
                requested+="${requested:+$'\n'}${cmd}"
            done
            [[ -z "$requested" ]] && { error "No commands provided."; exit 1; }

            local current removed="" missing=""
            current=$(read_group_privileges "$group")
            # If no explicit mappings exist, seed from defaults so the
            # remove takes effect against a known set.
            if [[ -z "$current" ]]; then
                current=$(default_privileges_for_group "$group")
            fi
            while IFS= read -r cmd; do
                [[ -z "$cmd" ]] && continue
                if printf '%s\n' "$current" | grep -qxF "$cmd"; then
                    removed+="${removed:+$'\n'}${cmd}"
                    current=$(printf '%s\n' "$current" | grep -vxF "$cmd" || true)
                else
                    missing+="${missing:+, }'${cmd}'"
                fi
            done <<< "$requested"

            if [[ -z "$removed" ]]; then
                warn "Nothing to remove for group '${group}' (not mapped: ${missing})."
                exit 0
            fi
            write_group_privileges "$group" "$current"
            local n
            n=$(printf '%s\n' "$removed" | wc -l)
            info "Removed ${n} priv-exec mapping(s) for group '${group}':"
            printf '%s\n' "$removed" | sed "s/^/    - /"
            [[ -n "$missing" ]] && info "(Not mapped, skipped: ${missing})"
            echo ""
            ;;
        clear)
            if [[ -z "$(read_group_privileges "$group")" ]]; then
                info "Group '${group}' has no explicit priv mappings; nothing to clear."
                exit 0
            fi
            read -rp "  Clear all priv-exec mappings for group '${group}'? [y/N]: " confirm
            if [[ ! "$confirm" =~ ^[Yy] ]]; then
                info "Aborted."
                return
            fi
            write_group_privileges "$group" ""
            info "Cleared explicit priv-exec mappings for group '${group}' (defaults will be used)."
            echo ""
            ;;
    esac
}

cmd_group_privilege_usage() {
    echo ""
    echo -e "${BOLD}tacctl group privilege${NC} — per-group Cisco priv-exec command mappings"
    echo ""
    echo "Usage:"
    echo "  tacctl group privilege list <group>                              Show mappings (explicit or default)"
    echo "  tacctl group privilege add <group>    '<cmd>'[,'<cmd>'...]       Move one or more commands to the priv-lvl"
    echo "  tacctl group privilege remove <group> '<cmd>'[,'<cmd>'...]       Remove mapping(s)"
    echo "  tacctl group privilege clear <group>                             Wipe explicit mappings (revert to defaults)"
    echo "  tacctl group privilege seed [<group>] [--force]                  Populate built-ins with safe defaults"
    echo ""
    echo "Drives 'privilege exec level <lvl> <cmd>' lines emitted by"
    echo "'tacctl config cisco'. Pure device-side; tacquito does not read"
    echo "these. When no explicit mappings exist for a group, a conservative"
    echo "default set is used (only commands moved DOWN from priv 15)."
    echo ""
}

cmd_group_privilege_seed() {
    local force="false"
    local target=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --force) force="true"; shift ;;
            -*)
                error "Unknown flag: '$1'"; cmd_group_privilege_usage; exit 1 ;;
            *)
                if [[ -n "$target" ]]; then
                    error "seed takes at most one group name; got extra '$1'"; exit 1
                fi
                target="$1"; shift ;;
        esac
    done

    local candidates=""
    if [[ -n "$target" ]]; then
        if [[ -z "$(default_privileges_for_group "$target")" && "$target" != "readonly" && "$target" != "operator" && "$target" != "superuser" ]]; then
            error "seed only supports the built-in groups (readonly, operator, superuser)."
            exit 1
        fi
        candidates="$target"
    else
        candidates="readonly operator superuser"
    fi

    local touched="" skipped=""
    for grp in $candidates; do
        if ! grep -q "^${grp}: &${grp}$" "$CONFIG"; then
            warn "Group '${grp}' does not exist; skipping."
            continue
        fi
        if [[ -n "$(read_group_privileges "$grp")" ]] && [[ "$force" != "true" ]]; then
            warn "Group '${grp}' already has explicit priv mappings; skipping (pass --force to overwrite)."
            skipped+=" ${grp}"
            continue
        fi
        local defaults
        defaults=$(default_privileges_for_group "$grp")
        write_group_privileges "$grp" "$defaults"
        touched+=" ${grp}"
    done

    if [[ -n "$touched" ]]; then
        info "Seeded default priv-exec mappings for:${touched}"
        echo ""
        echo "  Review with:"
        for grp in $touched; do
            echo "    tacctl group privilege list ${grp}"
        done
        echo ""
        echo "  Preview Cisco device config:"
        echo "    tacctl config cisco"
        echo ""
    else
        info "No groups seeded."
        if [[ -n "$skipped" ]]; then
            info "(Skipped:${skipped}. Pass --force to overwrite.)"
        fi
        echo ""
    fi
}

# --- GROUP dispatcher ---
cmd_group() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        list)
            cmd_group_list
            ;;
        add)
            cmd_group_add "$@"
            ;;
        edit)
            cmd_group_edit "$@"
            ;;
        remove)
            cmd_group_remove "$@"
            ;;
        commands)
            cmd_group_commands "$@"
            ;;
        privilege)
            cmd_group_privilege "$@"
            ;;
        *)
            echo ""
            echo -e "${BOLD}Group Commands${NC}"
            echo ""
            echo "Usage: tacctl group <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                                                List all groups"
            echo "  add <name> <priv-lvl> <juniper-class>               Add a new group"
            echo "  edit <name> priv-lvl <0-15>                         Change Cisco privilege level"
            echo "  edit <name> juniper-class <CLASS>                   Change Juniper class name"
            echo "  remove <name>                                       Remove a custom group"
            echo "  commands list|default|add|remove|clear <group> ...  Per-group authorized commands"
            echo "  privilege list|add|remove|clear|seed <group> ...    Per-group Cisco priv-exec mappings"
            echo ""
            echo "Examples:"
            echo "  tacctl group list"
            echo "  tacctl group add helpdesk 5 HELPDESK-CLASS"
            echo "  tacctl group edit operator priv-lvl 10"
            echo "  tacctl group edit operator juniper-class NEW-CLASS"
            echo "  tacctl group remove helpdesk"
            echo "  tacctl group commands default operator deny"
            echo "  tacctl group commands add operator show --action permit"
            echo "  tacctl group privilege list operator"
            echo "  tacctl group privilege add operator 'show running-config'"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  STATUS & VALIDATION COMMANDS
# =====================================================================

# --- STATUS ---
cmd_status() {
    echo ""
    echo -e "${BOLD}Tacquito Service Status${NC}"
    echo "--------------------------------------------"

    # Service state
    local state
    state=$(systemctl is-active tacquito 2>/dev/null || echo "unknown")
    local state_color="$GREEN"
    [[ "$state" != "active" ]] && state_color="$RED"
    echo -e "  ${BOLD}Service:${NC}              ${state_color}${state}${NC}"

    # Uptime
    if [[ "$state" == "active" ]]; then
        local since
        since=$(systemctl show tacquito --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2)
        echo -e "  ${BOLD}Since:${NC}                ${since}"
    fi

    # PID
    local pid
    pid=$(systemctl show tacquito --property=MainPID 2>/dev/null | cut -d= -f2)
    if [[ -n "$pid" && "$pid" != "0" ]]; then
        echo -e "  ${BOLD}PID:${NC}                  ${pid}"
        # Memory usage
        local mem
        mem=$(ps -o rss= -p "$pid" 2>/dev/null | awk '{printf "%.1f MB", $1/1024}')
        echo -e "  ${BOLD}Memory:${NC}               ${mem}"
    fi

    # Listening port
    local listen
    listen=$(ss -tlnp 2>/dev/null | grep ":49 " | awk '{print $4}' | head -1)
    if [[ -n "$listen" ]]; then
        echo -e "  ${BOLD}Listening:${NC}            ${GREEN}${listen}${NC}"
    else
        echo -e "  ${BOLD}Listening:${NC}            ${RED}port 49 not detected${NC}"
    fi

    # Log level
    # Tolerate no-match: when tacquito is launched with ${TACQUITO_LEVEL}
    # rather than a literal -level flag, grep finds nothing and (under
    # pipefail + set -e) would abort status. `|| true` absorbs that.
    local loglevel
    loglevel=$(systemctl show tacquito --property=ExecStart 2>/dev/null | grep -oP '\-level \K\d+' || true)
    local level_name="unknown"
    case "$loglevel" in
        10) level_name="error" ;;
        20) level_name="info" ;;
        30) level_name="debug" ;;
    esac
    echo -e "  ${BOLD}Log level:${NC}            ${level_name} (${loglevel})"

    # User count
    local user_count
    user_count=$(python3 -c "
import re, sys
config = open(sys.argv[1]).read()
users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
if users_match:
    print(len(re.findall(r'- name:', users_match.group(1))))
else:
    print(0)
" "$CONFIG")
    echo -e "  ${BOLD}Users:${NC}                ${user_count}"

    # Config file
    echo -e "  ${BOLD}Config:${NC}               ${CONFIG}"

    # Accounting log size
    local acct_log="/var/log/tacquito/accounting.log"
    if [[ -f "$acct_log" ]]; then
        local log_size
        log_size=$(du -sh "$acct_log" 2>/dev/null | awk '{print $1}')
        local log_lines
        log_lines=$(wc -l < "$acct_log" 2>/dev/null)
        echo -e "  ${BOLD}Accounting log:${NC}       ${log_size} (${log_lines} entries)"
    fi

    # Backup count
    local backup_count
    backup_count=$(ls -1 "${BACKUP_DIR}"/tacquito.yaml.* 2>/dev/null | wc -l)
    echo -e "  ${BOLD}Config backups:${NC}       ${backup_count}"

    # Prometheus metrics — auth stats
    echo ""
    echo -e "  ${BOLD}Authentication Stats (since last restart):${NC}"
    local metrics
    metrics=$(curl -s http://localhost:8080/metrics 2>/dev/null || true)
    if [[ -n "$metrics" ]]; then
        local auth_pass auth_fail authz_pass authz_fail
        auth_pass=$(echo "$metrics" | grep -P '^tacquito_authenstart_handle_pap ' | awk '{print $2}' | head -1 || true)
        auth_fail=$(echo "$metrics" | grep -P '^tacquito_authenpap_handle_error ' | awk '{print $2}' | head -1 || true)
        authz_pass=$(echo "$metrics" | grep -P '^tacquito_stringy_handle_authorize_accept_pass_add ' | awk '{print $2}' | head -1 || true)
        authz_fail=$(echo "$metrics" | grep -P '^tacquito_stringy_handle_authorize_fail ' | awk '{print $2}' | head -1 || true)

        echo -e "    Auth attempts:      ${auth_pass:-0}"
        echo -e "    Auth errors:        ${auth_fail:-0}"
        echo -e "    Authz granted:      ${authz_pass:-0}"
        echo -e "    Authz denied:       ${authz_fail:-0}"
    else
        echo -e "    ${YELLOW}Metrics unavailable (http://localhost:8080/metrics)${NC}"
    fi

    # Recent errors
    echo ""
    echo -e "  ${BOLD}Recent Errors (last 5):${NC}"
    local errors
    errors=$(journalctl -u tacquito --no-pager -n 100 --since "24 hours ago" 2>/dev/null | grep "ERROR:" | tail -5 || true)
    if [[ -n "$errors" ]]; then
        echo "$errors" | while IFS= read -r line; do
            echo -e "    ${RED}${line}${NC}"
        done
    else
        echo -e "    ${GREEN}No errors in the last 24 hours${NC}"
    fi

    # Security posture — aggregate scope prefixes + per-scope secret check +
    # IPv6/IPv4 ACL parity. Iterates all scopes rather than reading the first
    # secrets[] entry, so multi-scope installs are accurately summarized.
    echo ""
    echo -e "  ${BOLD}Security Posture:${NC}"
    local posture_json
    posture_json=$(python3 - "$CONFIG" "$SECRET_MIN_LENGTH" <<'PY' 2>/dev/null
import json, re, sys, yaml
cfg_path = sys.argv[1]
min_secret = int(sys.argv[2])
with open(cfg_path) as f:
    d = yaml.safe_load(f) or {}

# Collect CIDRs + secret lengths per scope (from secrets: list).
all_cidrs = []
weak_scopes = []
placeholder_scopes = []
empty_prefix_scopes = []
for s in (d.get('secrets') or []):
    name = s.get('name') or '(unnamed)'
    key = (s.get('secret') or {}).get('key') or ''
    opts = s.get('options') or {}
    pfx = opts.get('prefixes') or ''
    cidrs = []
    try:
        cidrs = json.loads(pfx) if pfx else []
    except Exception:
        cidrs = re.findall(r'"([^"]+)"', pfx)
    if not cidrs:
        empty_prefix_scopes.append(name)
    all_cidrs.extend(cidrs)
    if 'REPLACE' in key:
        placeholder_scopes.append(name)
    elif len(key) < min_secret:
        weak_scopes.append(f"{name}:{len(key)}")

cfg_text = open(cfg_path).read()
def flat_list(key):
    m = re.search(r'^' + key + r':\s*\[(.*?)\]', cfg_text, re.MULTILINE)
    return re.findall(r'"([^"]+)"', m.group(1)) if m and m.group(1).strip() else []
allow = flat_list('prefix_allow')

def has_v6(lst):
    return any(':' in c for c in lst)

rfc1918 = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}
unrestricted = rfc1918.issubset(set(all_cidrs)) and len(all_cidrs) == 3

print(f"prefix_count={len(all_cidrs)}")
print(f"prefix_unrestricted={'1' if unrestricted else '0'}")
print(f"prefix_has_v6={'1' if has_v6(all_cidrs) else '0'}")
print(f"allow_has_v6={'1' if has_v6(allow) else '0'}")
print(f"placeholder_scopes={','.join(placeholder_scopes)}")
print(f"weak_scopes={','.join(weak_scopes)}")
print(f"empty_prefix_scopes={','.join(empty_prefix_scopes)}")
PY
)
    local prefix_count=0 prefix_unrestricted=0 prefix_has_v6=0 allow_has_v6=0
    local placeholder_scopes="" weak_scopes="" empty_prefix_scopes=""
    if [[ -n "$posture_json" ]]; then
        eval "$posture_json"
    fi

    if [[ "$prefix_unrestricted" == "1" ]]; then
        echo -e "    ${RED}Prefix scope:       UNRESTRICTED (all RFC 1918 — harden with 'tacctl scopes prefixes <name>')${NC}"
    elif [[ "$prefix_count" -eq 0 ]]; then
        echo -e "    ${RED}Prefix scope:       EMPTY (no clients can connect)${NC}"
    else
        echo -e "    ${GREEN}Prefix scope:       ${prefix_count} CIDR(s) across all scopes${NC}"
    fi
    if [[ -n "$empty_prefix_scopes" ]]; then
        echo -e "      ${YELLOW}scopes with no prefixes: ${empty_prefix_scopes}${NC}"
    fi

    # IPv6 parity warning: if the listener is tcp6 but no IPv6 CIDR exists
    # anywhere in prefixes/allow, IPv4-mapped addresses can bypass ACLs.
    local listener_net
    listener_net=$(read_service_override TACQUITO_NETWORK)
    listener_net=${listener_net:-tcp}
    if [[ "$listener_net" == "tcp6" ]]; then
        if [[ "$prefix_has_v6" != "1" && "$allow_has_v6" != "1" ]]; then
            echo -e "    ${RED}IPv6 ACL parity:    MISSING (listener is tcp6 but no IPv6 CIDRs — v4-mapped clients bypass ACLs)${NC}"
        else
            echo -e "    ${GREEN}IPv6 ACL parity:    present${NC}"
        fi
    fi

    # Shared-secret sanity: flag any scope with a placeholder or short key.
    if [[ -n "$placeholder_scopes" ]]; then
        echo -e "    ${RED}Shared secret:      PLACEHOLDER in scope(s): ${placeholder_scopes} (run 'tacctl scopes secret <name> generate')${NC}"
    elif [[ -n "$weak_scopes" ]]; then
        echo -e "    ${RED}Shared secret:      weak in scope(s): ${weak_scopes} (min ${SECRET_MIN_LENGTH})${NC}"
    else
        echo -e "    ${GREEN}Shared secret:      all scopes ≥ ${SECRET_MIN_LENGTH} chars${NC}"
    fi

    # Management ACL: shared permit list used by Cisco VTY-ACL and the
    # Juniper lo0-filter example. Empty means 'tacctl config cisco'
    # emits a placeholder scaffold and 'tacctl config juniper' emits a
    # comment.
    local mgmt_acl_count
    mgmt_acl_count=$(read_mgmt_acl_cidrs | wc -l)
    if [[ "$mgmt_acl_count" -eq 0 ]]; then
        echo -e "    ${RED}Management ACL:     EMPTY (configure via 'tacctl config mgmt-acl add <cidr>')${NC}"
    else
        echo -e "    ${GREEN}Management ACL:     configured (${mgmt_acl_count} entr$( [[ $mgmt_acl_count -eq 1 ]] && echo "y" || echo "ies" ))${NC}"
    fi

    # Scopes: multi-scope posture. Orphan detection = any user referencing
    # a scope name that has no matching secrets[] entry.
    local all_scopes scope_count="0" user_count_scopes="0"
    all_scopes=$(list_scopes)
    [[ -n "$all_scopes" ]] && scope_count=$(printf '%s\n' "$all_scopes" | wc -l)
    local orphan_report
    orphan_report=$(python3 - "$CONFIG" <<'PY' 2>/dev/null
import yaml, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
names = {s.get('name') for s in (d.get('secrets') or []) if s.get('name')}
empty_scopes = set(names)
orphans = []
total_refs = 0
for u in (d.get('users') or []):
    uname = u.get('name')
    for s in (u.get('scopes') or []):
        total_refs += 1
        if s in names:
            empty_scopes.discard(s)
        else:
            orphans.append(f"{uname}:{s}")
print(f"REFS={total_refs}")
print(f"EMPTY={','.join(sorted(empty_scopes))}")
for o in orphans:
    print(f"ORPHAN={o}")
PY
)
    local total_refs="0" empty_scopes=""
    if [[ -n "$orphan_report" ]]; then
        total_refs=$(echo "$orphan_report" | awk -F= '/^REFS=/{print $2}')
        empty_scopes=$(echo "$orphan_report" | awk -F= '/^EMPTY=/{print $2}')
    fi
    local orphan_lines
    orphan_lines=$(echo "$orphan_report" | awk -F= '/^ORPHAN=/{print $2}' || true)
    if [[ "$scope_count" -eq 0 ]]; then
        echo -e "    ${RED}Scopes:             NONE (no auth targets defined)${NC}"
    elif [[ -n "$orphan_lines" ]]; then
        echo -e "    ${RED}Scopes:             ORPHAN references — users point at missing scopes${NC}"
        echo "$orphan_lines" | while IFS= read -r pair; do
            local u="${pair%%:*}"
            local s="${pair#*:}"
            echo -e "      ${RED}user '${u}' → scope '${s}' (does not exist)${NC}"
        done
    else
        echo -e "    ${GREEN}Scopes:             configured (${scope_count} scope(s), ${total_refs} user grant(s))${NC}"
        if [[ -n "$empty_scopes" ]]; then
            echo -e "      ${YELLOW}empty scope(s): ${empty_scopes} (no users — intentional?)${NC}"
        fi
    fi
    local def_scope
    def_scope=$(read_default_scope)
    if [[ -z "$def_scope" ]]; then
        echo -e "    ${YELLOW}Default scope:      UNSET (tacctl user add without --scopes will fail)${NC}"
    else
        echo -e "    ${GREEN}Default scope:      ${def_scope}${NC}"
    fi

    # Password age warnings
    echo ""
    echo -e "  ${BOLD}Password Age Warnings:${NC}"
    local pw_warnings=0
    local today
    today=$(date +%s)
    if [[ -d "$PASSWORD_DATES_DIR" ]]; then
        for datefile in "${PASSWORD_DATES_DIR}"/*.date; do
            [[ -f "$datefile" ]] || continue
            local uname pw_date pw_epoch age_days
            uname=$(basename "$datefile" .date)
            pw_date=$(cat "$datefile")
            pw_epoch=$(date -d "$pw_date" +%s 2>/dev/null || echo 0)
            if [[ "$pw_epoch" -gt 0 ]]; then
                age_days=$(( (today - pw_epoch) / 86400 ))
                if [[ "$age_days" -gt "$PASSWORD_MAX_AGE_DAYS" ]]; then
                    echo -e "    ${YELLOW}${uname}: password is ${age_days} days old (changed ${pw_date})${NC}"
                    pw_warnings=$((pw_warnings + 1))
                fi
            fi
        done
    fi
    if [[ "$pw_warnings" -eq 0 ]]; then
        echo -e "    ${GREEN}No passwords older than ${PASSWORD_MAX_AGE_DAYS} days${NC}"
    fi

    echo ""
}

# --- CONFIG VALIDATE ---
cmd_config_validate() {
    echo ""
    echo -e "${BOLD}Validating ${CONFIG}...${NC}"
    echo ""

    local errors=0

    # Check YAML syntax
    if python3 -c "import yaml; yaml.safe_load(open('$CONFIG'))" 2>/dev/null; then
        echo -e "  ${GREEN}YAML syntax:${NC}          valid"
    else
        echo -e "  ${RED}YAML syntax:${NC}          INVALID"
        python3 -c "import yaml; yaml.safe_load(open('$CONFIG'))" 2>&1 | head -3
        errors=$((errors + 1))
    fi

    # Check required sections exist
    local result
    result=$(python3 -c "
import re, sys

config = open(sys.argv[1]).read()
DISABLED_MARKER = sys.argv[2]
errors = []

# Check for users section
if not re.search(r'^users:', config, re.MULTILINE):
    errors.append('Missing users: section')

# Check for secrets section
if not re.search(r'^secrets:', config, re.MULTILINE):
    errors.append('Missing secrets: section')

# Check for at least one user
users_match = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
if users_match:
    users = re.findall(r'- name: (\S+)', users_match.group(1))
    if len(users) == 0:
        errors.append('No users defined')
    else:
        # Check each user has a bcrypt anchor
        for u in users:
            if not re.search(r'^bcrypt_' + re.escape(u) + r':', config, re.MULTILINE):
                errors.append(f'User \"{u}\" has no bcrypt authenticator anchor')

        # Check for DISABLED or empty hashes
        for m in re.finditer(r'^bcrypt_(\w+):.*?hash:\s*(\S+)', config, re.MULTILINE | re.DOTALL):
            username = m.group(1)
            h = m.group(2)
            if h == 'REPLACE_ME':
                errors.append(f'User \"{username}\" has placeholder hash (REPLACE_ME)')
            elif h == 'DISABLED' or h == DISABLED_MARKER:
                pass  # valid state (legacy or well-formed marker)
            elif len(h) < 20:
                errors.append(f'User \"{username}\" has suspiciously short hash')

# Check shared secret
secret_match = re.search(r'key:\s*\"?([^\"\n]+)\"?', config)
if not secret_match:
    errors.append('No shared secret (key:) found in secrets section')
elif 'REPLACE' in secret_match.group(1):
    errors.append('Shared secret contains placeholder value')

# Check prefixes
prefix_match = re.search(r'prefixes:', config)
if not prefix_match:
    errors.append('No prefixes defined in secrets section')

if errors:
    for e in errors:
        print(f'ERROR:{e}')
else:
    print('OK')
" "$CONFIG" "$DISABLED_MARKER_HEX")

    if [[ "$result" == "OK" ]]; then
        echo -e "  ${GREEN}Config structure:${NC}      valid"
    else
        echo "$result" | while IFS= read -r line; do
            local msg="${line#ERROR:}"
            echo -e "  ${RED}Error:${NC}                ${msg}"
            errors=$((errors + 1))
        done
    fi

    # Scope integrity: every user's scopes[] must reference an existing
    # secrets[].name; the default-scope marker must also name one.
    local scope_report
    scope_report=$(python3 - "$CONFIG" "$DEFAULT_SCOPE_FILE" <<'PY' 2>/dev/null
import yaml, os, sys
with open(sys.argv[1]) as f:
    d = yaml.safe_load(f) or {}
names = [s.get('name') for s in (d.get('secrets') or []) if s.get('name')]
name_set = set(names)
issues = []
# Flat-emission invariant: every entry sharing a name must share its
# secret.key. Divergence means one or more entries will auth with a
# stale key, producing non-deterministic "bad secret" failures on the
# subset of prefixes that rolled their key.
keys_by_name = {}
for s in (d.get('secrets') or []):
    nm = s.get('name')
    if not nm:
        continue
    k = (s.get('secret') or {}).get('key') or ''
    keys_by_name.setdefault(nm, []).append(k)
for nm, keys in keys_by_name.items():
    uniq = set(keys)
    if len(uniq) > 1:
        issues.append(f"Scope '{nm}' has {len(keys)} entries but {len(uniq)} distinct secret.key values — entries must share a key")
for u in (d.get('users') or []):
    uname = u.get('name')
    for s in (u.get('scopes') or []):
        if s not in name_set:
            issues.append(f"User '{uname}' references nonexistent scope '{s}'")
# Default-scope marker
marker_path = sys.argv[2]
if os.path.isfile(marker_path):
    try:
        val = open(marker_path).read().strip().splitlines()
        val = val[0] if val else ''
    except Exception:
        val = ''
    if val and val not in name_set:
        issues.append(f"Default-scope marker points at '{val}' which is not a defined scope")
for i in issues:
    print(f"ERROR:{i}")
if not issues:
    print('OK')
PY
)
    if [[ "$scope_report" == "OK" ]]; then
        echo -e "  ${GREEN}Scopes integrity:${NC}      valid"
    else
        echo "$scope_report" | while IFS= read -r line; do
            [[ "$line" == ERROR:* ]] || continue
            local msg="${line#ERROR:}"
            echo -e "  ${RED}Error:${NC}                ${msg}"
            errors=$((errors + 1))
        done
    fi

    # Check services
    local svc_count
    svc_count=$(grep -c "name: exec\|name: junos-exec" "$CONFIG" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}Services defined:${NC}     ${svc_count}"

    # Check groups
    local grp_count
    grp_count=$(grep -c "^[a-z].*: &" "$CONFIG" 2>/dev/null | head -1)
    echo -e "  ${GREEN}Groups/anchors:${NC}       ${grp_count}"

    # User count
    local user_count
    user_count=$(python3 -c "
import re
config = open('$CONFIG').read()
m = re.search(r'^users:\s*\n(.*?)(?=^# ---|\Z)', config, re.MULTILINE | re.DOTALL)
print(len(re.findall(r'- name:', m.group(1))) if m else 0)
")
    echo -e "  ${GREEN}Users defined:${NC}        ${user_count}"

    echo ""
    if [[ "$errors" -gt 0 ]]; then
        error "Validation failed with ${errors} error(s)."
        return 1
    else
        info "Configuration is valid."
    fi
    echo ""
}

# --- CONFIG LOGLEVEL ---
cmd_config_loglevel() {
    local new_level="${1:-}"

    local current_num
    current_num=$(read_service_override TACQUITO_LEVEL)
    current_num=${current_num:-20}

    if [[ -z "$new_level" ]]; then
        local level_name="unknown"
        case "$current_num" in
            10) level_name="error" ;;
            20) level_name="info" ;;
            30) level_name="debug" ;;
        esac
        echo ""
        echo "  Current log level: ${level_name} (${current_num})"
        echo ""
        echo "  Usage: tacctl config loglevel <debug|info|error>"
        echo ""
        return
    fi

    local level_num
    case "$new_level" in
        debug)  level_num=30 ;;
        info)   level_num=20 ;;
        error)  level_num=10 ;;
        *)
            error "Invalid level: ${new_level}. Use: debug, info, or error"
            return 1
            ;;
    esac

    if [[ "$current_num" == "$level_num" ]]; then
        info "Already at ${new_level} (${level_num})."
        return
    fi

    # Default level (20) uses the template default -- clear the override
    # instead of pinning it, so future template bumps can move the default.
    if [[ "$level_num" == "20" ]]; then
        clear_service_override TACQUITO_LEVEL
    else
        set_service_override TACQUITO_LEVEL "$level_num"
    fi
    systemctl daemon-reload
    systemctl restart tacquito

    info "Log level changed to ${new_level} (${level_num}). Service restarted."
    echo ""
}

# --- CONFIG LISTEN ---
cmd_config_listen() {
    local sub="${1:-}"
    local addr="${2:-}"

    local current_net current_addr net_src addr_src
    current_net=$(read_service_override TACQUITO_NETWORK)
    if [[ -n "$current_net" ]]; then net_src="override"; else net_src="default"; fi
    current_net=${current_net:-tcp}
    current_addr=$(read_service_override TACQUITO_ADDRESS)
    if [[ -n "$current_addr" ]]; then addr_src="override"; else addr_src="default"; fi
    current_addr=${current_addr:-:49}

    case "$sub" in
        ""|show)
            echo ""
            echo "  Current listener: ${current_net} ${current_addr}"
            if [[ "$net_src" == "override" || "$addr_src" == "override" ]]; then
                echo "  (override in ${OVERRIDE_FILE})"
            else
                echo "  (template default)"
            fi
            echo ""
            echo "  Usage: tacctl config listen <show|tcp|tcp6|reset> [address]"
            echo "  Examples:"
            echo "    tacctl config listen tcp :49"
            echo "    tacctl config listen tcp 10.1.0.1:49"
            echo "    tacctl config listen tcp6 [::]:49"
            echo "    tacctl config listen reset       # drop override, use template default"
            echo ""
            return
            ;;
        reset)
            if [[ "$net_src" == "default" && "$addr_src" == "default" ]]; then
                info "No listener override set. Already on template default (${current_net} ${current_addr})."
                return
            fi
            clear_service_override TACQUITO_NETWORK
            clear_service_override TACQUITO_ADDRESS
            systemctl daemon-reload
            systemctl restart tacquito
            if systemctl is-active --quiet tacquito; then
                info "Listener override removed. Using template default. Service restarted."
            else
                error "tacquito failed to start after reset."
                return 1
            fi
            echo ""
            return
            ;;
        tcp|tcp6)
            ;;
        *)
            error "Invalid subcommand: '${sub}'. Use: show, tcp, tcp6, or reset"
            return 1
            ;;
    esac

    if [[ -z "$addr" ]]; then
        error "Missing address. Example: tacctl config listen ${sub} :49"
        return 1
    fi

    validate_listen_address "$sub" "$addr" || return 1

    if [[ "$current_net" == "$sub" && "$current_addr" == "$addr" ]]; then
        info "Already listening on ${sub} ${addr}."
        return
    fi

    if [[ "$sub" == "tcp6" && "$current_net" != "tcp6" ]]; then
        echo ""
        warn "tcp6 enables dual-stack sockets on most platforms."
        warn "IPv4 clients connect with mapped addresses (::ffff:a.b.c.d)"
        warn "which do NOT match IPv4 rules in 'tacctl scopes prefixes <name>',"
        warn "'config allow', or 'config deny' -- effectively bypassing them."
        echo ""
        read -rp "  Proceed with tcp6? [y/N]: " confirm
        if [[ ! "$confirm" =~ ^[Yy] ]]; then
            info "Aborted."
            return
        fi
    fi

    # Snapshot override file for rollback if restart fails.
    local had_override="false"
    if [[ -f "$OVERRIDE_FILE" ]]; then
        cp "$OVERRIDE_FILE" "${OVERRIDE_FILE}.bak"
        had_override="true"
    fi

    set_service_override TACQUITO_NETWORK "$sub"
    set_service_override TACQUITO_ADDRESS "$addr"

    systemctl daemon-reload
    systemctl restart tacquito

    if systemctl is-active --quiet tacquito; then
        info "Listener changed to ${sub} ${addr}. Service restarted."
        rm -f "${OVERRIDE_FILE}.bak"
    else
        error "tacquito failed to start. Restoring previous override."
        if [[ "$had_override" == "true" ]]; then
            mv "${OVERRIDE_FILE}.bak" "$OVERRIDE_FILE"
        else
            rm -f "$OVERRIDE_FILE"
            rmdir "$OVERRIDE_DIR" 2>/dev/null || true
        fi
        systemctl daemon-reload
        systemctl restart tacquito
        return 1
    fi
    echo ""
}

# --- CONFIG SUDOERS ---
# Manages an optional /etc/sudoers.d/tacctl drop-in that grants NOPASSWD
# on /usr/local/bin/tacctl to a given group. Not installed by default --
# operators opt in explicitly.
SUDOERS_FILE="/etc/sudoers.d/tacctl"

cmd_config_sudoers() {
    local sub="${1:-}"
    local group="${2:-adm}"

    # Accept "%adm" or "adm" -- normalize to the bare group name.
    group="${group#%}"

    case "$sub" in
        ""|show)
            echo ""
            if [[ -f "$SUDOERS_FILE" ]]; then
                echo "  Status: installed at ${SUDOERS_FILE}"
                echo ""
                echo "  Contents:"
                sed 's/^/    /' "$SUDOERS_FILE"
            else
                echo "  Status: not installed"
            fi
            echo ""
            echo "  Usage: tacctl config sudoers <show|install|remove> [group]"
            echo "  Examples:"
            echo "    tacctl config sudoers install          # grant to group 'adm'"
            echo "    tacctl config sudoers install wheel    # grant to group 'wheel'"
            echo "    tacctl config sudoers remove"
            echo ""
            return
            ;;
        install) ;;
        remove)
            if [[ ! -f "$SUDOERS_FILE" ]]; then
                info "Not installed. Nothing to remove."
                return
            fi
            rm -f "$SUDOERS_FILE"
            info "Removed ${SUDOERS_FILE}."
            return
            ;;
        *)
            error "Invalid subcommand: '${sub}'. Use: show, install, or remove"
            return 1
            ;;
    esac

    if ! [[ "$group" =~ ^[a-zA-Z_][a-zA-Z0-9_-]*$ ]]; then
        error "Invalid group name: '${group}'"
        return 1
    fi

    # Confirm -- this grants the group passwordless root via tacctl.
    echo ""
    warn "This grants members of group '%${group}' passwordless sudo on"
    warn "/usr/local/bin/tacctl, which can modify system config and restart"
    warn "services. Effectively passwordless root for that group."
    echo ""
    read -rp "  Install ${SUDOERS_FILE} for group '%${group}'? [y/N]: " confirm
    if [[ ! "$confirm" =~ ^[Yy] ]]; then
        info "Aborted."
        return
    fi

    local tmp
    tmp=$(mktemp)
    cat > "$tmp" <<EOF
# Managed by tacctl. Grants passwordless sudo on /usr/local/bin/tacctl
# to members of group '${group}'. Remove with: tacctl config sudoers remove
%${group} ALL=(ALL) NOPASSWD: /usr/local/bin/tacctl
EOF

    if ! visudo -cf "$tmp" >/dev/null; then
        error "visudo validation failed. Not installed."
        rm -f "$tmp"
        return 1
    fi

    install -m 0440 -o root -g root "$tmp" "$SUDOERS_FILE"
    rm -f "$tmp"
    info "Installed ${SUDOERS_FILE} for group '%${group}'."
    echo ""
}

# --- CONFIG PASSWORD-AGE ---
cmd_config_password_age() {
    local new_days="${1:-}"

    if [[ -z "$new_days" ]]; then
        echo ""
        echo "  Password age warning threshold: ${PASSWORD_MAX_AGE_DAYS} days"
        echo ""
        echo "  Usage: tacctl config password-age <days>"
        echo ""
        return
    fi

    if ! [[ "$new_days" =~ ^[0-9]+$ ]] || [[ "$new_days" -lt 1 ]]; then
        error "Days must be a positive number."
        exit 1
    fi

    echo "$new_days" > "$PASSWORD_MAX_AGE_FILE"
    chmod 644 "$PASSWORD_MAX_AGE_FILE"
    PASSWORD_MAX_AGE_DAYS="$new_days"
    info "Password age warning threshold set to ${new_days} days."
    echo ""
}

# --- CONFIG BCRYPT-COST ---
# Cost factor affects only NEW hashes; existing hashes verify at whatever
# cost they were minted with. Higher = slower login + stronger.
cmd_config_bcrypt_cost() {
    local new_cost="${1:-}"

    if [[ -z "$new_cost" ]]; then
        echo ""
        echo "  Bcrypt cost factor: ${BCRYPT_COST}"
        echo "  (New hashes only — existing hashes keep their minted cost.)"
        echo ""
        echo "  Usage: tacctl config bcrypt-cost <10-14>"
        echo "  Typical wall-clock on a modern CPU: 10≈100ms, 12≈300ms, 14≈1.2s"
        echo ""
        return
    fi

    if ! [[ "$new_cost" =~ ^[0-9]+$ ]] || [[ "$new_cost" -lt 10 || "$new_cost" -gt 14 ]]; then
        error "Cost must be an integer between 10 and 14."
        exit 1
    fi

    echo "$new_cost" > "$BCRYPT_COST_FILE"
    chmod 644 "$BCRYPT_COST_FILE"
    BCRYPT_COST="$new_cost"
    info "Bcrypt cost set to ${new_cost}. Applies to new/changed passwords."
    echo ""
}

# --- CONFIG PASSWORD-MIN-LENGTH ---
# Floor enforced by validate_password_strength on user-supplied passwords.
# Auto-generated passwords (when the user accepts the prompt's blank
# default) bypass this — they're always 24+ chars.
cmd_config_password_min_length() {
    local new_len="${1:-}"

    if [[ -z "$new_len" ]]; then
        echo ""
        echo "  Password minimum length: ${PASSWORD_MIN_LENGTH}"
        echo "  (Enforced on interactively-entered passwords; auto-generated bypass.)"
        echo ""
        echo "  Usage: tacctl config password-min-length <8-64>"
        echo "  Guidance: NIST 800-63 floor is 8; OWASP 2025 recommends ≥12."
        echo ""
        return
    fi

    if ! [[ "$new_len" =~ ^[0-9]+$ ]] || [[ "$new_len" -lt 8 || "$new_len" -gt 64 ]]; then
        error "Length must be an integer between 8 and 64."
        exit 1
    fi

    echo "$new_len" > "$PASSWORD_MIN_LENGTH_FILE"
    chmod 644 "$PASSWORD_MIN_LENGTH_FILE"
    PASSWORD_MIN_LENGTH="$new_len"
    info "Password minimum length set to ${new_len}. Applies to new/changed passwords."
    echo ""
}

# --- CONFIG SECRET-MIN-LENGTH ---
# Floor enforced when the operator types a custom shared secret. The
# auto-gen path ('openssl rand -base64 24') always exceeds this.
cmd_config_secret_min_length() {
    local new_len="${1:-}"

    if [[ -z "$new_len" ]]; then
        echo ""
        echo "  Shared-secret minimum length: ${SECRET_MIN_LENGTH}"
        echo "  (Enforced on user-supplied secrets; auto-generated bypass.)"
        echo ""
        echo "  Usage: tacctl config secret-min-length <16-128>"
        echo "  Guidance: Cisco TACACS+ best practice is ≥16."
        echo ""
        return
    fi

    if ! [[ "$new_len" =~ ^[0-9]+$ ]] || [[ "$new_len" -lt 16 || "$new_len" -gt 128 ]]; then
        error "Length must be an integer between 16 and 128."
        exit 1
    fi

    echo "$new_len" > "$SECRET_MIN_LENGTH_FILE"
    chmod 644 "$SECRET_MIN_LENGTH_FILE"
    SECRET_MIN_LENGTH="$new_len"
    info "Shared-secret minimum length set to ${new_len}. Applies to new secrets."
    echo ""
}

# =====================================================================
#  LOG COMMANDS
# =====================================================================

cmd_log() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        tail)
            local count="${1:-20}"
            echo ""
            echo -e "${BOLD}Recent TACACS+ Log Entries${NC}"
            echo "--------------------------------------------"
            journalctl -u tacquito --no-pager -n "$count" 2>/dev/null || echo "  No log entries found."
            echo ""
            ;;
        search)
            local term="${1:-}"
            if [[ -z "$term" ]]; then
                error "Usage: tacctl log search <username>"
                exit 1
            fi
            echo ""
            echo -e "${BOLD}Log entries matching '${term}'${NC}"
            echo "--------------------------------------------"
            journalctl -u tacquito --no-pager --since "7 days ago" 2>/dev/null | grep -i "$term" || echo "  No matches found."
            echo ""
            ;;
        failures)
            echo ""
            echo -e "${BOLD}Authentication Failures (last 24 hours)${NC}"
            echo "--------------------------------------------"
            local failures
            failures=$(journalctl -u tacquito --no-pager --since "24 hours ago" 2>/dev/null | grep -i "ERROR\|fail\|bad secret" || true)
            if [[ -n "$failures" ]]; then
                echo "$failures"
            else
                echo -e "  ${GREEN}No failures in the last 24 hours${NC}"
            fi
            echo ""
            ;;
        accounting)
            local count="${1:-20}"
            echo ""
            echo -e "${BOLD}Recent Accounting Entries${NC}"
            echo "--------------------------------------------"
            if [[ -f "$ACCT_LOG" ]]; then
                tail -n "$count" "$ACCT_LOG"
            else
                echo "  No accounting log found at ${ACCT_LOG}"
            fi
            echo ""
            ;;
        *)
            echo ""
            echo -e "${BOLD}Log Commands${NC}"
            echo ""
            echo "Usage: tacctl log <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  tail [n]              Show last N journal entries (default 20)"
            echo "  search <term>         Search journal for a username or keyword"
            echo "  failures              Show auth failures from the last 24 hours"
            echo "  accounting [n]        Show last N accounting log entries"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  BACKUP COMMANDS
# =====================================================================

cmd_backup() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        list)
            echo ""
            echo -e "${BOLD}Config Backups${NC}"
            echo "--------------------------------------------"
            if ls "${BACKUP_DIR}"/tacquito.yaml.* &>/dev/null; then
                printf "  ${BOLD}%-25s %-10s${NC}\n" "TIMESTAMP" "SIZE"
                echo "  -----------------------------------"
                ls -1t "${BACKUP_DIR}"/tacquito.yaml.* | while IFS= read -r f; do
                    local ts size
                    ts=$(basename "$f" | sed 's/tacquito\.yaml\.//')
                    size=$(du -sh "$f" 2>/dev/null | awk '{print $1}')
                    printf "  %-25s %-10s\n" "$ts" "$size"
                done
            else
                echo "  No backups found."
            fi
            echo ""
            ;;
        diff)
            local timestamp="${1:-}"
            local backup_file=""

            if [[ -z "$timestamp" ]]; then
                # Use most recent backup
                backup_file=$(ls -1t "${BACKUP_DIR}"/tacquito.yaml.* 2>/dev/null | head -1)
                if [[ -z "$backup_file" ]]; then
                    error "No backups found."
                    exit 1
                fi
            else
                backup_file="${BACKUP_DIR}/tacquito.yaml.${timestamp}"
                if [[ ! -f "$backup_file" ]]; then
                    error "Backup not found: ${timestamp}"
                    error "Run 'tacctl backup list' to see available backups."
                    exit 1
                fi
            fi

            local ts
            ts=$(basename "$backup_file" | sed 's/tacquito\.yaml\.//')
            echo ""
            echo -e "${BOLD}Diff: current config vs backup ${ts}${NC}"
            echo "--------------------------------------------"
            diff --color=always "$backup_file" "$CONFIG" || true
            echo ""
            ;;
        restore)
            local timestamp="${1:-}"
            if [[ -z "$timestamp" ]]; then
                error "Usage: tacctl backup restore <timestamp>"
                error "Run 'tacctl backup list' to see available backups."
                exit 1
            fi

            local backup_file="${BACKUP_DIR}/tacquito.yaml.${timestamp}"
            if [[ ! -f "$backup_file" ]]; then
                error "Backup not found: ${timestamp}"
                exit 1
            fi

            echo ""
            echo "  Restoring config from: ${timestamp}"
            echo ""
            echo -e "  ${BOLD}Changes that will be applied:${NC}"
            diff --color=always "$CONFIG" "$backup_file" || true
            echo ""

            read -rp "  Restore this backup? [y/N]: " confirm
            if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
                info "Cancelled."
                exit 0
            fi

            # Back up current config before restoring (safety net)
            backup_config

            cp "$backup_file" "$CONFIG"
            chown tacquito:tacquito "$CONFIG"
            chmod 640 "$CONFIG"
            restart_service
            info "Config restored from backup ${timestamp}."
            echo ""
            ;;
        *)
            echo ""
            echo -e "${BOLD}Backup Commands${NC}"
            echo ""
            echo "Usage: tacctl backup <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                  Show available backups"
            echo "  diff [timestamp]      Diff current config vs a backup (default: most recent)"
            echo "  restore <timestamp>   Restore a backup (with confirmation)"
            echo ""
            exit 1
            ;;
    esac
}

# =====================================================================
#  SYSTEM LIFECYCLE COMMANDS
# =====================================================================

# --- HASH (bcrypt hash helper — does not require root) ---
cmd_hash() {
    local subcmd="${1:-}"
    case "$subcmd" in
        ""|-h|--help|help)
            cmd_hash_usage
            ;;
        generate)
            cmd_hash_generate
            ;;
        commands)
            cmd_hash_commands
            ;;
        *)
            error "Unknown subcommand: '$subcmd'"
            cmd_hash_usage
            exit 1
            ;;
    esac
}

cmd_hash_usage() {
    echo ""
    echo -e "${BOLD}tacctl hash${NC} — bcrypt hash helper (non-root)"
    echo ""
    echo "Usage:"
    echo "  tacctl hash generate                Prompt for a password and print its bcrypt hash"
    echo "  tacctl hash commands                Show OS-specific one-liners for offline generation"
    echo ""
    echo "Use 'generate' when you can shell in to this server."
    echo "Use 'commands' to hand an operator a command they can run on their own machine,"
    echo "so the plaintext password never leaves their laptop."
    echo ""
    echo "Either output plugs into:"
    echo "  tacctl user add <username> <group> --hash '<hash>'"
    echo "  tacctl user passwd <username> --hash '<hash>'"
    echo ""
    echo "Both accept either form — hex ('24326224...') or raw ('\$2b\$12\$...')."
    echo ""
}

cmd_hash_generate() {
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        error "python3-bcrypt not installed. Run 'tacctl hash commands' for client-side alternatives."
        exit 1
    fi
    local password
    password=$(prompt_password)
    local hash
    hash=$(generate_hash "$password")
    unset password
    echo ""
    echo "  Bcrypt hash (provide this to your admin):"
    echo ""
    echo "  ${hash}"
    echo ""
    echo "  Admin command:"
    echo "    tacctl user add <username> <group> --hash '${hash}'"
    echo ""
}

# Client-side bcrypt generation recipes. Intentionally verbose — this is
# the page an operator will paste from when the server isn't reachable,
# so brevity costs more than paper. Each recipe prints BOTH the raw
# '$2b$...' form and the hex form; 'tacctl user add --hash' accepts either.
cmd_hash_commands() {
    cat <<'EOF'

  Bcrypt hash generation — client-side recipes
  (run on the operator's machine; plaintext password never leaves it)

  =================================================================
  Any OS — Python 3 with the 'bcrypt' module
  =================================================================
    # install once:  python3 -m pip install --user bcrypt
    #                (use 'py' instead of 'python3' on Windows)
    python3 -c "import bcrypt,binascii,getpass; p=getpass.getpass('Password: ').encode(); r=bcrypt.hashpw(p,bcrypt.gensalt(12)); print('raw:',r.decode()); print('hex:',binascii.hexlify(r).decode())"

  =================================================================
  Linux / macOS — htpasswd (no Python needed)
  =================================================================
    # install once:  apt install apache2-utils  OR  brew install httpd
    htpasswd -nBC 12 "" | cut -d: -f2

  =================================================================
  Windows — PowerShell with BCrypt.Net (no Python needed)
  =================================================================
    Install-Module BCrypt.Net-Next -Scope CurrentUser -Force
    $pw  = (Get-Credential -UserName '_' -Message 'Password').GetNetworkCredential().Password
    $raw = [BCrypt.Net.BCrypt]::HashPassword($pw, 12)
    $hex = -join ($raw.ToCharArray() | % { '{0:x2}' -f [byte][char]$_ })
    "raw: $raw"
    "hex: $hex"

  =================================================================
  Handing the hash to your admin
  =================================================================
  'tacctl user passwd --hash' accepts either form; the server
  normalizes to hex internally. So either line works:
      tacctl user passwd <user> --hash '$2b$12$...'          # raw
      tacctl user passwd <user> --hash '24326224313224...'   # hex

EOF
}

# --- INSTALL ---
cmd_install() {
    # Parse optional --branch flag
    local INSTALL_BRANCH=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --branch) INSTALL_BRANCH="${2:-}"; shift 2 ;;
            *) shift ;;
        esac
    done

    for cmd in git wget python3; do
        if ! command -v "$cmd" &>/dev/null; then
            error "Required command '$cmd' not found. Install it first."
            exit 1
        fi
    done

    local PROJECT_DIR
    PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

    echo ""
    echo "============================================"
    echo "  Tacquito TACACS+ Server Installer"
    echo "============================================"
    echo ""
    echo "This will:"
    echo "  - Install Go ${GO_VERSION} (if not present)"
    echo "  - Clone and build tacquito from source"
    echo "  - Create a 'tacquito' service user"
    echo "  - Configure and start the TACACS+ service on port 49"
    echo "  - Prompt for shared secret and user passwords"
    echo ""

    read -rp "Continue with installation? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    echo ""

    # --- Step 1: Install Go ---
    if command -v /usr/local/go/bin/go &>/dev/null; then
        local CURRENT_GO
        CURRENT_GO=$(/usr/local/go/bin/go version | awk '{print $3}')
        if [[ "$CURRENT_GO" == "go${GO_VERSION}" ]]; then
            info "Go ${GO_VERSION} already installed, skipping."
        else
            warn "Go ${CURRENT_GO} found, upgrading to ${GO_VERSION}..."
            rm -rf /usr/local/go
        fi
    fi

    if ! command -v /usr/local/go/bin/go &>/dev/null; then
        info "Installing Go ${GO_VERSION}..."
        cd /tmp
        wget -q "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz"
        # Verify checksum
        local GO_SHA256
        GO_SHA256=$(wget -qO- "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz.sha256" 2>/dev/null || true)
        if [[ -n "$GO_SHA256" ]]; then
            local ACTUAL_SHA256
            ACTUAL_SHA256=$(sha256sum "go${GO_VERSION}.linux-amd64.tar.gz" | awk '{print $1}')
            if [[ "$GO_SHA256" != "$ACTUAL_SHA256" ]]; then
                error "Go tarball checksum mismatch!"
                error "  Expected: ${GO_SHA256}"
                error "  Got:      ${ACTUAL_SHA256}"
                rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
                exit 1
            fi
            info "Go tarball checksum verified."
        else
            warn "Could not fetch Go checksum for verification."
        fi
        tar -C /usr/local -xzf "go${GO_VERSION}.linux-amd64.tar.gz"
        rm -f "go${GO_VERSION}.linux-amd64.tar.gz"
        info "Go ${GO_VERSION} installed."
    fi

    export PATH=$PATH:/usr/local/go/bin

    # --- Step 2: Clone and build tacquito ---
    if [[ -d "$TACQUITO_SRC" ]]; then
        info "Tacquito source already exists at ${TACQUITO_SRC}, pulling latest..."
        cd "$TACQUITO_SRC" && git pull --quiet
    else
        info "Cloning tacquito..."
        git clone --quiet "$TACQUITO_REPO" "$TACQUITO_SRC"
    fi

    info "Building tacquito server..."
    cd "${TACQUITO_SRC}/cmds/server"
    go build -o "$TACQUITO_BIN" .

    info "Building password hash generator..."
    cd "${TACQUITO_SRC}/cmds/server/config/authenticators/bcrypt/generator"
    go build -o "$HASHGEN_BIN" .

    info "Binaries installed:"
    info "  Server:  ${TACQUITO_BIN}"
    info "  Hashgen: ${HASHGEN_BIN}"

    # Clone management repo for future upgrades
    local branch_flag=""
    [[ -n "$INSTALL_BRANCH" ]] && branch_flag="--branch $INSTALL_BRANCH"
    if [[ -d "${DEPLOY_DIR}/.git" ]]; then
        info "Management repo already cloned at ${DEPLOY_DIR}, pulling latest..."
        cd "$DEPLOY_DIR"
        [[ -n "$INSTALL_BRANCH" ]] && git checkout "$INSTALL_BRANCH" &>/dev/null || true
        git pull --quiet 2>/dev/null || true
    else
        [[ -d "$DEPLOY_DIR" ]] && rm -rf "$DEPLOY_DIR"
        git clone --quiet $branch_flag "$MANAGE_REPO" "$DEPLOY_DIR"
        info "Management repo cloned to ${DEPLOY_DIR}"
    fi
    normalize_deploy_perms
    # Ensure git safe.directory is set for sudo operations
    git config --global --add safe.directory "$DEPLOY_DIR" 2>/dev/null || true
    git config --global --add safe.directory "$TACQUITO_SRC" 2>/dev/null || true

    # Symlink management CLI (755 so non-root users can exec into sudo)
    chmod 755 "${DEPLOY_DIR}/bin/tacctl.sh"
    ln -sf "${DEPLOY_DIR}/bin/tacctl.sh" /usr/local/bin/tacctl
    cp "${PROJECT_DIR}/README.md" "${CONFIG_DIR}/README.md" 2>/dev/null || true
    # Install default config templates
    if [[ -d "${PROJECT_DIR}/config/templates" ]]; then
        mkdir -p "${CONFIG_DIR}/templates"
        cp -n "${PROJECT_DIR}/config/templates/"*.template "${CONFIG_DIR}/templates/" 2>/dev/null || true
        info "Config templates installed: ${CONFIG_DIR}/templates/"
    fi
    # Install logrotate config
    if [[ -f "${PROJECT_DIR}/config/tacquito.logrotate" ]]; then
        cp "${PROJECT_DIR}/config/tacquito.logrotate" /etc/logrotate.d/tacquito
        info "Log rotation installed: /etc/logrotate.d/tacquito"
    fi
    # Install bash completion
    if [[ -f "${PROJECT_DIR}/config/tacctl.bash-completion" ]]; then
        cp "${PROJECT_DIR}/config/tacctl.bash-completion" /etc/bash_completion.d/tacctl
        chmod 644 /etc/bash_completion.d/tacctl
        info "Bash completion installed: /etc/bash_completion.d/tacctl"
    fi
    # Install man page
    if [[ -f "${PROJECT_DIR}/man/tacctl.1" ]]; then
        install_man_page "${PROJECT_DIR}/man/tacctl.1"
        info "Man page installed: /usr/share/man/man1/tacctl.1.gz"
    fi

    info "Management CLI installed:"
    info "  tacctl — user, config, and system management"
    info "  Deploy source: ${DEPLOY_DIR}"

    # --- Step 3: Install python3-bcrypt ---
    if ! python3 -c "import bcrypt" 2>/dev/null; then
        info "Installing python3-bcrypt..."
        if command -v apt-get &>/dev/null; then
            apt-get install -y -qq python3-bcrypt
        elif command -v dnf &>/dev/null; then
            dnf install -y -q python3-bcrypt
        elif command -v yum &>/dev/null; then
            yum install -y -q python3-bcrypt
        else
            error "Cannot install python3-bcrypt automatically. Install it manually."
            exit 1
        fi
    fi

    # --- Step 4: Create service user and directories ---
    if ! id tacquito &>/dev/null; then
        info "Creating tacquito service user..."
        useradd --system --no-create-home --shell /usr/sbin/nologin tacquito
    else
        info "Service user 'tacquito' already exists."
    fi

    mkdir -p "$CONFIG_DIR" "$LOG_DIR"
    chown tacquito:tacquito "$CONFIG_DIR" "$LOG_DIR"
    # CONFIG_DIR is world-traversable so everyone can read README.md; sensitive files inside (tacquito.yaml, backups) are 0640 and stay protected by their own perms. LOG_DIR stays 0750.
    chmod 755 "$CONFIG_DIR"
    chmod 750 "$LOG_DIR"

    # --- Step 5: Generate shared secret ---
    local SHARED_SECRET
    SHARED_SECRET=$(openssl rand -hex 16)

    # --- Step 6: Write configuration ---
    local CONFIG_FILE="${CONFIG_DIR}/tacquito.yaml"
    info "Writing configuration to ${CONFIG_FILE}..."

    cp "${PROJECT_DIR}/config/tacquito.yaml" "$CONFIG_FILE"

    # Replace shared secret placeholder using Python. Secret passes through
    # /dev/fd (process substitution) so it never appears on argv or in the
    # environment — /proc/<pid>/cmdline sees only the ephemeral fd path.
    python3 - "$CONFIG_FILE" <(printf '%s' "$SHARED_SECRET") <<'PY'
import sys, tempfile, os
config_path, secret_path = sys.argv[1], sys.argv[2]
with open(secret_path) as f:
    secret = f.read()
config = open(config_path).read()
config = config.replace('REPLACE_WITH_SHARED_SECRET', secret)
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(config_path), delete=False)
tmp.write(config)
tmp.close()
os.rename(tmp.name, config_path)
PY

    chown tacquito:tacquito "$CONFIG_FILE"
    chmod 640 "$CONFIG_FILE"

    # --- Seed default-scope marker ---
    # Fresh installs ship with 'lab' as the sole scope, and the marker
    # points at it so 'tacctl user add <u> <g>' without --scopes lands
    # new users in lab (least-privilege by default). Operators who want
    # a production scope create it explicitly:
    #   tacctl scopes add prod --prefixes ... --secret generate
    #   tacctl scopes default prod   (if they want prod-default posture)
    write_default_scope "$DEFAULT_SCOPE_FRESH"
    info "Default scope seeded: ${DEFAULT_SCOPE_FRESH} (new users land here unless --scopes given)"

    # Flatten the seed template's multi-prefix entry into one entry per
    # prefix so tacquito's first-match walk lands on the narrowest
    # matching entry. Idempotent.
    flatten_secrets_if_needed

    mkdir -p "$BACKUP_DIR" "${BACKUP_DIR}/disabled" "$PASSWORD_DATES_DIR"
    chmod 750 "$BACKUP_DIR" "$PASSWORD_DATES_DIR"
    chmod 700 "${BACKUP_DIR}/disabled"
    chown tacquito:tacquito "$BACKUP_DIR" "$PASSWORD_DATES_DIR"

    # --- Step 7: Install systemd service ---
    info "Installing systemd service..."
    cp "${PROJECT_DIR}/config/tacquito.service" "$SERVICE_FILE"
    systemctl daemon-reload
    systemctl enable tacquito.service

    # --- Step 8: Start the service ---
    info "Starting tacquito..."
    systemctl start tacquito.service
    sleep 2

    if systemctl is-active --quiet tacquito.service; then
        info "Tacquito is running!"
    else
        error "Tacquito failed to start. Check: journalctl -u tacquito"
        exit 1
    fi

    # --- Step 9: Verify ---
    local LISTEN_CHECK
    LISTEN_CHECK=$(ss -tlnp | grep ":49 " || true)
    if [[ -n "$LISTEN_CHECK" ]]; then
        info "Listening on port 49/tcp"
    else
        warn "Port 49 not detected — check logs."
    fi

    # --- Summary ---
    echo ""
    echo "============================================"
    echo "  Installation Complete"
    echo "============================================"
    echo ""
    echo "  Service:        tacquito.service (enabled, running)"
    echo "  Config:         ${CONFIG_FILE}"
    echo "  Accounting log: ${LOG_DIR}/accounting.log"
    echo ""
    echo "  Shared Secret:  ${SHARED_SECRET}"
    echo ""
    echo -e "  ${RED}SAVE THE SHARED SECRET — it is not stored in plaintext.${NC}"
    echo -e "  ${YELLOW}Clear your terminal after recording: history -c && clear${NC}"
    echo ""
    echo "  Next steps:"
    echo "    1. Add your first user:    tacctl user add <username> superuser"
    echo "       (lands in default scope '${DEFAULT_SCOPE_FRESH}')"
    echo "    2. Configure devices:      tacctl config cisco / tacctl config juniper"
    echo "    3. Narrow scope prefixes:  tacctl scopes prefixes ${DEFAULT_SCOPE_FRESH} <your-subnets>"
    echo "    4. Add a prod scope:       tacctl scopes add prod --prefixes <cidrs> --secret generate"
    echo "    5. Open port 49/tcp in your firewall if needed"
    echo ""
    echo "  Security hardening:"
    echo "    6. Bind to a specific IP:  edit ${SERVICE_FILE}"
    echo "       Change '-address :49' to '-address <mgmt-ip>:49'"
    echo "       Then: systemctl daemon-reload && systemctl restart tacquito"
    echo "    7. Add connection ACL:     tacctl config allow add <cidr>"
    echo "    8. Review config:          tacctl config show"
    echo ""
}

# --- UPGRADE ---
# NOTE: Git pulls rely on HTTPS transport security. Commit signature verification
# is not enforced. The self-update exec re-runs the script after a git pull — the
# pulled code runs as root. Verify the repo's integrity in sensitive environments.
cmd_upgrade() {
    # Parse optional --branch flag
    local UPGRADE_BRANCH=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --branch) UPGRADE_BRANCH="${2:-}"; shift 2 ;;
            *) shift ;;
        esac
    done

    if [[ ! -d "$TACQUITO_SRC" ]]; then
        error "Tacquito source not found at ${TACQUITO_SRC}. Run 'tacctl install' first."
        exit 1
    fi

    if [[ ! -x "$GO_BIN" ]]; then
        error "Go not found at ${GO_BIN}. Install Go first."
        exit 1
    fi

    export PATH=$PATH:/usr/local/go/bin

    # Ensure git safe.directory is set for sudo operations
    git config --global --add safe.directory "$DEPLOY_DIR" 2>/dev/null || true
    git config --global --add safe.directory "$TACQUITO_SRC" 2>/dev/null || true

    local PROJECT_DIR
    PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

    echo ""
    echo "============================================"
    echo "  Tacquito Upgrade"
    echo "============================================"
    echo ""

    # --- Record current version ---
    local CURRENT_COMMIT
    CURRENT_COMMIT=$(cd "$TACQUITO_SRC" && git rev-parse --short HEAD)
    info "Current commit: ${CURRENT_COMMIT}"

    # --- Pull latest source ---
    info "Pulling latest source..."
    cd "$TACQUITO_SRC"
    git fetch --quiet
    local LOCAL REMOTE SKIP_BUILD NEW_COMMIT
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse @{u})

    if [[ "$LOCAL" == "$REMOTE" ]]; then
        info "Tacquito source already up to date (${CURRENT_COMMIT})."
        SKIP_BUILD=true
    else
        SKIP_BUILD=false
        if [[ -f "$TACQUITO_BIN" ]]; then
            cp "$TACQUITO_BIN" "${TACQUITO_BIN}.bak"
            info "Backed up current binary to ${TACQUITO_BIN}.bak"
        fi
    fi

    if [[ "$SKIP_BUILD" == "false" ]]; then
        git pull --quiet
        NEW_COMMIT=$(git rev-parse --short HEAD)
        info "Updated: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"

        echo ""
        info "Changes:"
        git log --oneline "${CURRENT_COMMIT}..${NEW_COMMIT}" | head -20
        echo ""

        info "Building tacquito server..."
        cd "${TACQUITO_SRC}/cmds/server"
        if ! go build -o "$TACQUITO_BIN" . ; then
            error "Build failed. Restoring previous binary."
            mv "${TACQUITO_BIN}.bak" "$TACQUITO_BIN"
            exit 1
        fi

        info "Building password hash generator..."
        cd "${TACQUITO_SRC}/cmds/server/config/authenticators/bcrypt/generator"
        go build -o "$HASHGEN_BIN" . || warn "Hashgen build failed (non-critical)."
    fi

    # --- Update management repo ---
    if [[ -d "${DEPLOY_DIR}/.git" ]]; then
        info "Pulling latest management scripts..."
        cd "$DEPLOY_DIR"
        # Discard local tracked-file edits so the pull can fast-forward.
        # Errors here are rare but not silenced — a failure would leave
        # local mods that block the pull a few lines later.
        git checkout -- . || {
            error "Failed to discard local modifications in ${DEPLOY_DIR}."
            error "Run 'sudo git -C ${DEPLOY_DIR} status' to investigate."
            exit 1
        }
        # Remove tacctl-managed untracked backup files that would otherwise
        # survive `git checkout -- .` and clutter the tree indefinitely.
        rm -f "${DEPLOY_DIR}"/bin/tacctl.sh.*-bak \
              "${DEPLOY_DIR}"/config/templates/*.template.*-bak 2>/dev/null || true
        if [[ -n "$UPGRADE_BRANCH" ]]; then
            # --tags --force so force-pushed tags (e.g. after a history rewrite) update locally.
            git fetch --tags --force || {
                error "git fetch failed. Check network / credentials."
                exit 1
            }
            git checkout "$UPGRADE_BRANCH" &>/dev/null || git checkout -b "$UPGRADE_BRANCH" "origin/${UPGRADE_BRANCH}" &>/dev/null
            info "Switched to branch '${UPGRADE_BRANCH}'."
        fi
        git fetch --tags --force || {
            error "git fetch failed. Check network / credentials."
            exit 1
        }
        local LOCAL_MANAGE REMOTE_MANAGE
        LOCAL_MANAGE=$(git rev-parse HEAD 2>/dev/null)
        REMOTE_MANAGE=$(git rev-parse @{u} 2>/dev/null || echo "")
        if [[ -n "$REMOTE_MANAGE" && "$LOCAL_MANAGE" != "$REMOTE_MANAGE" ]]; then
            # Copy self to temp before pull (git pull will overwrite the running script)
            local SELF_TMP
            SELF_TMP=$(mktemp)
            cp "${DEPLOY_DIR}/bin/tacctl.sh" "$SELF_TMP"

            # Stderr NOT silenced so failures surface (conflicts, diverged
            # branches, overwrite-would-happen, etc.). --ff-only refuses any
            # merge scenario; upgrades should be fast-forward only.
            if ! git pull --ff-only; then
                error "git pull failed. Common causes:"
                error "  - local commits on ${DEPLOY_DIR} diverging from origin"
                error "  - untracked files that would be overwritten"
                error "Run 'sudo git -C ${DEPLOY_DIR} status' to investigate."
                rm -f "$SELF_TMP"
                exit 1
            fi
            info "Management scripts updated: $(git rev-parse --short HEAD)"

            # If tacctl changed, re-run the new version
            if ! diff -q "$SELF_TMP" "${DEPLOY_DIR}/bin/tacctl.sh" &>/dev/null; then
                rm -f "$SELF_TMP"
                info "tacctl updated — restarting upgrade with new version..."
                exec "${DEPLOY_DIR}/bin/tacctl.sh" upgrade
            fi
            rm -f "$SELF_TMP"
        else
            info "Management scripts already up to date."
        fi
    elif [[ ! -d "$DEPLOY_DIR" ]]; then
        info "Cloning management repo..."
        git clone --quiet "$MANAGE_REPO" "$DEPLOY_DIR" || warn "Failed to clone management repo."
    fi
    # Always normalize, even when nothing was pulled -- self-healing for
    # prior installs whose files were left at 0600 by the script's umask.
    normalize_deploy_perms

    # --- Ensure symlink exists (755 so non-root users can exec into sudo) ---
    if [[ -d "$DEPLOY_DIR" ]]; then
        chmod 755 "${DEPLOY_DIR}/bin/tacctl.sh"
        ln -sf "${DEPLOY_DIR}/bin/tacctl.sh" /usr/local/bin/tacctl
    fi

    # --- Update system config files ---
    info "Updating system files..."
    local SCRIPTS_UPDATED=0
    local ACTIVE_DEPLOY_DIR="$DEPLOY_DIR"

    if [[ ! -d "$ACTIVE_DEPLOY_DIR" ]]; then
        # Fall back to script's own project dir
        ACTIVE_DEPLOY_DIR="$PROJECT_DIR"
    fi

    if [[ -z "$ACTIVE_DEPLOY_DIR" ]]; then
        warn "Deploy directory not found. Skipping updates."
        warn "To fix: clone the repo to ${DEPLOY_DIR}"
    fi

    update_if_changed() {
        local src="$1" dest="$2" label="$3"
        if [[ ! -f "$src" ]]; then return; fi
        if diff -q "$src" "$dest" &>/dev/null; then
            info "  Unchanged: ${label}"
        else
            cp "$src" "$dest"
            info "  Updated: ${label}"
            SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
        fi
    }

    if [[ -f "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" ]]; then
        if ! diff -q "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" "$SERVICE_FILE" &>/dev/null; then
            # Before replacing the installed unit with the new template, rescue
            # any hand-edited -network/-address/-level flags into the drop-in.
            # Only the pre-drop-in schema hardcoded these in ExecStart; the
            # new template references them via TACQUITO_* env vars. We only
            # migrate values that (a) are present AND (b) differ from the
            # template's defaults -- otherwise there's nothing to preserve.
            local mig_net mig_addr mig_level migrated=0
            mig_net=$(grep -oP '\-network \K\S+' "$SERVICE_FILE" 2>/dev/null | head -1)
            mig_addr=$(grep -oP '\-address \K\S+' "$SERVICE_FILE" 2>/dev/null | head -1)
            mig_level=$(grep -oP '\-level \K\d+' "$SERVICE_FILE" 2>/dev/null | head -1)
            if [[ -n "$mig_net" && "$mig_net" != "tcp" && "$mig_net" != '${TACQUITO_NETWORK}' ]]; then
                [[ -z "$(read_service_override TACQUITO_NETWORK)" ]] && { set_service_override TACQUITO_NETWORK "$mig_net"; migrated=1; }
            fi
            if [[ -n "$mig_addr" && "$mig_addr" != ":49" && "$mig_addr" != '${TACQUITO_ADDRESS}' ]]; then
                [[ -z "$(read_service_override TACQUITO_ADDRESS)" ]] && { set_service_override TACQUITO_ADDRESS "$mig_addr"; migrated=1; }
            fi
            if [[ -n "$mig_level" && "$mig_level" != "20" ]]; then
                [[ -z "$(read_service_override TACQUITO_LEVEL)" ]] && { set_service_override TACQUITO_LEVEL "$mig_level"; migrated=1; }
            fi

            cp "$SERVICE_FILE" "${SERVICE_FILE}.bak"
            cp "${ACTIVE_DEPLOY_DIR}/config/tacquito.service" "$SERVICE_FILE"
            systemctl daemon-reload
            info "  Updated: tacquito.service (previous backed up to ${SERVICE_FILE}.bak)"
            if [[ "$migrated" == "1" ]]; then
                info "  Migrated custom -network/-address/-level flags to ${OVERRIDE_FILE}"
            fi
            SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
        else
            info "  Unchanged: tacquito.service"
        fi
    fi

    update_if_changed "${ACTIVE_DEPLOY_DIR}/README.md" "${CONFIG_DIR}/README.md" "README.md"
    update_if_changed "${ACTIVE_DEPLOY_DIR}/config/tacquito.logrotate" "/etc/logrotate.d/tacquito" "logrotate config"
    update_if_changed "${ACTIVE_DEPLOY_DIR}/config/tacctl.bash-completion" "/etc/bash_completion.d/tacctl" "bash completion"
    chmod 644 /etc/bash_completion.d/tacctl 2>/dev/null || true
    # Man page: unconditional re-gzip (cheap, <10 KB) also heals hosts where the file is missing.
    install_man_page "${ACTIVE_DEPLOY_DIR}/man/tacctl.1"
    # Older installs left CONFIG_DIR at 0750, which blocks non-root reads of README.md; normalize to 0755 (sensitive files inside stay 0640).
    chmod 755 "$CONFIG_DIR" 2>/dev/null || true

    # Update default config templates (only if user hasn't customized them)
    if [[ -d "${ACTIVE_DEPLOY_DIR}/config/templates" ]]; then
        mkdir -p "${CONFIG_DIR}/templates"
        for tmpl in "${ACTIVE_DEPLOY_DIR}/config/templates/"*.template; do
            [[ -f "$tmpl" ]] || continue
            local tmpl_name dest
            tmpl_name=$(basename "$tmpl")
            dest="${CONFIG_DIR}/templates/${tmpl_name}"
            if [[ ! -f "$dest" ]]; then
                cp "$tmpl" "$dest"
                info "  Installed: ${tmpl_name}"
                SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
            else
                update_if_changed "$tmpl" "$dest" "template: ${tmpl_name}"
            fi
        done
    fi

    info "${SCRIPTS_UPDATED} file(s) updated."

    # --- Seed default-scope marker if missing (upgrade hook) ---
    # Pre-multi-scope installs don't have /etc/tacquito/default-scope.
    # Seed it with the NAME of the existing sole scope so behavior is
    # preserved (no forced rename of 'network_devices' to 'lab' — that
    # remains an optional operator choice). If the install already has
    # multiple scopes and no marker, fall back to the first scope and
    # warn; operators should pick one explicitly.
    if [[ ! -f "$DEFAULT_SCOPE_FILE" ]]; then
        local _existing_scopes _first_scope _scope_count
        _existing_scopes=$(list_scopes 2>/dev/null || true)
        _scope_count=$(printf '%s\n' "$_existing_scopes" | awk 'NF' | wc -l)
        if [[ "$_scope_count" -eq 1 ]]; then
            _first_scope=$(printf '%s\n' "$_existing_scopes" | awk 'NF' | head -1)
            write_default_scope "$_first_scope"
            info "Seeded default-scope marker: ${_first_scope}"
        elif [[ "$_scope_count" -gt 1 ]]; then
            _first_scope=$(printf '%s\n' "$_existing_scopes" | awk 'NF' | head -1)
            write_default_scope "$_first_scope"
            warn "Multiple scopes detected and no default-scope marker was set."
            warn "Provisionally seeded default to '${_first_scope}'."
            warn "Review with: tacctl scopes default     |   set with: tacctl scopes default <name>"
        fi
    fi

    # --- Flatten multi-prefix secrets[] entries to one-entry-per-prefix ---
    # Pre-flat installs have a single secrets[] entry per scope with a
    # multi-line prefixes: block. Under the new emission, each prefix becomes
    # its own entry so tacquito's slice-ordered first-match walk honors
    # cross-scope specificity. Idempotent; no-op on already-flat files.
    if [[ -r "$CONFIG" ]]; then
        local _pre _post
        _pre=$(sha256sum "$CONFIG" 2>/dev/null | awk '{print $1}')
        flatten_secrets_if_needed
        _post=$(sha256sum "$CONFIG" 2>/dev/null | awk '{print $1}')
        if [[ "$_pre" != "$_post" ]]; then
            chown tacquito:tacquito "$CONFIG"
            info "Migrated tacquito.yaml to flat per-prefix secrets: entries."
            SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
        fi
    fi

    # --- Restart service (if binaries or service file changed) ---
    if [[ "$SKIP_BUILD" == "false" ]] || [[ "$SCRIPTS_UPDATED" -gt 0 ]]; then
        info "Restarting tacquito service..."
        systemctl restart tacquito.service
        sleep 2

        if systemctl is-active --quiet tacquito.service; then
            info "Tacquito is running."
            rm -f "${TACQUITO_BIN}.bak"
        else
            if [[ "$SKIP_BUILD" == "false" ]]; then
                error "Tacquito failed to start after upgrade. Rolling back binary..."
                mv "${TACQUITO_BIN}.bak" "$TACQUITO_BIN"
                systemctl restart tacquito.service
                sleep 2
                if systemctl is-active --quiet tacquito.service; then
                    warn "Rolled back to previous binary. Service is running."
                else
                    error "Rollback failed. Check: journalctl -u tacquito"
                fi
                exit 1
            else
                error "Tacquito failed to start. Check: journalctl -u tacquito"
                exit 1
            fi
        fi

        local LISTEN_CHECK
        LISTEN_CHECK=$(ss -tlnp | grep ":49 " || true)
        if [[ -n "$LISTEN_CHECK" ]]; then
            info "Listening on port 49/tcp"
        else
            warn "Port 49 not detected — check logs."
        fi
    fi

    echo ""
    echo "============================================"
    if [[ "$SKIP_BUILD" == "false" ]]; then
        echo "  Upgrade Complete: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"
    else
        echo "  Scripts Updated (source unchanged at ${CURRENT_COMMIT})"
    fi
    echo "  Managed scripts: ${SCRIPTS_UPDATED} updated"
    echo "============================================"
    echo ""
}

# --- UNINSTALL ---
cmd_uninstall() {

    echo ""
    echo "============================================"
    echo -e "  ${RED}Tacquito Uninstaller${NC}"
    echo "============================================"
    echo ""
    echo "This will remove:"
    echo "  - Tacquito service and binary"
    echo "  - Management CLI (tacctl)"
    echo "  - Password hash generator (tacquito-hashgen)"
    echo "  - Configuration directory (/etc/tacquito)"
    echo "  - Log directory (/var/log/tacquito)"
    echo "  - Logrotate config"
    echo "  - Service user (tacquito)"
    echo "  - Management repo (${DEPLOY_DIR})"
    echo ""
    echo -e "${YELLOW}The tacquito source (/opt/tacquito-src) and Go installation"
    echo -e "(/usr/local/go) will NOT be removed.${NC}"
    echo ""

    read -rp "Are you sure you want to uninstall tacquito? [y/N]: " confirm
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        exit 0
    fi

    echo ""

    # --- Stop and disable service ---
    if systemctl is-active --quiet tacquito 2>/dev/null; then
        info "Stopping tacquito service..."
        systemctl stop tacquito
    fi
    if systemctl is-enabled --quiet tacquito 2>/dev/null; then
        systemctl disable tacquito 2>/dev/null || true
    fi

    # --- Ask about preserving data ---
    local PRESERVE_BACKUPS=false PRESERVE_LOGS=false

    echo ""
    read -rp "Preserve config backups (/etc/tacquito/backups)? [y/N]: " keep_backups
    if [[ "$keep_backups" == "y" || "$keep_backups" == "Y" ]]; then
        PRESERVE_BACKUPS=true
    fi

    read -rp "Preserve accounting logs (/var/log/tacquito)? [y/N]: " keep_logs
    if [[ "$keep_logs" == "y" || "$keep_logs" == "Y" ]]; then
        PRESERVE_LOGS=true
    fi

    echo ""

    # --- Remove symlinks and binaries ---
    info "Removing binaries and symlinks..."
    rm -f /usr/local/bin/tacctl
    rm -f /usr/local/bin/tacquito
    rm -f /usr/local/bin/tacquito.bak
    rm -f /usr/local/bin/tacquito-hashgen

    # --- Remove systemd unit ---
    info "Removing systemd unit..."
    rm -f /etc/systemd/system/tacquito.service
    rm -f /etc/systemd/system/tacquito.service.bak
    rm -rf /etc/systemd/system/tacquito.service.d
    rm -f /etc/sudoers.d/tacctl
    systemctl daemon-reload

    # --- Remove logrotate config ---
    info "Removing logrotate config..."
    rm -f /etc/logrotate.d/tacquito

    # --- Remove man page ---
    info "Removing man page..."
    rm -f /usr/share/man/man1/tacctl.1.gz
    mandb -q 2>/dev/null || true

    # --- Remove configuration ---
    local BACKUP_ARCHIVE="" LOG_ARCHIVE=""
    if [[ "$PRESERVE_BACKUPS" == "true" ]]; then
        if [[ -d /etc/tacquito/backups ]]; then
            BACKUP_ARCHIVE="/root/tacquito-backups-$(date +%Y%m%d_%H%M%S).tar.gz"
            tar czf "$BACKUP_ARCHIVE" -C /etc/tacquito backups/ 2>/dev/null || true
            info "Config backups saved to ${BACKUP_ARCHIVE}"
        fi
    fi
    info "Removing configuration directory..."
    rm -rf /etc/tacquito

    # --- Remove logs ---
    if [[ "$PRESERVE_LOGS" == "true" ]]; then
        if [[ -d /var/log/tacquito ]]; then
            LOG_ARCHIVE="/root/tacquito-logs-$(date +%Y%m%d_%H%M%S).tar.gz"
            tar czf "$LOG_ARCHIVE" -C /var/log tacquito/ 2>/dev/null || true
            info "Accounting logs saved to ${LOG_ARCHIVE}"
        fi
    fi
    info "Removing log directory..."
    rm -rf /var/log/tacquito

    # --- Remove password max age file ---
    rm -f /etc/tacquito/password-max-age

    # --- Remove management repo ---
    info "Removing management repo..."
    rm -rf "$DEPLOY_DIR"

    # --- Remove service user ---
    if id tacquito &>/dev/null; then
        info "Removing tacquito service user..."
        userdel tacquito 2>/dev/null || true
    fi

    echo ""
    echo "============================================"
    echo "  Uninstall Complete"
    echo "============================================"
    echo ""
    echo "  Removed:"
    echo "    - Tacquito service and binary"
    echo "    - Management CLI and symlinks"
    echo "    - Configuration and systemd unit"
    echo "    - Logrotate config"
    echo "    - Service user"
    if [[ "$PRESERVE_BACKUPS" == "true" && -n "$BACKUP_ARCHIVE" ]]; then
        echo "    - Config backups saved to: ${BACKUP_ARCHIVE}"
    fi
    if [[ "$PRESERVE_LOGS" == "true" && -n "$LOG_ARCHIVE" ]]; then
        echo "    - Accounting logs saved to: ${LOG_ARCHIVE}"
    fi
    echo ""
    echo "  Not removed:"
    echo "    - Go installation (/usr/local/go)"
    echo "    - Tacquito source (/opt/tacquito-src)"
    echo "    - python3-bcrypt package"
    echo ""
}

# =====================================================================
#  MAIN
# =====================================================================

usage() {
    echo ""
    echo -e "${BOLD}Tacquito Control${NC} ($(get_version))"
    echo ""
    echo "Usage: tacctl <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  install [--branch <name>]     Install tacquito server and configure from scratch"
    echo "  upgrade [--branch <name>]     Pull latest source, rebuild, and update scripts"
    echo "  uninstall                     Remove tacquito and all associated files"
    echo "  status                        Show service health, stats, and recent errors"
    echo "  user <subcommand>             User management (list, add, remove, passwd, scopes, ...)"
    echo "  group <subcommand>            Group management (list, add, edit, remove)"
    echo "  scopes <subcommand>           Scope management (named CIDR + shared-secret bundles)"
    echo "  config <subcommand>           Configuration (show, cisco, juniper, validate, ...)"
    echo "  log <subcommand>              Log viewer (tail, search, failures, accounting)"
    echo "  backup <subcommand>           Backup management (list, diff, restore)"
    echo "  hash [help]                   Generate a bcrypt password hash (or show client-side alternatives)"
    echo "  version                       Print tacctl version"
    echo ""
    echo "Run any command without arguments for detailed help, e.g.:"
    echo "  tacctl user"
    echo "  tacctl config"
    echo ""
    echo "Examples:"
    echo "  tacctl install"
    echo "  tacctl upgrade"
    echo "  tacctl user add jsmith superuser"
    echo "  tacctl user scopes jsmith add prod"
    echo "  tacctl scopes add prod --prefixes 10.10.0.0/16 --secret generate"
    echo "  tacctl config cisco --scope prod"
    echo ""
}

COMMAND="${1:-}"
shift || true

# --- USER dispatcher ---
cmd_user() {
    local subcmd="${1:-help}"
    shift || true

    case "$subcmd" in
        list)       cmd_list ;;
        show)       cmd_show "$@" ;;
        add)        cmd_add "$@" ;;
        remove)     cmd_remove "$@" ;;
        passwd)     cmd_passwd "$@" ;;
        disable)    cmd_disable "$@" ;;
        enable)     cmd_enable "$@" ;;
        rename)     cmd_rename "$@" ;;
        move)       cmd_move "$@" ;;
        verify)     cmd_verify "$@" ;;
        scopes)     cmd_user_scopes "$@" ;;
        *)
            echo ""
            echo -e "${BOLD}User Commands${NC}"
            echo ""
            echo "Usage: tacctl user <subcommand> [arguments]"
            echo ""
            echo "Subcommands:"
            echo "  list                                        List all users (name, group, status, pw age, scopes)"
            echo "  show <username>                             Show user details incl. scope membership"
            echo "  add <username> <group>                      Add a new user; lands in default scope"
            echo "  add <username> <group> --scopes <s>[,s...]  Grant specific scopes at creation"
            echo "  add <username> <group> --hash <hash>        Add with pre-generated bcrypt hash"
            echo "  remove <username>                           Remove a user"
            echo "  passwd <username>                           Change a user's password"
            echo "  passwd <username> --hash <hash>             Change with pre-generated bcrypt hash"
            echo "  disable <username>                          Disable a user (preserves hash)"
            echo "  enable <username>                           Re-enable a disabled user"
            echo "  rename <old> <new>                          Rename a user"
            echo "  move <user> <group>                         Move user to a different group"
            echo "  verify <username>                           Verify password and show user details"
            echo "  scopes <user> list|add|remove|set|clear     Manage which scopes the user can auth from"
            echo ""
            echo "Examples:"
            echo "  tacctl user list"
            echo "  tacctl user add jsmith superuser"
            echo "  tacctl user add jsmith superuser --scopes prod,lab"
            echo "  tacctl user scopes jsmith add prod"
            echo "  tacctl user verify jsmith"
            echo ""
            exit 1
            ;;
    esac
}

case "$COMMAND" in
    install)
        cmd_install "$@"
        ;;
    upgrade)
        cmd_upgrade "$@"
        ;;
    uninstall)
        cmd_uninstall "$@"
        ;;
    status)
        preflight
        cmd_status
        ;;
    user)
        preflight
        cmd_user "$@"
        ;;
    group)
        preflight
        cmd_group "$@"
        ;;
    config)
        preflight
        cmd_config "$@"
        ;;
    scopes)
        preflight
        cmd_scopes "$@"
        ;;
    log)
        preflight
        cmd_log "$@"
        ;;
    backup)
        preflight
        cmd_backup "$@"
        ;;
    hash)
        cmd_hash "$@"
        ;;
    _completion-names)
        # Hidden helper used by bash completion to enumerate scope, user, or
        # group names. Completion runs in the user's shell where the config
        # is unreadable (mode 0600); `sudo -n tacctl _completion-names <kind>`
        # bridges that when a NOPASSWD sudoers rule for tacctl is installed.
        # Not shown in `tacctl` help or the man page — deliberate low-surface
        # interface, behavior subject to change.
        preflight
        case "${1:-}" in
            scopes) list_scopes ;;
            users)  python3 -c "
import yaml
with open('$CONFIG') as f:
    d = yaml.safe_load(f) or {}
for u in (d.get('users') or []):
    n = u.get('name')
    if n: print(n)
" 2>/dev/null ;;
            groups) awk '/^# --- Groups ---/,/^# --- Users ---/ {
                if (match($0, /^[a-z][a-zA-Z0-9_-]*: &/)) {
                    sub(/:.*/, ""); print
                }
            }' "$CONFIG" 2>/dev/null ;;
        esac
        ;;
    version|--version|-v)
        echo "tacctl $(get_version)"
        ;;
    *)
        usage
        exit 1
        ;;
esac
