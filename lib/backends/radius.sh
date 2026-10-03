# shellcheck shell=bash
# shellcheck disable=SC2034  # constants assigned here are read by the other lib files
# tacctl lib/backends/radius.sh -- the RADIUS backend (FreeRADIUS from the distro package): renderer (model + tacctl.yaml -> tacctl-radius.conf, tacctl-radius.users and tacctl's dictionary), the daemon's config check, the unit drop-in, listeners, status and log sections, install/upgrade/uninstall steps
# Sourced by bin/tacctl.sh after lib/backend.sh (see the load block there for ordering); not executable.
#
# 'tacctl backend enable radius' gives the users, groups and scopes of the
# store a RADIUS service: PAP only, checked against the stored bcrypt hashes.
# What was verified against real FreeRADIUS, and how, is in
# docs/radius-notes.md; this header is the design.
#
# --- An instance of its own, inside the distro's package ---------------------
#
# FreeRADIUS reads <raddb>/<name>.conf when started with '-n <name>'. tacctl
# renders a complete main configuration under its own name,
# <raddb>/tacctl-radius.conf, and a drop-in for the distro's unit that starts
# the daemon with '-n tacctl-radius'. Nothing the package shipped is edited,
# moved or unlinked: radiusd.conf, clients.conf, sites-enabled/ (default,
# inner-tunnel) and mods-enabled/ (eap, mschap, ...) are simply not read, so
# no EAP, no inner tunnel, no proxying, no Status-Server and not the
# package's 'localhost / testing123' client. (Switching sites-enabled/ links
# instead does not work: the package's eap module refuses to load once no
# site has an 'Auth-Type EAP', so mods-enabled/ would have to be edited too.)
# From the package tacctl uses the binary, its modules (rlm_files, rlm_pap,
# rlm_detail, rlm_linelog, rlm_always), the dictionaries (included by
# tacctl's own, see "Vendor attributes" below), the service account, the unit
# and the log directory.
#
#                     Debian/Ubuntu              RHEL family
#   raddb             /etc/freeradius/3.0        /etc/raddb
#   unit              freeradius.service         radiusd.service
#   account           freerad:freerad            radiusd:radiusd
#   binary            /usr/sbin/freeradius       /usr/sbin/radiusd
#   logs              /var/log/freeradius        /var/log/radius
#   pid file          /run/freeradius/freeradius.pid   /run/radiusd/radiusd.pid
#   modules (libdir)  /usr/lib/freeradius        /usr/lib64/freeradius
#   main dictionary   /usr/share/freeradius/dictionary   (both)
#   packages          freeradius freeradius-utils (both; RHEL: AppStream, no EPEL)
#
# The family is detected (the raddb directory, else the package manager);
# TACCTL_RADIUS_FAMILY=debian|rhel overrides it, and TACCTL_RADIUS_DIR,
# TACCTL_RADIUS_LOG, TACCTL_RADIUS_BIN, TACCTL_RADIUS_DICT,
# TACCTL_SYSTEMD_DIR and TACCTL_LOGROTATE_DIR move the paths (tests).
#
# --- Artifacts ----------------------------------------------------------------
#
#   <raddb>/tacctl-radius.conf    main settings, the module instances, and
#                                 'server tacctl': one listen{} per listener
#                                 of listeners.radius, one client{} per prefix
#                                 of every scope RADIUS serves (with that
#                                 scope's secret), the policy.
#   <raddb>/tacctl-radius.users   rlm_files: one entry per (user, scope).
#   <raddb>/tacctl-radius-dictionary/dictionary
#                                 the daemon's main dictionary ('-D'): the
#                                 package's, then the WTI vendor and tacctl's
#                                 internal attributes.
#
# The first two hold secrets or hashes; all three are 0640 root:<daemon
# group>, like the package's own files (the dictionary's directory 0750).
# Outside the artifacts tacctl owns <unit>.service.d/tacctl.conf
# (the drop-in; present exactly while the backend is enabled),
# /etc/logrotate.d/tacctl-radius and three files in the package's log
# directory: tacctl-radius.log (the daemon), tacctl-auth.log (one line per
# Access-Accept and Access-Reject) and tacctl-accounting.log (detail records).
#
# --- A user authenticates only from a scope they belong to -------------------
#
# Every client{} carries a field of tacctl's own, tacctl_scope. The policy
# copies it into the request ('Tmp-String-0 := "<render id>/%{client:
# tacctl_scope}"'; an internal attribute, which cannot arrive in a packet and
# is overwritten anyway), and every users entry has that value as a check
# item next to the hash:
#
#   alice  Tmp-String-0 == "<render id>/lab", Crypt-Password := "$2b$12$..."
#          Service-Type = Administrative-User, Cisco-AVPair = "shell:priv-lvl=15", ...
#
# No entry for (user, scope of the client) means no password to compare with:
# the request is rejected before rlm_pap is asked. Disabled users, users
# without a hash and the 'root' accounting sink have no entry at all.
# rlm_pap hands Crypt-Password to crypt(3); libxcrypt on both families
# verifies $2a$/$2b$/$2y$. CHAP, MS-CHAP and EAP requests carry no
# User-Password and are rejected: nothing else is configured.
#
# Overlapping prefixes: FreeRADIUS answers a client with the longest matching
# prefix, which is tacquito's "most specific first". The store allows a
# network in one scope only, so two clients never collide.
#
# The render id is a hash of the three files' content. A users file from one
# render never matches a policy from another, so a daemon that somehow reads
# half of a commit (a crash between two renames, a HUP on a daemon that was
# not restarted) authenticates nobody instead of mixing two states.
#
# --- What an Access-Accept carries ----------------------------------------------
#
#   Service-Type              always: Administrative-User at priv-lvl 15, else
#                             NAS-Prompt-User (a standard attribute)
#   Cisco-AVPair              "shell:priv-lvl=<priv_lvl>"      vendor cisco
#   Juniper-Local-User-Name   "<juniper_class>"                vendor juniper
#   WTI-Super                 0-3 (WTI_SUPER_BANDS)            vendor wti
#
# The same level and class TACACS+ returns. A reject carries none of them.
# commands.<group> is NOT rendered: RADIUS has no per-command authorization.
# 'tacctl status', 'config render' and 'backend enable' say so when a group
# with RADIUS users has rules that restrict commands.
#
# --- Vendor attributes: opt-in per scope, per address ----------------------------
#
# A RADIUS server cannot see what kind of device asks, and one vendor's
# privilege attribute has no business on another vendor's device. So a vendor
# attribute is sent only where the operator said so:
#
#   scope vendor-attrs <scope> enable <vendor>   every device of the scope
#                                                that is not tagged
#   scope devices <scope> set <ip|cidr> <vendor> that address: its own
#                                                vendor's attribute and no
#                                                other, whatever the scope
#                                                enables
#
# A new scope sends none. How it is rendered:
#
#   - one client{} per prefix of a scope and one per tagged address
#     (FreeRADIUS answers with the longest matching prefix, so a tagged
#     address inside a prefix is its own client; the store makes sure it is
#     an address this scope answers for). Besides tacctl_scope each carries
#     tacctl_device ("generic", or the vendor it is tagged with) and one
#     tacctl_send_<vendor> = "yes" | "no" per vendor: what the scope enables
#     for a generic client, its own vendor alone for a tagged one.
#   - a users entry puts the group's values into the control list, in
#     attributes of tacctl's own (Tacctl-Priv-Lvl, Tacctl-Juniper-Class,
#     Tacctl-WTI-Super; check items with ':='), and only Service-Type into
#     the reply.
#   - post-auth adds a vendor's attribute to the reply when, and only when,
#     the client says tacctl_send_<vendor> = "yes" and the control list has
#     the value.
#
# The direction of failure is the point: a vendor attribute is only ever
# ADDED, by an exact match on a field of the client. A client without the
# field, a typo in the policy, a users entry without the value: each leaves
# a device with too few attributes, never with another vendor's. The values
# never travel: the control list is not part of a reply, and the three
# attributes are numbered in the range FreeRADIUS keeps for site-local
# attributes that "will NOT go into a RADIUS packet" (3000-3999), so even one
# copied into a reply by mistake is not encoded (docs/radius-notes.md).
#
# WTI-Super is not in the dictionaries FreeRADIUS ships, and tacctl's three
# attributes are in none. tacctl renders a dictionary of its own that
# includes the package's main dictionary by absolute path and then defines
# them, and the unit starts the daemon with '-D <its directory>'. No file of
# the package is edited. (<raddb>/dictionary, the package's file for local
# attributes, is still read after it; tacctl's numbers are at the top of the
# site-local range to stay clear of what a site may have put there.)
#
# --- Filters, secrets, restart ----------------------------------------------------
#
# filters.deny / filters.allow are enforced by the policy as tacquito enforces
# them: a packet from a denied address, or from outside a non-empty allow
# list, gets no answer (authentication and accounting).
#
# A secret is written single-quoted when it has no backslash, double-quoted
# when it has one; a secret with both a backslash and a dollar sign cannot be
# written in either form on every supported FreeRADIUS version and refuses
# the render. secret_constraints is the interoperability advice (63
# printable, space-free characters); render_notes warns beyond it.
#
# FreeRADIUS reads clients only at start, so every change restarts the unit
# (never a reload). Requests in flight are lost; a NAS retransmits within
# its timeout.
#
# --- Install, enable, disable, uninstall ----------------------------------------
#
#   install build    the packages, unless the binary is there. A unit found
#                    active or enabled is somebody's RADIUS server: refused,
#                    with what to run to hand it over. The unit the package
#                    just started on its own (Debian) is stopped and disabled.
#   install files    /etc/logrotate.d/tacctl-radius
#   install account  the package's account must exist; nothing is created
#   (render)         the artifacts, each proven by 'radiusd -C' first
#   install start    the drop-in, 'systemctl enable' and 'start', then active
#   upgrade config   re-render (a release may change what it renders), bring
#                    the drop-in in line with it, restart when either changed
#   service enable   the drop-in, daemon-reload, 'systemctl enable'
#   service disable  'systemctl disable', the drop-in removed, daemon-reload:
#                    the unit is the package's again, stopped and not enabled
#   uninstall        stop and disable as above; then the artifacts, the
#                    logrotate file and the three logs are removed. The
#                    packages stay.

BACKEND_IDS+=(radius)

# --- Layout ---------------------------------------------------------------------

# debian | rhel | '' (neither recognised).
_radius_family_detect() {
    case "${TACCTL_RADIUS_FAMILY:-}" in
        debian|rhel) echo "$TACCTL_RADIUS_FAMILY"; return 0 ;;
    esac
    if [[ -d /etc/freeradius/3.0 ]]; then
        echo debian
    elif [[ -d /etc/raddb ]]; then
        echo rhel
    elif command -v apt-get > /dev/null 2>&1; then
        echo debian
    elif command -v dnf > /dev/null 2>&1 || command -v yum > /dev/null 2>&1; then
        echo rhel
    fi
    return 0
}

RADIUS_FAMILY=$(_radius_family_detect)
case "$RADIUS_FAMILY" in
    rhel)
        RADIUS_DIR="${TACCTL_RADIUS_DIR:-/etc/raddb}"
        RADIUS_UNIT="radiusd.service"
        RADIUS_USER="radiusd"
        RADIUS_GROUP="radiusd"
        RADIUS_BIN="${TACCTL_RADIUS_BIN:-/usr/sbin/radiusd}"
        RADIUS_LOG_DIR="${TACCTL_RADIUS_LOG:-/var/log/radius}"
        RADIUS_PID_FILE="/run/radiusd/radiusd.pid"
        RADIUS_LIB_DIR="/usr/lib64/freeradius"
        RADIUS_SYSTEM_DICT="${TACCTL_RADIUS_DICT:-/usr/share/freeradius/dictionary}"
        ;;
    *)
        RADIUS_DIR="${TACCTL_RADIUS_DIR:-/etc/freeradius/3.0}"
        RADIUS_UNIT="freeradius.service"
        RADIUS_USER="freerad"
        RADIUS_GROUP="freerad"
        RADIUS_BIN="${TACCTL_RADIUS_BIN:-/usr/sbin/freeradius}"
        RADIUS_LOG_DIR="${TACCTL_RADIUS_LOG:-/var/log/freeradius}"
        RADIUS_PID_FILE="/run/freeradius/freeradius.pid"
        RADIUS_LIB_DIR="/usr/lib/freeradius"
        RADIUS_SYSTEM_DICT="${TACCTL_RADIUS_DICT:-/usr/share/freeradius/dictionary}"
        ;;
esac
RADIUS_PKGS="freeradius freeradius-utils"
# The name the daemon is started under ('-n'): it reads <raddb>/<name>.conf.
RADIUS_NAME="tacctl-radius"
RADIUS_CONF="${RADIUS_DIR}/${RADIUS_NAME}.conf"
RADIUS_USERS="${RADIUS_DIR}/${RADIUS_NAME}.users"
# The daemon reads <dir>/dictionary of the directory given with '-D': a
# directory of tacctl's own, so that the file can have that name.
RADIUS_DICT_DIR="${RADIUS_DIR}/${RADIUS_NAME}-dictionary"
RADIUS_DICT="${RADIUS_DICT_DIR}/dictionary"
RADIUS_DAEMON_LOG="${RADIUS_LOG_DIR}/tacctl-radius.log"
RADIUS_AUTH_LOG="${RADIUS_LOG_DIR}/tacctl-auth.log"
RADIUS_ACCT_LOG="${RADIUS_LOG_DIR}/tacctl-accounting.log"
RADIUS_DROPIN="${TACCTL_SYSTEMD_DIR:-/etc/systemd/system}/${RADIUS_UNIT}.d/tacctl.conf"
RADIUS_LOGROTATE="${TACCTL_LOGROTATE_DIR:-/etc/logrotate.d}/tacctl-radius"
# How long a restarted unit must stay up before a listener change counts as
# applied.
RADIUS_SETTLE_SECONDS="${TACCTL_SETTLE_SECONDS:-0.5}"
# Mirrors of SECRET_ADVICE_* in _render_radius_py.
RADIUS_SECRET_MAX_LEN=63
RADIUS_SECRET_CHARSET='[!-~]'

# =====================================================================
#  RENDERER
# =====================================================================

# Appended to _store_py, _rendered_py and _listener_py (lib/store.sh,
# lib/backend.sh, lib/conf.sh), whose names it uses; carries its own command
# dispatcher. Output depends only on the inputs -- no timestamps -- so an
# unchanged model renders byte-identically. The three files it writes into an
# output directory are named conf, users and dictionary.
_render_radius_py() {
    cat <<'PY'

# ---- tacctl-radius.conf / tacctl-radius.users / dictionary renderer ----------

RADIUS_HEADER = (
    "# GENERATED by tacctl from /etc/tacctl/store.yaml and tacctl.yaml. Edits here are overwritten,\n"
    "# and there is no way to adopt one: change users, groups, scopes and listeners with tacctl.\n"
)
RID_PLACEHOLDER = '@TACCTL_RENDER_ID@'
# The alphabet of a bcrypt hash; nothing in it needs quoting. A hash of the
# wrong length is still written: crypt(3) matches no password against it.
RE_BCRYPT_RAW = re.compile(r'\$2[aby]\$[./A-Za-z0-9$]*')
# What every NAS we found a figure for accepts; advice, not a refusal.
SECRET_ADVICE_MAX_LEN = 63
RE_SECRET_ADVICE = re.compile(r'[!-~]+')
# WTI-Super for a privilege level: (lowest level of the band, value, the
# unit's name for it). The bands are those of the TACACS+ mapping; must equal
# wti_access_level_for_privlvl and wti_super_for_privlvl in
# lib/render_devices.sh (a unit test pins them together).
WTI_SUPER_BANDS = ((15, 3, 'Administrator'), (10, 2, 'SuperUser'), (5, 1, 'User'), (0, 0, 'ViewOnly'))
# tacctl's own attributes: a users entry carries the group's values in them
# (control list), the policy turns them into vendor attributes. Numbered at
# the top of the range FreeRADIUS reserves for site-local attributes that
# never go into a packet (3000-3999).
INTERNAL_ATTRS = (('Tacctl-Priv-Lvl', 3990, 'integer'),
                  ('Tacctl-Juniper-Class', 3991, 'string'),
                  ('Tacctl-WTI-Super', 3992, 'integer'))
# vendor -> (the attribute an Access-Accept gets, the control attribute that
# must be there, the value as unlang writes it).
VENDOR_REPLY = {
    'cisco': ('Cisco-AVPair', 'Tacctl-Priv-Lvl', '"shell:priv-lvl=%{control:Tacctl-Priv-Lvl}"'),
    'juniper': ('Juniper-Local-User-Name', 'Tacctl-Juniper-Class', '&control:Tacctl-Juniper-Class'),
    'wti': ('WTI-Super', 'Tacctl-WTI-Super', '&control:Tacctl-WTI-Super'),
}


def radius_scopes(model):
    """Scopes this backend serves: no protocols filter, or one naming radius."""
    return {n: s for n, s in model['scopes'].items()
            if not s.get('protocols') or 'radius' in s['protocols']}


def hash_raw(hexhash):
    """The stored hex form of a bcrypt hash -> the '$2b$..' string crypt(3) takes."""
    try:
        raw = binascii.unhexlify(hexhash).decode('ascii')
    except (binascii.Error, ValueError, UnicodeDecodeError, TypeError):
        raise StoreError('a password hash is not hex-encoded bcrypt')
    if not RE_BCRYPT_RAW.fullmatch(raw):
        raise StoreError('a password hash holds characters no bcrypt hash has')
    return raw


def fr_dq(s):
    """A FreeRADIUS double-quoted string for a value that has no '$'."""
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def fr_secret(secret):
    """A shared secret as a FreeRADIUS config string that reads back as
    exactly the secret on 3.0.x and 3.2.x (docs/radius-notes.md): single
    quotes take everything but a backslash literally; double quotes take
    backslash escapes but expand '${...}' and '$ENV{...}'. None when neither
    form is safe."""
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in secret) or not secret:
        return None
    if '\\' not in secret:
        return "'" + secret.replace("'", "\\'") + "'"
    if '$' not in secret:
        return fr_dq(secret)
    return None


def wti_super(priv_lvl):
    """(WTI-Super value, the unit's name for that access level)."""
    for floor, value, label in WTI_SUPER_BANDS:
        if priv_lvl >= floor:
            return value, label
    return WTI_SUPER_BANDS[-1][1:]


def group_reply(group):
    """Reply items of a group, as (attribute, value-as-written) pairs: the
    standard attribute only. Vendor attributes are the policy's to add."""
    lvl = group['priv_lvl']
    return [
        ('Service-Type', 'Administrative-User' if lvl == 15 else 'NAS-Prompt-User'),
    ]


def group_control(group):
    """What the policy makes vendor attributes from, as (attribute,
    value-as-written) pairs for the control list."""
    lvl = group['priv_lvl']
    return [
        ('Tacctl-Priv-Lvl', str(lvl)),
        ('Tacctl-Juniper-Class', fr_dq(group['juniper_class'])),
        ('Tacctl-WTI-Super', str(wti_super(lvl)[0])),
    ]


def radius_clients(scopes):
    """The clients of the scopes RADIUS serves, most specific first, as
    (cidr, scope, device, vendors-to-send): one per prefix ('generic': what
    the scope enables) and one per tagged address (its own vendor alone). A
    tagged CIDR that is also a prefix of its scope is one client, the tagged
    one."""
    clients = {}
    for name, s in scopes.items():
        enabled = [v for v in KNOWN_VENDORS if v in (s.get('vendor_attrs') or [])]
        for c in s['prefixes']:
            clients[str(ipaddress.ip_network(c, strict=False))] = (name, 'generic', enabled)
    for name, s in scopes.items():
        for c, vendor in (s.get('devices') or {}).items():
            clients[str(ipaddress.ip_network(c, strict=False))] = (name, vendor, [vendor])
    return [(c,) + clients[c] for c in sorted(clients, key=lambda c: (cidr_key(c), clients[c][0]))]


def radius_users(model):
    """Users this backend can authenticate, name -> (user, [scope, ...]):
    enabled, with a hash, not the accounting sink, in a scope RADIUS serves."""
    scopes = radius_scopes(model)
    out = {}
    for name in sorted(model['users']):
        u = model['users'][name]
        if u.get('disabled') or u.get('accounting_sink') or not u.get('hash'):
            continue
        mine = [s for s in u['scopes'] if s in scopes]
        if mine:
            out[name] = (u, mine)
    return out


def render_users_text(model):
    """tacctl-radius.users: one entry per (user, scope)."""
    w = [RADIUS_HEADER,
         "#\n"
         "# One entry per user and scope. Tmp-String-0 is set by the policy in tacctl-radius.conf to\n"
         "# '<render id>/<scope of the client>': a user matches only from a client of a scope they are in.\n"
         "# Disabled users and the accounting sink have no entry.\n"
         "# The Tacctl-* items go to the control list, never into a packet: the policy makes a vendor's\n"
         "# attribute from them for a client whose scope or tag asks for it. The reply is Service-Type.\n"]
    for name, (u, mine) in radius_users(model).items():
        if name.startswith('DEFAULT'):
            raise StoreError(f"user '{name}' cannot be served over RADIUS: FreeRADIUS reads a users entry whose "
                             "name starts with DEFAULT as a default for everyone. Rename the user, or keep its "
                             "scopes TACACS+-only ('tacctl scope protocols <scope> set tacacs').")
        raw = hash_raw(u['hash'])
        reply = group_reply(model['groups'][u['group']]) + [('Fall-Through', 'No')]
        control = ''.join(f', {a} := {v}' for a, v in group_control(model['groups'][u['group']]))
        for scope in mine:
            w.append(f'\n{name}\tTmp-String-0 == "{RID_PLACEHOLDER}/{scope}", Crypt-Password := {fr_dq(raw)}{control}\n')
            w.append(',\n'.join(f'\t{a} = {v}' for a, v in reply) + '\n')
    return ''.join(w)


def _src_in(cidr):
    net = ipaddress.ip_network(cidr, strict=False)
    attr = '&Packet-Src-IP-Address' if net.version == 4 else '&Packet-Src-IPv6-Address'
    return f'({attr} && ({attr} <= {net}))'


def render_filter_policy(filters):
    """The 'policy { tacctl_filter { ... } }' body for filters.deny/allow, or
    '' when there are none. A filtered packet gets no answer."""
    drop = ("\t\t\tupdate control {\n"
            "\t\t\t\t&Response-Packet-Type := Do-Not-Respond\n"
            "\t\t\t}\n"
            "\t\t\ttacctl_drop\n")
    w = []
    deny = sorted(filters.get('deny') or [], key=cidr_key)
    allow = sorted(filters.get('allow') or [], key=cidr_key)
    if deny:
        w.append("\t\t# filters.deny\n\t\tif (" + ' || '.join(_src_in(c) for c in deny) + ") {\n" + drop + "\t\t}\n")
    if allow:
        w.append("\t\t# filters.allow\n\t\tif (!(" + ' || '.join(_src_in(c) for c in allow) + ")) {\n" + drop + "\t\t}\n")
    return ''.join(w)


def radius_listeners(conf):
    """listeners.radius in effect -> [(name, type, key, address, port)]."""
    problems = listeners_problems(conf)
    if problems:
        raise StoreError('tacctl.yaml: ' + '; '.join(problems))
    out = []
    for name, l in listeners_effective(conf, 'radius').items():
        host, port = split_listen_address(l['address'])
        if l['network'] == 'udp6':
            key, host = 'ipv6addr', host or '::'
        else:
            key, host = 'ipaddr', host or '*'
        out.append((name, l['role'], key, host, port))
    return out


def render_conf_text(model, conf, params):
    """tacctl-radius.conf: main settings, module instances, server tacctl."""
    scopes = radius_scopes(model)
    filt = render_filter_policy(model.get('filters') or {})
    w = [RADIUS_HEADER,
         "#\n"
         "# FreeRADIUS main configuration of tacctl's own instance: the unit starts the daemon with\n"
         f"# '-n {params['name']}', so the package's radiusd.conf, clients.conf, sites-enabled/ and mods-enabled/\n"
         "# are not read. PAP only, against the bcrypt hashes of the store.\n"
         f"# render id: {RID_PLACEHOLDER}\n"
         "\n"
         "# The daemon's built-in defaults refer to prefix and localstatedir (without them it passes\n"
         "# its own check and then fails to start); libdir is where the package keeps the modules.\n"
         "prefix = /usr\n"
         "localstatedir = /var\n"
         f"libdir = {params['lib_dir']}\n"
         f"logdir = {params['log_dir']}\n"
         f"pidfile = {params['pid_file']}\n"
         "max_request_time = 30\n"
         "cleanup_delay = 5\n"
         "max_requests = 16384\n"
         "hostname_lookups = no\n"
         "proxy_requests = no\n"
         "\n"
         "log {\n"
         "\tdestination = files\n"
         "\tfile = ${logdir}/tacctl-radius.log\n"
         "\tauth = no\n"
         "}\n"
         "\n"
         "security {\n"
         f"\tuser = {params['user']}\n"
         f"\tgroup = {params['group']}\n"
         "\tallow_core_dumps = no\n"
         "\tmax_attributes = 200\n"
         "\treject_delay = 1\n"
         "\tstatus_server = no\n"
         "}\n"
         "\n"
         "thread pool {\n"
         "\tstart_servers = 5\n"
         "\tmax_servers = 32\n"
         "\tmin_spare_servers = 3\n"
         "\tmax_spare_servers = 10\n"
         "\tmax_requests_per_server = 0\n"
         "}\n"
         "\n"
         "modules {\n"
         "\tfiles tacctl_users {\n"
         f"\t\tfilename = ${{confdir}}/{params['name']}.users\n"
         "\t}\n"
         "\tpap tacctl_pap {\n"
         "\t\tnormalise = no\n"
         "\t}\n"
         "\talways tacctl_reject {\n"
         "\t\trcode = reject\n"
         "\t}\n"
         "\talways tacctl_drop {\n"
         "\t\trcode = handled\n"
         "\t}\n"
         "\tdetail tacctl_acct {\n"
         "\t\tfilename = ${logdir}/tacctl-accounting.log\n"
         "\t\tpermissions = 0640\n"
         "\t\theader = \"%t\"\n"
         "\t}\n"
         "\tlinelog tacctl_auth {\n"
         "\t\tfilename = ${logdir}/tacctl-auth.log\n"
         "\t\tpermissions = 0640\n"
         "\t\tformat = \"%S %{reply:Packet-Type} scope=%{client:tacctl_scope} device=%{client:tacctl_device} "
         "client=%{%{Packet-Src-IP-Address}:-%{Packet-Src-IPv6-Address}} "
         "nas=%{%{NAS-Identifier}:-%{%{NAS-IP-Address}:--}} "
         "reason='%{%{Tmp-String-1}:-%{%{Module-Failure-Message}:--}}' user=%{User-Name}\"\n"
         "\t}\n"
         "}\n"]
    if filt:
        w.append("\n"
                 "# Connection filters ('tacctl config allow|deny'): no answer for a filtered address.\n"
                 "policy {\n"
                 "\ttacctl_filter {\n" + filt + "\t}\n"
                 "}\n")
    w.append("\nserver tacctl {\n")
    for name, role, key, host, port in radius_listeners(conf):
        w.append(f"\t# listeners.radius.{name}\n"
                 "\tlisten {\n"
                 f"\t\ttype = {role}\n"
                 f"\t\t{key} = {host}\n"
                 f"\t\tport = {port}\n"
                 "\t}\n")
    w.append("\n"
             "\t# One client per prefix of every scope RADIUS serves, and one per tagged address of a\n"
             "\t# scope ('tacctl scope devices'). An address in two of them is the client of the longer\n"
             "\t# prefix (the more specific scope, the tagged address), as with TACACS+.\n"
             "\t# tacctl_device is 'generic' or the vendor an address is tagged with; tacctl_send_<vendor>\n"
             "\t# says whether post-auth adds that vendor's attribute for this client.\n")
    counter = {}
    for cidr, name, device, send in radius_clients(scopes):
        secret = fr_secret(scopes[name]['secret'])
        if secret is None:
            raise StoreError(
                f"scope '{name}': its secret holds both a backslash and a dollar sign, which no FreeRADIUS "
                f"config string can carry unchanged. Set another ('tacctl scope secret {name} generate'), or "
                f"keep the scope TACACS+-only ('tacctl scope protocols {name} set tacacs').")
        label = name if device == 'generic' else f'{name}.{device}'
        counter[label] = counter.get(label, 0) + 1
        net = ipaddress.ip_network(cidr, strict=False)
        w.append(f"\tclient {label}.{counter[label]} {{\n"
                 f"\t\t{'ipaddr' if net.version == 4 else 'ipv6addr'} = {net}\n"
                 f"\t\tsecret = {secret}\n"
                 f"\t\ttacctl_scope = \"{name}\"\n"
                 f"\t\ttacctl_device = \"{device}\"\n"
                 + ''.join(f"\t\ttacctl_send_{v} = \"{'yes' if v in send else 'no'}\"\n" for v in KNOWN_VENDORS)
                 + "\t}\n")
    # A vendor's attribute is added for a client that says yes, and for no
    # other: no match, no attribute.
    vendor_policy = ''.join(
        f"\t\t\tif ((\"%{{client:tacctl_send_{v}}}\" == \"yes\") && &control:{VENDOR_REPLY[v][1]}) {{\n"
        "\t\t\t\tupdate reply {\n"
        f"\t\t\t\t\t&{VENDOR_REPLY[v][0]} := {VENDOR_REPLY[v][2]}\n"
        "\t\t\t\t}\n"
        "\t\t\t}\n"
        for v in KNOWN_VENDORS)
    use_filter = "\t\ttacctl_filter\n" if filt else ""
    w.append("\n"
             "\tauthorize {\n" + use_filter +
             "\t\tupdate request {\n"
             f"\t\t\t&Tmp-String-0 := \"{RID_PLACEHOLDER}/%{{client:tacctl_scope}}\"\n"
             "\t\t}\n"
             "\t\ttacctl_users\n"
             "\t\tif (!ok) {\n"
             "\t\t\tupdate request {\n"
             "\t\t\t\t&Tmp-String-1 := \"not an enabled user of this scope\"\n"
             "\t\t\t}\n"
             "\t\t\ttacctl_reject\n"
             "\t\t}\n"
             "\t\ttacctl_pap\n"
             "\t}\n"
             "\tauthenticate {\n"
             "\t\ttacctl_pap\n"
             "\t}\n"
             "\tpost-auth {\n"
             "\t\t# A filtered packet (tacctl_filter) gets no answer and no line in the auth log.\n"
             "\t\tif (!&control:Response-Packet-Type) {\n"
             "\t\t\t# Vendor attributes: only for a client whose scope enables the vendor\n"
             "\t\t\t# ('tacctl scope vendor-attrs') or whose address is tagged with it\n"
             "\t\t\t# ('tacctl scope devices'). The values come from the control list.\n"
             + vendor_policy +
             "\t\t\ttacctl_auth\n"
             "\t\t}\n"
             "\t\tPost-Auth-Type REJECT {\n"
             "\t\t\tupdate reply {\n"
             "\t\t\t\t&Service-Type !* ANY\n"
             "\t\t\t\t&Cisco-AVPair !* ANY\n"
             "\t\t\t\t&Juniper-Local-User-Name !* ANY\n"
             "\t\t\t\t&WTI-Super !* ANY\n"
             "\t\t\t}\n"
             "\t\t\ttacctl_auth\n"
             "\t\t}\n"
             "\t}\n"
             "\tpreacct {\n" + use_filter +
             "\t}\n"
             "\taccounting {\n"
             "\t\ttacctl_acct\n"
             "\t}\n"
             "}\n")
    return ''.join(w)


def render_dictionary_text(params):
    """tacctl's dictionary: the package's main dictionary, the WTI vendor,
    tacctl's internal attributes. Depends on the machine only (where the
    package keeps its dictionary), not on the model."""
    width = max(len(a) for a, _n, _t in INTERNAL_ATTRS)
    w = ["# GENERATED by tacctl. Edits here are overwritten, and there is no way to adopt one.\n"
         "#\n"
         "# The main dictionary of tacctl's FreeRADIUS instance: the unit starts the daemon with\n"
         "# '-D <this directory>', which makes it read this file in place of the package's main\n"
         "# dictionary. That one is included first, unchanged; no file of the package is edited.\n"
         "\n"
         f"$INCLUDE {params['system_dict']}\n"
         "\n"
         "# WTI (Western Telematic Inc.) console servers and power units: the access level of a login.\n"
         "# Written by tacctl from the numbers WTI publishes; not a copy of WTI's file, which also has\n"
         "# attributes tacctl does not send and carries no licence statement:\n"
         "#   https://ftp.wti.com/InfoCenter/rsa/dictionary/dictionary.wti\n"
         "# The value names are those of the WTI user's guide (the published file has none).\n"
         "VENDOR\t\tWTI\t\t\t24496\n"
         "BEGIN-VENDOR\tWTI\n"
         "ATTRIBUTE\tWTI-Super\t\t41\tinteger\n"]
    for _floor, value, label in reversed(WTI_SUPER_BANDS):
        w.append(f"VALUE\t\tWTI-Super\t\t{label}\t{value}\n")
    w.append("END-VENDOR\tWTI\n"
             "\n"
             "# tacctl's own attributes. A users entry sets them in the control list and the policy in\n"
             "# tacctl-radius.conf makes the vendor attributes of a reply from them. They are numbered in\n"
             "# the range FreeRADIUS reserves for site-local attributes (3000-3999), which it never puts\n"
             "# into a RADIUS packet.\n")
    for attr, number, kind in INTERNAL_ATTRS:
        w.append(f"ATTRIBUTE\t{attr.ljust(width)}\t{number}\t{kind}\n")
    return ''.join(w)


def render_radius(model, conf, params):
    """Model + merged tacctl.yaml view -> (conf text, users text, dictionary
    text). The first two are bound to each other by the render id, which is
    a hash of all three."""
    errs = store_validate(model)
    if errs:
        raise StoreError('cannot render an invalid model:\n  - ' + '\n  - '.join(errs))
    conf_text = render_conf_text(model, conf, params)
    users_text = render_users_text(model)
    dict_text = render_dictionary_text(params)
    rid = hashlib.sha256((conf_text + '\0' + users_text + '\0' + dict_text).encode()).hexdigest()[:16]
    return conf_text.replace(RID_PLACEHOLDER, rid), users_text.replace(RID_PLACEHOLDER, rid), dict_text


def restrictive_rules(conf, group):
    """True when commands.<group> restricts anything (has a deny rule)."""
    rules = (conf.get('commands') or {}).get(group) or []
    if not isinstance(rules, list):
        return False
    return any(isinstance(r, dict) and r.get('action') == 'deny' for r in rules)


def radius_notes(model, conf):
    """What the rendered state means for an operator, '<kind>|<detail>' lines:
    commands (groups with RADIUS users whose command rules restrict
    something), secret (scopes whose secret is beyond the advice of
    secret_constraints), filters (how many there are), vendors (how many of
    the scopes served send a vendor attribute to their untagged devices, and
    how many addresses are tagged)."""
    notes = []
    scopes = radius_scopes(model)
    users = radius_users(model)
    groups = sorted({u['group'] for u, _mine in users.values()})
    limited = [g for g in groups if restrictive_rules(conf, g)]
    if limited:
        notes.append('commands|' + ', '.join(limited))
    odd = [n for n, s in sorted(scopes.items())
           if len(s['secret']) > SECRET_ADVICE_MAX_LEN or not RE_SECRET_ADVICE.fullmatch(s['secret'])]
    if odd:
        notes.append('secret|' + ', '.join(odd))
    filters = model.get('filters') or {}
    if filters.get('deny') or filters.get('allow'):
        notes.append(f"filters|{len(filters.get('allow') or [])} allow, {len(filters.get('deny') or [])} deny")
    enabling = sum(1 for s in scopes.values() if s.get('vendor_attrs'))
    tagged = sum(len(s.get('devices') or {}) for s in scopes.values())
    notes.append(f"vendors|{enabling}|{len(scopes)}|{tagged}")
    return notes


def radius_conf_view(overrides_path):
    """The merged tacctl.yaml view arrives on stdin; a tacctl.yaml that does
    not parse would silently fall back to the defaults there -- refuse."""
    if overrides_path and os.path.exists(overrides_path):
        try:
            with open(overrides_path) as f:
                raw = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise StoreError(yaml_problem(overrides_path, e) + ' -- fix it before rendering')
        if raw is not None and not isinstance(raw, dict):
            raise StoreError(f'{overrides_path}: not a YAML mapping -- fix it before rendering')
    conf = json.load(sys.stdin)
    if not isinstance(conf, dict):
        raise StoreError('internal: merged tacctl.yaml view is not a mapping')
    return conf


def live_state(records, staged, live):
    """How a live artifact stands against its render, in the words of the
    contract's render_check."""
    live = os.path.abspath(live)
    status = 'unreadable' if records is None else rendered_status(records, live)
    same = False
    if os.path.exists(live):
        try:
            with open(staged, 'rb') as a, open(live, 'rb') as b:
                same = a.read() == b.read()
        except OSError:
            same = False
    if same:
        return 'current' if status == 'ok' else 'same'
    return status


def radius_main(argv):
    cmd, rest = argv[0], argv[1:]

    if cmd == 'render':
        # render <model.json> <out dir> <params json>; merged view on stdin.
        # Pure: model -> <out dir>/conf, <out dir>/users and <out dir>/dictionary.
        with open(rest[0]) as f:
            model = json.load(f)
        texts = render_radius(model, json.load(sys.stdin), json.loads(rest[2]))
        for fname, text in zip(('conf', 'users', 'dictionary'), texts):
            with open(os.path.join(rest[1], fname), 'w') as f:
                f.write(text)

    elif cmd == 'render-live':
        # render-live <store.yaml> <out dir> <tacctl.yaml path> <rendered.json>
        #             <live conf> <live users> <live dictionary> <params json>;
        #             merged view on stdin.
        # Renders the store to <out dir>/conf, <out dir>/users and
        # <out dir>/dictionary and prints
        # '<conf state> <users state> <dictionary state>'.
        model = store_normalize(store_load_raw(rest[0]))
        conf = radius_conf_view(rest[2])
        texts = render_radius(model, conf, json.loads(rest[7]))
        try:
            records = rendered_load(rest[3])
        except StoreError:
            records = None
        states = []
        for fname, text, live in zip(('conf', 'users', 'dictionary'), texts, rest[4:7]):
            path = os.path.join(rest[1], fname)
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w') as f:
                f.write(text)
            states.append(live_state(records, path, live))
        print(' '.join(states))

    elif cmd == 'notes':
        # notes <store.yaml> <tacctl.yaml path>; merged view on stdin.
        model = store_normalize(store_load_raw(rest[0]))
        for line in radius_notes(model, radius_conf_view(rest[1])):
            print(line)

    elif cmd == 'secret':
        # secret: the secret on stdin as a config string; exit 1 when it has none.
        quoted = fr_secret(sys.stdin.read())
        if quoted is None:
            return 1
        print(quoted)

    elif cmd == 'hash-raw':
        print(hash_raw(rest[0]))

    elif cmd == 'wti-super':
        # wti-super <priv-lvl>: '<WTI-Super value> <access level name>'.
        print(*wti_super(int(rest[0])))

    else:
        raise StoreError(f'internal: unknown command {cmd!r}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(radius_main(sys.argv[1:]))
    except StoreError as e:
        print(f'tacctl render: {e}', file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f'tacctl render: {e.filename or "I/O"}: {e.strerror}', file=sys.stderr)
        sys.exit(1)
PY
}

# Run the render program: _radius_python <command> [args...].
_radius_python() {
    python3 <(_store_py; _rendered_py; _listener_py; _render_radius_py) "$@"
}

# What the renderer needs to know about this machine, as JSON.
_radius_params() {
    printf '{"name": "%s", "user": "%s", "group": "%s", "log_dir": "%s", "pid_file": "%s", "lib_dir": "%s", "system_dict": "%s"}' \
        "$RADIUS_NAME" "$RADIUS_USER" "$RADIUS_GROUP" "$RADIUS_LOG_DIR" "$RADIUS_PID_FILE" "$RADIUS_LIB_DIR" "$RADIUS_SYSTEM_DICT"
}

# render_radius_config <model.json> <out dir>
# Pure: a model (as model_dump prints it) and the merged tacctl.yaml view ->
# <out dir>/conf, <out dir>/users and <out dir>/dictionary. No drift check, no
# records, no daemon.
render_radius_config() {
    local model="${1:-}" out="${2:-}"
    if [[ -z "$model" || -z "$out" ]]; then
        error "Usage: render_radius_config <model.json> <out dir>"
        return 1
    fi
    _conf_load_cache
    _radius_python render "$model" "$out" "$(_radius_params)" < <(printf '%s' "$_TACCTL_CFG_CACHE")
}

# _radius_render_live <dir>: render the current store into <dir>/conf,
# <dir>/users and <dir>/dictionary; prints
# '<conf state> <users state> <dictionary state>'.
_radius_render_live() {
    _conf_load_cache
    _radius_python render-live "$STORE_FILE" "$1" "${TACCTL_OVERRIDES_FILE:-}" "$RENDERED_FILE" \
        "$RADIUS_CONF" "$RADIUS_USERS" "$RADIUS_DICT" "$(_radius_params)" < <(printf '%s' "$_TACCTL_CFG_CACHE")
}

# The state furthest from the render among the words given.
_radius_worst() {
    local word s
    for word in unreadable drift unrecorded missing ok same current; do
        for s in "$@"; do
            if [[ "$s" == "$word" ]]; then
                echo "$word"
                return 0
            fi
        done
    done
    return 1
}

# _radius_daemon_check <dir>: have the daemon itself read <dir>/conf,
# <dir>/users and <dir>/dictionary ('radiusd -C'). Returns 0 accepted; 2
# skipped (no daemon on this machine); 1 rejected, the daemon's errors on
# stderr.
#
# The check drops to the service account before it reads the users file, so
# the files are copied into a scratch directory beside the live ones (0750
# root:<daemon group>; a staging directory under /tmp is closed to that
# account) and the daemon is pointed at it with -d, and at the copy of the
# dictionary with -D. The live files are not touched and the directory is
# removed before this returns.
_radius_daemon_check() {
    local dir="$1" chk out rc=0
    [[ -x "$RADIUS_BIN" && -d "$RADIUS_DIR" ]] || return 2
    # tacctl's dictionary includes the package's; without that one the daemon
    # knows no attribute at all, and says so in a way that names neither.
    if [[ ! -r "$RADIUS_SYSTEM_DICT" ]]; then
        error "FreeRADIUS's main dictionary is not at ${RADIUS_SYSTEM_DICT}; tacctl's dictionary (${RADIUS_DICT}) includes it."
        error "The freeradius package is incomplete or keeps its dictionaries somewhere tacctl does not know. Nothing was changed."
        return 1
    fi
    chk=$(mktemp -d "${RADIUS_DIR}/.tacctl-check.XXXXXX") || return 1
    if ! { cp "${dir}/conf" "${chk}/${RADIUS_NAME}.conf" && cp "${dir}/users" "${chk}/${RADIUS_NAME}.users" \
            && mkdir "${chk}/dictionary.d" && cp "${dir}/dictionary" "${chk}/dictionary.d/dictionary"; }; then
        rm -rf "$chk"
        return 1
    fi
    chown -R "root:${RADIUS_GROUP}" "$chk" 2> /dev/null || true
    chmod 750 "$chk" "${chk}/dictionary.d"
    chmod 640 "${chk}/${RADIUS_NAME}.conf" "${chk}/${RADIUS_NAME}.users" "${chk}/dictionary.d/dictionary"
    out=$("$RADIUS_BIN" -C -lstdout -d "$chk" -D "${chk}/dictionary.d" -n "$RADIUS_NAME" 2>&1) || rc=$?
    rm -rf "$chk"
    (( rc == 0 )) && return 0
    error "FreeRADIUS rejects the rendered configuration ('${RADIUS_BIN##*/} -C'):"
    # The scratch paths are the live files' as far as the operator is concerned.
    printf '%s\n' "$out" | { grep -i 'error' || true; } | sed "s#${chk}/dictionary.d#${RADIUS_DICT_DIR}#g; s#${chk}#${RADIUS_DIR}#g" | tail -n 5 >&2
    return 1
}

# Copy a file that is about to be overwritten into backups/legacy/.
_radius_save_displaced() {
    local src="$1" dir="${BACKUP_DIR}/legacy" dest
    mkdir -p "$dir" || return 1
    chmod 700 "$dir"
    dest="${dir}/$(basename "$src").drift.$(date +%Y%m%d_%H%M%S_%3N)"
    cp "$src" "$dest" || return 1
    chmod 600 "$dest"
    warn "Previous ${src} saved to ${dest}" >&2
}

# The artifacts as one phrase for a message.
_radius_artifact_names() {
    echo "${RADIUS_CONF}, ${RADIUS_USERS} or ${RADIUS_DICT}"
}

# _radius_render_stage <dir> <force 0|1>: render, prove, and decide whether
# the live artifacts may be replaced. Leaves <dir>/conf, <dir>/users,
# <dir>/dictionary and <dir>/status ('<conf state> <users state>
# <dictionary state>'). An artifact that is missing is simply written: that
# is the state of an install from before the dictionary existed.
_radius_render_stage() {
    local dir="$1" force="$2" states worst rc=0
    states=$(_radius_render_live "$dir") || return 1
    # shellcheck disable=SC2086  # three words
    worst=$(_radius_worst $states) || return 1
    case "$worst" in
        current|same|ok|missing) ;;
        drift|unrecorded)
            if (( ! force )); then
                if [[ "$worst" == "drift" ]]; then
                    error "$(_radius_artifact_names) was edited since tacctl rendered it; rendering would discard those edits."
                else
                    error "$(_radius_artifact_names) was not rendered by tacctl; rendering would replace it."
                fi
                error "There is no way to adopt an edit of the RADIUS files into the store. To discard it: 'tacctl config render --force' (the current files are saved under ${BACKUP_DIR}/legacy/ first)."
                return 3
            fi
            ;;
        *)
            error "Cannot read ${RENDERED_FILE}; refusing to overwrite ${RADIUS_CONF}."
            return 1
            ;;
    esac
    _radius_daemon_check "$dir" || rc=$?
    (( rc == 0 || rc == 2 )) || return 1
    printf '%s\n' "$states" > "${dir}/status" || return 1
}

# _radius_install_file <staged> <live> <state>: one artifact of a commit.
# Prints CHANGED when the live file was replaced.
_radius_install_file() {
    local staged="$1" live="$2" state="$3"
    case "$state" in
        current) return 0 ;;
        same)    rendered_record "$live"; return ;;
        drift|unrecorded) _radius_save_displaced "$live" || return 1 ;;
    esac
    # Same directory as the target, so the final step is a rename.
    local new="${live}.tacctl-new"
    if [[ ! -d "${live%/*}" ]]; then
        # The dictionary's directory, on its first render.
        mkdir -p "${live%/*}" || return 1
        chmod 750 "${live%/*}"
        chown "root:${RADIUS_GROUP}" "${live%/*}" 2> /dev/null || true
    fi
    cp "$staged" "$new" || return 1
    chmod 640 "$new"
    chown "root:${RADIUS_GROUP}" "$new" 2> /dev/null || true
    mv -f "$new" "$live" || { rm -f "$new"; return 1; }
    rendered_record "$live" || return 1
    echo "CHANGED"
}

# _radius_render_commit <dir>: install what _radius_render_stage left. The
# dictionary first (the other two need its attributes), then the users file:
# until the config that carries the new render id is in place too, the daemon
# would match nobody rather than a mix of two renders.
_radius_render_commit() {
    local dir="$1" conf_state users_state dict_state a b c
    read -r conf_state users_state dict_state < "${dir}/status" || return 1
    mkdir -p "$RADIUS_DIR" || return 1
    c=$(_radius_install_file "${dir}/dictionary" "$RADIUS_DICT" "$dict_state") || return 1
    a=$(_radius_install_file "${dir}/users" "$RADIUS_USERS" "$users_state") || return 1
    b=$(_radius_install_file "${dir}/conf" "$RADIUS_CONF" "$conf_state") || return 1
    if [[ -n "${a}${b}${c}" ]]; then
        echo "CHANGED"
    else
        echo "UNCHANGED"
    fi
}

# The gate of store_apply's step 1. Hand edits cannot be adopted, so a file
# tacctl has no record of is refused like an edited one.
_radius_render_gate() {
    local f rc
    for f in "$RADIUS_CONF" "$RADIUS_USERS" "$RADIUS_DICT"; do
        rc=0
        rendered_check "$f" > /dev/null || rc=$?
        case "$rc" in
            0|2) continue ;;
            1)   error "${f} was edited since tacctl rendered it; this command would discard those edits." ;;
            3)   error "${f} was not rendered by tacctl; this command would replace it." ;;
            *)
                error "Cannot read ${RENDERED_FILE}; refusing to overwrite ${f}."
                return 1
                ;;
        esac
        error "Nothing was changed. There is no way to adopt an edit of the RADIUS files into the store; to discard it: 'tacctl config render --force'. Then run this command again."
        return 3
    done
    return 0
}

_radius_render_check_run() {
    local tmpd states rc=0
    tmpd=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064  # expand tmpd now; the subshell owns this trap
    trap "rm -rf '${tmpd}'" EXIT
    states=$(_radius_render_live "$tmpd") || exit 1
    _radius_daemon_check "$tmpd" || rc=$?
    (( rc == 0 || rc == 2 )) || exit 1
    # shellcheck disable=SC2086  # three words
    _radius_worst $states
    exit 0
}

# _radius_render_apply: render this backend alone and install the result (the
# upgrade's re-render; a command that changes the store goes through
# store_apply and renders every backend). Prints CHANGED or UNCHANGED.
# Returns 1 failed, 3 refused (an artifact was edited by hand); nothing is
# replaced then.
_radius_render_apply() {
    (
        local tmpd rc=0
        tmpd=$(mktemp -d) || exit 1
        # shellcheck disable=SC2064  # expand tmpd now; the subshell owns this trap
        trap "rm -rf '${tmpd}'" EXIT
        _radius_render_stage "$tmpd" 0 >&2 || rc=$?
        (( rc == 0 )) || exit "$rc"
        _radius_render_commit "$tmpd"
    )
}

# The notes of the rendered state, '<kind>|<text>' lines (see radius_notes).
_radius_notes() {
    [[ -f "$STORE_FILE" ]] || return 0
    _conf_load_cache
    _radius_python notes "$STORE_FILE" "${TACCTL_OVERRIDES_FILE:-}" \
        < <(printf '%s' "$_TACCTL_CFG_CACHE") 2> /dev/null || true
}

# =====================================================================
#  UNIT, DROP-IN, LISTENERS
# =====================================================================

# The drop-in that makes the package's unit run tacctl's instance, with
# tacctl's dictionary ('-D'). The package's pre-start and reload commands
# name its own configuration, so every Exec line is replaced.
_radius_dropin_text() {
    local args="-d ${RADIUS_DIR} -D ${RADIUS_DICT_DIR} -n ${RADIUS_NAME}"
    cat <<EOF
# Installed by tacctl ('tacctl backend enable radius'), removed by 'tacctl backend disable radius'.
# ${RADIUS_UNIT} runs tacctl's FreeRADIUS instance (${RADIUS_CONF}) instead of the package's radiusd.conf.
[Service]
ExecStartPre=
EOF
    if [[ "$RADIUS_FAMILY" == "rhel" ]]; then
        cat <<EOF
ExecStartPre=-/bin/chown -R ${RADIUS_USER}:${RADIUS_GROUP} /var/run/radiusd
ExecStartPre=${RADIUS_BIN} -C -lstdout ${args}
ExecStart=
ExecStart=${RADIUS_BIN} ${args}
EOF
    else
        cat <<EOF
ExecStartPre=${RADIUS_BIN} -C -lstdout ${args}
ExecStart=
ExecStart=${RADIUS_BIN} -f ${args}
EOF
    fi
    cat <<EOF
ExecReload=
ExecReload=${RADIUS_BIN} -C -lstdout ${args}
ExecReload=/bin/kill -HUP \$MAINPID
EOF
}

# Set by _radius_dropin_install: 1 when it wrote the drop-in.
RADIUS_DROPIN_CHANGED=0

# Install the drop-in when it is missing or not what this release writes.
# Prints nothing; returns 1 when it cannot be written.
_radius_dropin_install() {
    local want
    RADIUS_DROPIN_CHANGED=0
    want=$(_radius_dropin_text)
    if [[ -f "$RADIUS_DROPIN" && "$(cat "$RADIUS_DROPIN")" == "$want" ]]; then
        return 0
    fi
    mkdir -p "$(dirname "$RADIUS_DROPIN")" || return 1
    printf '%s\n' "$want" > "${RADIUS_DROPIN}.tacctl-new" || return 1
    chmod 644 "${RADIUS_DROPIN}.tacctl-new"
    mv -f "${RADIUS_DROPIN}.tacctl-new" "$RADIUS_DROPIN" || return 1
    RADIUS_DROPIN_CHANGED=1
    systemctl daemon-reload
}

# Restart the unit on what the artifacts now are. A drop-in from a release
# before the dictionary starts the daemon without '-D'; the configuration a
# render of this release writes does not load that way, so the drop-in is
# brought in line first (only once the dictionary it names is there, and only
# while the backend runs tacctl's instance).
_radius_unit_restart() {
    if [[ -f "$RADIUS_DROPIN" && -f "$RADIUS_DICT" ]]; then
        _radius_dropin_install || warn "Could not update ${RADIUS_DROPIN}."
    fi
    systemctl restart "$RADIUS_UNIT" 2> /dev/null
}

_radius_dropin_remove() {
    [[ -f "$RADIUS_DROPIN" ]] || return 0
    rm -f "$RADIUS_DROPIN"
    rmdir "$(dirname "$RADIUS_DROPIN")" 2> /dev/null || true
    systemctl daemon-reload
}

_radius_logrotate_text() {
    cat <<EOF
# Installed by tacctl: the logs of its FreeRADIUS instance.
${RADIUS_DAEMON_LOG} ${RADIUS_AUTH_LOG} ${RADIUS_ACCT_LOG} {
	weekly
	rotate 12
	missingok
	notifempty
	compress
	delaycompress
	copytruncate
	su ${RADIUS_USER} ${RADIUS_GROUP}
}
EOF
}

_radius_logrotate_install() {
    [[ -d "$(dirname "$RADIUS_LOGROTATE")" ]] || return 0
    _radius_logrotate_text > "$RADIUS_LOGROTATE" || return 1
    chmod 644 "$RADIUS_LOGROTATE"
}

# The listeners in effect, one '<name> <network> <address>' line each, the
# built-in ones (auth, acct) first.
_radius_listener_lines() {
    if ! grep -qs 'listeners' "$TACCTL_OVERRIDES_FILE"; then
        printf '%s\n' "auth udp :1812" "acct udp :1813"
        return 0
    fi
    local name net addr _rest
    while IFS=$'\t' read -r name net addr _rest; do
        echo "${name} ${net} ${addr}"
    done < <(backend_listeners radius)
}

# _radius_listener_get <name>: sets L_NET, L_ADDR, L_ROLE and L_SRC
# (override|default). Returns 1 when there is none of that name.
_radius_listener_get() {
    local want="$1" name net addr role _m src
    L_NET="" L_ADDR="" L_ROLE="" L_SRC="default"
    while IFS=$'\t' read -r name net addr role _m src; do
        if [[ "$name" == "$want" ]]; then
            L_NET="$net" L_ADDR="$addr" L_ROLE="$role" L_SRC="$src"
        fi
    done < <(backend_listeners radius)
    [[ -n "$L_NET" ]]
}

_radius_listener_builtin() {
    [[ "$1" == "auth" || "$1" == "acct" ]]
}

_radius_listener_show() {
    local want="$1" name net addr role _m src
    if [[ "$want" != "default" ]] && ! _radius_listener_get "$want"; then
        error "No RADIUS listener '${want}'. Create it: tacctl config listen --backend radius --listener ${want} udp <address>"
        return 1
    fi
    while IFS=$'\t' read -r name net addr role _m src; do
        [[ "$want" == "default" || "$want" == "$name" ]] || continue
        if [[ "$src" == "override" ]]; then
            src="set in ${TACCTL_OVERRIDES_FILE}"
        else
            src="built-in default"
        fi
        echo "  RADIUS listener '${name}' (${role}): ${net} ${addr}   (${src})"
    done < <(backend_listeners radius)
}

# Would listeners.radius.<name> = <json> be refused by the schema or collide
# with another listener? Message on stderr.
_radius_listener_check() {
    _conf_load_cache
    python3 <(_listener_py; cat <<'PY'
import json, sys
doc, name, value = json.loads(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3])
section = doc.get('listeners') if isinstance(doc.get('listeners'), dict) else {}
mine = section.get('radius') if isinstance(section.get('radius'), dict) else {}
doc['listeners'] = dict(section, radius=dict(mine, **{name: value}))
path = f'listeners.radius.{name}'
bad = listeners_problems(doc, only=path)
if bad:
    print(bad[0][len(path) + 2:], file=sys.stderr)
    sys.exit(1)
PY
) "$_TACCTL_CFG_CACHE" "$1" "$2"
}

# Is the backend in backends.enabled and its daemon set up?
_radius_serving() {
    _backends_load 2> /dev/null || return 1
    _backend_is_enabled radius && backend_radius_installed
}

# _radius_listener_apply <writer> [<arg>...]: run a conf_* writer that changes
# listeners.radius through store_apply (the listen{} blocks are part of the
# rendered config), restart, and require the unit to stay up; when it does
# not, tacctl.yaml and the artifacts go back and the unit is restarted on
# them. Returns 0 applied; 1 failed or refused, everything as it was.
_radius_listener_apply() {
    local keep rc=0
    keep=$(mktemp "${TACCTL_STATE_DIR}/.radius-listen.XXXXXX") || return 1
    if [[ -f "$TACCTL_OVERRIDES_FILE" ]]; then
        cp -p "$TACCTL_OVERRIDES_FILE" "$keep" || { rm -f "$keep"; return 1; }
    else
        rm -f "$keep"
    fi
    store_apply --defer-restart radius "$@" || rc=$?
    if (( rc != 0 )); then
        rm -f "$keep"
        return 1
    fi
    if ! _radius_serving; then
        rm -f "$keep"
        return 0
    fi
    _radius_unit_restart || true
    sleep "$RADIUS_SETTLE_SECONDS"
    if systemctl is-active --quiet "$RADIUS_UNIT"; then
        rm -f "$keep"
        return 0
    fi
    error "${RADIUS_UNIT%.service} did not stay up with the new listener; putting the previous one back."
    if ! store_apply --defer-restart radius _radius_overrides_put "$keep"; then
        warn "Could not put the previous listener back; fix listeners.radius in ${TACCTL_OVERRIDES_FILE} and run 'tacctl config render'."
    fi
    rm -f "$keep"
    _radius_unit_restart || true
    return 1
}

# Writer for store_apply: tacctl.yaml becomes the copy at $1 (absent: none).
_radius_overrides_put() {
    if [[ -f "$1" ]]; then
        cp -p "$1" "$TACCTL_OVERRIDES_FILE" || return 1
    else
        rm -f "$TACCTL_OVERRIDES_FILE"
    fi
    _conf_invalidate
}

_radius_listener_set() {
    local name="$1" net="$2" addr="$3"
    if [[ "$name" == "default" ]]; then
        error "The RADIUS backend has two built-in listeners; name one: --listener auth (udp :1812) or --listener acct (udp :1813)."
        return 1
    fi
    case "$net" in
        udp|udp6) ;;
        *)
            error "Invalid network '${net}': the RADIUS backend listens on udp or udp6. Usage: tacctl config listen --backend radius --listener <name> <udp|udp6> <address>"
            return 1
            ;;
    esac
    if [[ -z "$addr" ]]; then
        error "Missing address. Example: tacctl config listen --backend radius --listener ${name} ${net} :1812"
        return 1
    fi
    validate_listen_address "$net" "$addr" || return 1

    local existed=1 role
    _radius_listener_get "$name" || existed=0
    if [[ "$L_NET" == "$net" && "$L_ADDR" == "$addr" ]]; then
        info "RADIUS listener '${name}' already on ${net} ${addr}."
        return 0
    fi
    # A listener answers authentication or accounting, never both. An
    # existing one keeps what it does; a new one is an accounting listener
    # when its name starts with 'acct', else an authentication listener.
    role="${L_ROLE:-auth}"
    if (( ! existed )) && [[ "$name" == acct* ]]; then
        role="acct"
    fi

    local json why
    json=$(printf '{"network": "%s", "address": "%s", "role": "%s"}' "$net" "$addr" "$role")
    if ! why=$(_radius_listener_check "$name" "$json" 2>&1); then
        error "Cannot listen on ${net} ${addr}: ${why}"
        return 1
    fi
    if [[ "$net" == "udp6" && "$L_NET" != "udp6" ]]; then
        warn "A udp6 listener serves IPv6 clients only; scope prefixes that are IPv4 are reached through a udp listener."
    fi
    _radius_listener_apply conf_set_json "listeners.radius.${name}" "$json" || return 1
    if (( existed )); then
        info "RADIUS listener '${name}' changed to ${net} ${addr}."
    else
        info "RADIUS listener '${name}' (${role}) added on ${net} ${addr}."
    fi
    echo ""
}

_radius_listener_reset() {
    local name="$1"
    if [[ "$name" == "default" ]]; then
        error "Name the listener: --listener auth or --listener acct."
        return 1
    fi
    if ! _radius_listener_get "$name"; then
        error "No RADIUS listener '${name}'."
        return 1
    fi
    if [[ "$L_SRC" == "default" ]]; then
        info "RADIUS listener '${name}' is already on its default (${L_NET} ${L_ADDR})."
        return 0
    fi
    _radius_listener_apply conf_unset "listeners.radius.${name}" || return 1
    if _radius_listener_builtin "$name"; then
        info "RADIUS listener '${name}' is back on its default."
    else
        info "RADIUS listener '${name}' removed."
    fi
    echo ""
}

# =====================================================================
#  STATUS AND LOGS
# =====================================================================

_radius_status_service() {
    local state state_color="$GREEN" since pid mem
    state=$(systemctl is-active "$RADIUS_UNIT" 2> /dev/null) || true
    state=${state:-unknown}
    [[ "$state" != "active" ]] && state_color="$RED"
    echo -e "  ${BOLD}Service:${NC}              ${state_color}${state}${NC} (${RADIUS_UNIT})"
    if [[ "$state" == "active" ]]; then
        since=$(systemctl show "$RADIUS_UNIT" --property=ActiveEnterTimestamp 2> /dev/null | cut -d= -f2)
        echo -e "  ${BOLD}Since:${NC}                ${since}"
    fi
    pid=$(systemctl show "$RADIUS_UNIT" --property=MainPID 2> /dev/null | cut -d= -f2)
    if [[ -n "$pid" && "$pid" != "0" ]]; then
        echo -e "  ${BOLD}PID:${NC}                  ${pid}"
        mem=$(ps -o rss= -p "$pid" 2> /dev/null | awk '{printf "%.1f MB", $1/1024}')
        echo -e "  ${BOLD}Memory:${NC}               ${mem}"
    fi
    local name net addr bound
    while read -r name net addr; do
        [[ -n "$name" ]] || continue
        bound=$(backend_listener_probe "$net" "$addr")
        if [[ -n "$bound" ]]; then
            echo -e "  ${BOLD}Listening (${name}):${NC}     ${GREEN}${bound}/udp${NC}"
        else
            echo -e "  ${BOLD}Listening (${name}):${NC}     ${RED}port ${addr##*:}/udp not detected${NC}"
        fi
    done < <(_radius_listener_lines)
}

_radius_status_config() {
    echo -e "  ${BOLD}Config:${NC}               ${RADIUS_CONF}"
    echo -e "  ${BOLD}Authentication:${NC}       PAP against the store's bcrypt hashes (no CHAP, MS-CHAP or EAP)"
    local kind text
    while IFS='|' read -r kind text; do
        case "$kind" in
            commands) echo -e "  ${YELLOW}Command rules:${NC}        not enforced over RADIUS (commands.<group> of: ${text})" ;;
            secret)   echo -e "  ${YELLOW}Secrets:${NC}              beyond what every RADIUS client takes (${RADIUS_SECRET_MAX_LEN} characters, no space, ASCII): ${text}" ;;
            filters)  echo -e "  ${BOLD}Connection filters:${NC}   enforced (${text})" ;;
            vendors)  _radius_status_vendors "$text" ;;
        esac
    done < <(_radius_notes)
}

# The vendor-attributes line of the status reports, from the 'vendors' note
# ('<scopes that enable one>|<scopes served>|<tagged addresses>'): a count,
# not a line per scope ('tacctl scope list' has those).
_radius_status_vendors() {
    local enabling served tagged
    IFS='|' read -r enabling served tagged <<< "$1"
    if (( enabling == 0 && tagged == 0 )); then
        echo -e "  ${BOLD}Vendor attributes:${NC}    not sent (no scope enables one: tacctl scope vendor-attrs <scope> enable <vendor>)"
    else
        echo -e "  ${BOLD}Vendor attributes:${NC}    enabled for ${enabling} of ${served} scope(s), ${tagged} tagged address(es) (tacctl scope list)"
    fi
}

# status summary: what 'tacctl backend status' adds for this backend.
_radius_status_summary() {
    local kind text
    while IFS='|' read -r kind text; do
        [[ "$kind" == "vendors" ]] && _radius_status_vendors "$text"
    done < <(_radius_notes)
    return 0
}

# Records of a detail file: one per paragraph.
_radius_acct_records() {
    grep -c '^[^[:space:]]' "$1" 2> /dev/null || true
}

_radius_status_accounting() {
    [[ -f "$RADIUS_ACCT_LOG" ]] || return 0
    echo -e "  ${BOLD}Accounting log:${NC}       $(du -sh "$RADIUS_ACCT_LOG" 2> /dev/null | awk '{print $1}') ($(_radius_acct_records "$RADIUS_ACCT_LOG") records)"
}

# Lines of the auth log from the last 24 hours (it is written in local time).
_radius_auth_recent() {
    [[ -r "$RADIUS_AUTH_LOG" ]] || return 0
    local cutoff
    cutoff=$(date -d '24 hours ago' '+%Y-%m-%d %H:%M:%S' 2> /dev/null) || cutoff=""
    awk -v c="$cutoff" '($1 " " $2) >= c' "$RADIUS_AUTH_LOG"
}

# FreeRADIUS has no counters to scrape: the figures are counted from the
# auth log tacctl's policy writes.
_radius_status_activity() {
    local recent accepted=0 rejected=0 line
    recent=$(_radius_auth_recent)
    if [[ -n "$recent" ]]; then
        accepted=$(grep -c ' Access-Accept ' <<< "$recent" || true)
        rejected=$(grep -c ' Access-Reject ' <<< "$recent" || true)
    fi
    echo ""
    echo -e "  ${BOLD}Authentication (last 24 hours, from ${RADIUS_AUTH_LOG##*/}):${NC}"
    echo -e "    Accepted:           ${accepted}"
    echo -e "    Rejected:           ${rejected}"
    echo ""
    echo -e "  ${BOLD}Recent Rejects (last 5):${NC}"
    if (( rejected > 0 )); then
        grep ' Access-Reject ' <<< "$recent" | tail -5 | while IFS= read -r line; do
            echo -e "    ${RED}${line}${NC}"
        done
    else
        echo -e "    ${GREEN}No rejects in the last 24 hours${NC}"
    fi
}

# 'YYYY-MM-DD HH:MM:SS' of the user's last Access-Accept, or "never". An
# accepted line ends in ' user=<name>', and only a request whose User-Name
# is exactly a user of the store is ever accepted.
_radius_last_login() {
    local username="$1" ts=""
    if [[ -r "$RADIUS_AUTH_LOG" ]]; then
        ts=$(grep -F ' Access-Accept ' "$RADIUS_AUTH_LOG" 2> /dev/null \
            | grep -F -- " user=${username}" | awk -v u="user=${username}" '$NF == u' \
            | tail -1 | cut -c1-19) || ts=""
    fi
    echo "${ts:-never}"
}

_radius_log_clear() {
    local force=false f
    case "${1:-}" in
        -y|--force|--yes) force=true ;;
    esac
    echo ""
    echo -e "${BOLD}Clear RADIUS logs${NC}"
    echo "--------------------------------------------"
    warn "This truncates ${RADIUS_AUTH_LOG}, ${RADIUS_ACCT_LOG} and ${RADIUS_DAEMON_LOG}."
    warn "Historical authentication and accounting records will be lost."
    if [[ "$force" != "true" ]]; then
        local confirm=""
        read -rp "  Continue? [y/N]: " confirm || true
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            info "Cancelled."
            return 0
        fi
    fi
    # Truncated in place: the daemon keeps writing to the same files.
    for f in "$RADIUS_AUTH_LOG" "$RADIUS_ACCT_LOG" "$RADIUS_DAEMON_LOG"; do
        [[ -f "$f" ]] || continue
        : > "$f" 2> /dev/null || warn "Could not truncate ${f} (check permissions)."
    done
    info "RADIUS logs cleared."
    echo ""
}

# =====================================================================
#  INSTALL, UPGRADE, UNINSTALL
# =====================================================================

_radius_pkg_install() {
    if [[ "$RADIUS_FAMILY" == "debian" ]] && command -v apt-get > /dev/null 2>&1; then
        # shellcheck disable=SC2086  # a list of package names
        _apt_install $RADIUS_PKGS
    elif command -v dnf > /dev/null 2>&1; then
        # shellcheck disable=SC2086
        dnf install -y -q $RADIUS_PKGS > /dev/null
    elif command -v yum > /dev/null 2>&1; then
        # shellcheck disable=SC2086
        yum install -y -q $RADIUS_PKGS > /dev/null
    else
        return 1
    fi
}

# Is the package's unit free for tacctl to run its instance under? Not when it
# is running or enabled without tacctl's drop-in: that is somebody's RADIUS
# server. Returns 1 with what to do about it.
_radius_unit_free() {
    local why=""
    [[ -f "$RADIUS_DROPIN" ]] && return 0
    if systemctl is-active --quiet "$RADIUS_UNIT" 2> /dev/null; then
        why="running"
    elif systemctl is-enabled --quiet "$RADIUS_UNIT" 2> /dev/null; then
        why="enabled at boot"
    fi
    [[ -n "$why" ]] || return 0
    error "FreeRADIUS is already installed on this machine and ${RADIUS_UNIT} is ${why}: somebody's RADIUS server."
    error "tacctl runs its own configuration under that unit (the files in ${RADIUS_DIR} stay as they are, but are no longer served)."
    error "If it is not in use, hand the unit over and run this again:  systemctl disable --now ${RADIUS_UNIT}"
    return 1
}

# install build: the packages. A FreeRADIUS that was here before and is
# active or enabled is not tacctl's to take.
_radius_install_build() {
    if [[ -z "$RADIUS_FAMILY" ]]; then
        error "Neither a Debian/Ubuntu nor a RHEL-family system: tacctl does not know where FreeRADIUS lives here."
        exit 1
    fi
    if [[ -x "$RADIUS_BIN" ]]; then
        _radius_unit_free || exit 1
        info "FreeRADIUS is already installed (${RADIUS_BIN}); ${RADIUS_UNIT} is neither running nor enabled."
        return 0
    fi
    info "Installing FreeRADIUS (${RADIUS_PKGS})..."
    if ! _radius_pkg_install || [[ ! -x "$RADIUS_BIN" ]]; then
        error "Could not install ${RADIUS_PKGS}. Install them and run this again."
        exit 1
    fi
    # Debian starts the package's default configuration on installation.
    systemctl disable --quiet --now "$RADIUS_UNIT" 2> /dev/null || true
    info "FreeRADIUS installed; the package's own configuration in ${RADIUS_DIR} is left as shipped and is not served."
}

_radius_install_files() {
    _radius_logrotate_install || warn "Could not write ${RADIUS_LOGROTATE}."
}

_radius_install_account() {
    if ! id "$RADIUS_USER" > /dev/null 2>&1; then
        error "The FreeRADIUS service account '${RADIUS_USER}' does not exist; the package did not install as expected."
        exit 1
    fi
    if [[ ! -d "$RADIUS_DIR" || ! -d "$RADIUS_LOG_DIR" ]]; then
        error "${RADIUS_DIR} or ${RADIUS_LOG_DIR} is missing; the package did not install as expected."
        exit 1
    fi
    if [[ ! -r "$RADIUS_SYSTEM_DICT" ]]; then
        error "FreeRADIUS's main dictionary is not at ${RADIUS_SYSTEM_DICT}; the package did not install as expected."
        exit 1
    fi
}

# install start: after the first render.
_radius_install_start() {
    if [[ ! -f "$RADIUS_CONF" || ! -f "$RADIUS_USERS" || ! -f "$RADIUS_DICT" ]]; then
        error "${RADIUS_CONF} was not rendered."
        exit 1
    fi
    backend_radius_service enable || exit 1
    info "Starting ${RADIUS_UNIT%.service}..."
    systemctl start "$RADIUS_UNIT" || true
    sleep 2
    if ! systemctl is-active --quiet "$RADIUS_UNIT"; then
        error "FreeRADIUS failed to start. Check: journalctl -u ${RADIUS_UNIT%.service} and ${RADIUS_DAEMON_LOG}"
        exit 1
    fi
    info "FreeRADIUS is running (${RADIUS_UNIT}, PAP only)."
    local name net addr
    while read -r name net addr; do
        [[ -n "$name" ]] || continue
        if [[ -n "$(backend_listener_probe "$net" "$addr")" ]]; then
            info "Listening on port ${addr##*:}/udp (${name})"
        else
            warn "Port ${addr##*:}/udp (${name}) not detected — check ${RADIUS_DAEMON_LOG}."
        fi
    done < <(_radius_listener_lines)
    backend_radius_render_notes
}

# What 'upgrade config' did, for the summary 'upgrade finish' adds:
# '' nothing | rendered | failed.
RADIUS_UPGRADE_STATE=""

# upgrade config: bring the artifacts and the drop-in in line with this
# release, as one step, and restart when either changed. A release can change
# what it renders (the dictionary, and with it the unit's command line, came
# with the vendor attributes); the files of the release before are what
# tacctl rendered then, so this is a re-render like any other, not drift.
# The order matters: the artifacts first, the drop-in only once the
# dictionary it names is in place, then the restart. A hand-edited artifact
# refuses the render (as it refuses every mutation) and leaves all of it,
# the running daemon included, as it was. Never fails the upgrade.
_radius_upgrade_config() {
    RADIUS_UPGRADE_STATE=""
    [[ -f "$STORE_FILE" && -f "$RADIUS_DROPIN" ]] || return 0
    backend_radius_installed || return 0
    local result rc=0
    result=$(_radius_render_apply) || rc=$?
    if (( rc != 0 )); then
        RADIUS_UPGRADE_STATE="failed"
        warn "The RADIUS files were not re-rendered; FreeRADIUS keeps serving the previous ones. Run 'tacctl config render' once the problem above is fixed."
        return 0
    fi
    _radius_dropin_install || warn "Could not update ${RADIUS_DROPIN}."
    if [[ "$result" != "CHANGED" && "$RADIUS_DROPIN_CHANGED" != "1" ]]; then
        return 0
    fi
    RADIUS_UPGRADE_STATE="rendered"
    if [[ "$result" == "CHANGED" ]]; then
        info "RADIUS: re-rendered $(backend_artifact_names radius)."
        # What an operator of a release before the vendor attributes notices
        # first: an Accept carried Cisco and Juniper attributes for everyone.
        local kind text
        while IFS='|' read -r kind text; do
            if [[ "$kind" == "vendors" && "$text" == 0\|*\|0 ]]; then
                warn "RADIUS: no scope enables a vendor attribute, so an Access-Accept carries Service-Type only."
                warn "Enable what each scope's devices need: tacctl scope vendor-attrs <scope> enable cisco|juniper|wti (or tag addresses: tacctl scope devices)."
            fi
        done < <(_radius_notes)
    fi
    if [[ "$RADIUS_DROPIN_CHANGED" == "1" ]]; then
        info "RADIUS: updated ${RADIUS_DROPIN}."
    fi
    info "Restarting ${RADIUS_UNIT%.service}..."
    systemctl restart "$RADIUS_UNIT" 2> /dev/null || true
    sleep 2
    if systemctl is-active --quiet "$RADIUS_UNIT"; then
        info "FreeRADIUS is running."
    else
        RADIUS_UPGRADE_STATE="failed"
        error "FreeRADIUS did not start after the re-render. Check: journalctl -u ${RADIUS_UNIT%.service} and ${RADIUS_DAEMON_LOG}"
    fi
    return 0
}

# upgrade files: the logrotate file as this release writes it.
_radius_upgrade_files() {
    backend_radius_installed || return 0
    _radius_logrotate_install || true
    return 0
}

# upgrade finish: one line of the closing summary.
_radius_upgrade_finish() {
    case "$RADIUS_UPGRADE_STATE" in
        rendered) UPGRADE_SUMMARY_NOTES+=("RADIUS: config re-rendered for this release, FreeRADIUS restarted") ;;
        failed)   UPGRADE_SUMMARY_NOTES+=("RADIUS: NOT brought in line with this release (see above); 'tacctl config validate' says what stands") ;;
    esac
    return 0
}

_radius_uninstall_stop() {
    if systemctl is-active --quiet "$RADIUS_UNIT" 2> /dev/null && [[ -f "$RADIUS_DROPIN" ]]; then
        info "Stopping ${RADIUS_UNIT%.service}..."
        systemctl stop "$RADIUS_UNIT" || true
    fi
    if [[ -f "$RADIUS_DROPIN" ]]; then
        systemctl disable --quiet "$RADIUS_UNIT" 2> /dev/null || true
        _radius_dropin_remove
    fi
}

_radius_uninstall_data() {
    local keep=false archive="" f had=0
    [[ "${1:-}" == "--keep-logs" ]] && keep=true
    # Nothing of tacctl's here (an uninstall that takes every backend because
    # tacctl.yaml could not say which are enabled): nothing to do or to say.
    for f in "$RADIUS_LOGROTATE" "$RADIUS_CONF" "$RADIUS_USERS" "$RADIUS_DICT_DIR" "$RADIUS_LOG_DIR"/tacctl-*.log*; do
        [[ -e "$f" ]] && had=1
    done
    (( had )) || return 0
    rm -f "$RADIUS_LOGROTATE" "$RADIUS_CONF" "$RADIUS_USERS" "${RADIUS_CONF}.tacctl-new" "${RADIUS_USERS}.tacctl-new"
    rm -rf "${RADIUS_DICT_DIR:?}"
    local -a logs=()
    for f in "$RADIUS_LOG_DIR"/tacctl-*.log*; do
        [[ -f "$f" ]] && logs+=("${f##*/}")
    done
    if (( ${#logs[@]} )); then
        if [[ "$keep" == "true" ]]; then
            archive="/root/tacctl-radius-logs-$(date +%Y%m%d_%H%M%S).tar.gz"
            tar czf "$archive" -C "$RADIUS_LOG_DIR" "${logs[@]}" 2> /dev/null || true
            info "RADIUS logs saved to ${archive}"
            UNINSTALL_SAVED+=("RADIUS logs saved to: ${archive}")
        fi
        info "Removing tacctl's RADIUS logs from ${RADIUS_LOG_DIR}..."
        for f in "${logs[@]}"; do
            rm -f "${RADIUS_LOG_DIR:?}/${f}"
        done
    fi
    info "FreeRADIUS itself (${RADIUS_PKGS}) is left installed, with the package's configuration in ${RADIUS_DIR} as shipped."
}

# =====================================================================
#  THE BACKEND CONTRACT (lib/backend.sh)
# =====================================================================

backend_radius_describe() {
    printf '%s\n' \
        "protocol=radius" \
        "impl=freeradius" \
        "units=${RADIUS_UNIT}" \
        "user=${RADIUS_USER}" \
        "config_dir=${RADIUS_DIR}" \
        "log_dir=${RADIUS_LOG_DIR}"
}

# The daemon is on this machine and tacctl has set it up: its drop-in is in
# place (enabled), or its rendered config is (disabled; still tacctl's to
# remove on uninstall).
backend_radius_installed() {
    [[ -x "$RADIUS_BIN" ]] && [[ -f "$RADIUS_DROPIN" || -f "$RADIUS_CONF" ]]
}

backend_radius_install() {
    case "${1:-}" in
        build)   _radius_install_build ;;
        files)   _radius_install_files ;;
        account) _radius_install_account ;;
        start)   _radius_install_start ;;
    esac
}

backend_radius_upgrade() {
    case "${1:-}" in
        config) _radius_upgrade_config ;;
        files)  _radius_upgrade_files ;;
        finish) _radius_upgrade_finish ;;
    esac
}

backend_radius_uninstall() {
    local phase="${1:-}"
    shift || true
    case "$phase" in
        stop) _radius_uninstall_stop ;;
        data) _radius_uninstall_data "$@" ;;
    esac
}

backend_radius_artifacts() {
    printf '%s\n' "$RADIUS_CONF" "$RADIUS_USERS" "$RADIUS_DICT"
}

backend_radius_render_check() {
    ( _radius_render_check_run )
}

backend_radius_render_gate() {
    _radius_render_gate
}

backend_radius_render_stage() {
    local dir="${1:-}" overwrite=0
    case "${2:-}" in
        "")      ;;
        --force) overwrite=1 ;;
        *)
            error "Usage: backend_radius_render_stage <dir> [--force]"
            return 1
            ;;
    esac
    _radius_render_stage "$dir" "$overwrite"
}

backend_radius_render_commit() {
    _radius_render_commit "${1:-}"
}

backend_radius_render_notes() {
    local kind text
    while IFS='|' read -r kind text; do
        case "$kind" in
            commands)
                warn "RADIUS does not enforce the command rules (commands.<group>) of: ${text}. Over RADIUS their users are limited only by the group's privilege level (Cisco), login class (Juniper) or access level (WTI), where the scope sends it."
                ;;
            secret)
                warn "The secret of scope ${text} is longer than ${RADIUS_SECRET_MAX_LEN} characters or has a space or a non-ASCII character: FreeRADIUS takes it, some RADIUS clients do not."
                ;;
        esac
    done < <(_radius_notes)
    # The scopes whose network devices would get Service-Type alone (the same
    # test as 'config validate'; Linux-host scopes need nothing).
    local gaps
    gaps=$(model_vendor_gaps 2> /dev/null | paste -sd, || true)
    if [[ -n "$gaps" ]]; then
        warn "Over RADIUS no vendor attribute is sent to the devices of scope(s) ${gaps//,/, }: an Access-Accept carries Service-Type only. Enable what they need: tacctl scope vendor-attrs <scope> enable cisco|juniper|wti"
    fi
    return 0
}

# One daemon serves every listener, so a listener argument changes nothing.
# 'reload' restarts: FreeRADIUS reads its clients only at start.
backend_radius_service() {
    case "${1:-}" in
        restart|reload)
            if _radius_unit_restart; then
                info "Service restarted (${RADIUS_UNIT%.service})."
            else
                warn "Service restart failed — run: sudo systemctl restart ${RADIUS_UNIT%.service}"
            fi
            ;;
        start)     systemctl start "$RADIUS_UNIT" ;;
        stop)
            # Without the drop-in the unit is not running tacctl's instance:
            # whatever it does is not tacctl's to stop.
            [[ -f "$RADIUS_DROPIN" ]] || return 0
            systemctl stop "$RADIUS_UNIT"
            ;;
        enable)
            _radius_unit_free || return 1
            _radius_dropin_install || { error "Could not write ${RADIUS_DROPIN}."; return 1; }
            systemctl enable --quiet "$RADIUS_UNIT"
            ;;
        disable)
            local rc=0
            [[ -f "$RADIUS_DROPIN" ]] || return 0
            systemctl disable --quiet "$RADIUS_UNIT" || rc=1
            _radius_dropin_remove || rc=1
            return "$rc"
            ;;
        is-active) systemctl is-active "$RADIUS_UNIT" 2> /dev/null ;;
        since)     systemctl show "$RADIUS_UNIT" --property=ActiveEnterTimestamp 2> /dev/null | cut -d= -f2 ;;
        pid)       systemctl show "$RADIUS_UNIT" --property=MainPID 2> /dev/null | cut -d= -f2 ;;
        *)
            error "Usage: backend_radius_service <start|stop|restart|reload|enable|disable|is-active|since|pid> [<listener>]"
            return 2
            ;;
    esac
}

# listeners list                      '<name> <network> <address>' per listener, auth and acct first
# listeners show [<name>]             one listener, or all of them
# listeners set <name> <net> <addr>   create or change it; re-renders and restarts
# listeners reset <name>              auth and acct go back to their default; any other is removed
backend_radius_listeners() {
    case "${1:-}" in
        list)  _radius_listener_lines ;;
        show)  _radius_listener_show "${2:-default}" ;;
        set)   _radius_listener_set "${2:-default}" "${3:-}" "${4:-}" ;;
        reset) _radius_listener_reset "${2:-default}" ;;
        *)
            error "Usage: backend_radius_listeners <list|show [<name>]|set <name> <network> <address>|reset <name>>"
            return 2
            ;;
    esac
}

backend_radius_status() {
    case "${1:-}" in
        service)    _radius_status_service ;;
        config)     _radius_status_config ;;
        accounting) _radius_status_accounting ;;
        activity)   _radius_status_activity ;;
        summary)    _radius_status_summary ;;
        *)          return 2 ;;
    esac
}

backend_radius_log() {
    local subcmd="${1:-}"
    shift || true
    case "$subcmd" in
        tail)
            local count="${1:-20}"
            echo ""
            echo -e "${BOLD}Recent RADIUS Authentications${NC} (${RADIUS_AUTH_LOG})"
            echo "--------------------------------------------"
            if [[ -s "$RADIUS_AUTH_LOG" ]]; then
                tail -n "$count" "$RADIUS_AUTH_LOG"
            else
                echo "  No log entries found."
            fi
            if [[ -s "$RADIUS_DAEMON_LOG" ]]; then
                echo ""
                echo -e "${BOLD}FreeRADIUS Daemon Log${NC} (${RADIUS_DAEMON_LOG})"
                echo "--------------------------------------------"
                tail -n "$count" "$RADIUS_DAEMON_LOG"
            fi
            echo ""
            ;;
        search)
            local term="${1:-}"
            if [[ -z "$term" ]]; then
                error "Usage: tacctl log search <username>"
                exit 1
            fi
            echo ""
            echo -e "${BOLD}RADIUS log entries matching '${term}'${NC}"
            echo "--------------------------------------------"
            local f found=0
            for f in "$RADIUS_AUTH_LOG" "$RADIUS_DAEMON_LOG"; do
                [[ -r "$f" ]] || continue
                if grep -i -e "$term" "$f"; then
                    found=1
                fi
            done
            (( found )) || echo "  No matches found."
            echo ""
            ;;
        failures)
            echo ""
            echo -e "${BOLD}RADIUS Authentication Failures (last 24 hours)${NC}"
            echo "--------------------------------------------"
            local failures
            failures=$(_radius_auth_recent | grep ' Access-Reject ' || true)
            if [[ -n "$failures" ]]; then
                echo "$failures"
            else
                echo -e "  ${GREEN}No failures in the last 24 hours${NC}"
            fi
            echo ""
            ;;
        clear)
            _radius_log_clear "$@"
            ;;
        *)
            return 2
            ;;
    esac
}

# The last <n> records of the detail file (a record is a paragraph).
backend_radius_accounting() {
    local subcmd="${1:-}"
    shift || true
    case "$subcmd" in
        tail)
            local count="${1:-20}"
            echo ""
            echo -e "${BOLD}Recent RADIUS Accounting Records${NC}"
            echo "--------------------------------------------"
            if [[ -f "$RADIUS_ACCT_LOG" ]]; then
                awk -v n="$count" 'BEGIN { RS = ""; ORS = "\n\n" } { rec[NR] = $0 }
                    END { for (i = (NR > n ? NR - n + 1 : 1); i <= NR; i++) print rec[i] }' "$RADIUS_ACCT_LOG"
            else
                echo "  No accounting log found at ${RADIUS_ACCT_LOG}"
            fi
            echo ""
            ;;
        *)
            return 2
            ;;
    esac
}

backend_radius_last_login() {
    _radius_last_login "$@"
}

# Advice for interoperability, not what FreeRADIUS itself takes (any string
# up to 8k): the shortest limit among the RADIUS clients we found a figure
# for, and no space or non-ASCII character. The renderer refuses only what
# it cannot write (see fr_secret); render_notes warns beyond the advice.
backend_radius_secret_constraints() {
    printf '%s\n' "max_len=${RADIUS_SECRET_MAX_LEN}" "charset=${RADIUS_SECRET_CHARSET}"
}

# device_vars <vendor> <scope>: what a RADIUS device template needs from the
# daemon. The vendor changes nothing here.
backend_radius_device_vars() {
    local scope="${2:-}" name net addr secret
    while read -r name net addr; do
        case "$name" in
            auth) echo "AUTH_PORT=${addr##*:}" ;;
            acct) echo "ACCT_PORT=${addr##*:}" ;;
        esac
    done < <(_radius_listener_lines)
    if [[ -n "$scope" ]] && secret=$(model_scope "$scope" secret 2> /dev/null); then
        echo "SECRET=${secret}"
    fi
    return 0
}
