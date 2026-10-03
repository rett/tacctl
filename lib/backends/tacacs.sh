# shellcheck shell=bash
# shellcheck disable=SC2034  # constants assigned here are read by the other lib files
# shellcheck disable=SC2164  # errexit is set by bin/tacctl.sh before this file is sourced
# tacctl lib/backends/tacacs.sh -- the TACACS+ backend (tacquito): renderer (model + tacctl.yaml -> tacquito.yaml), daemon load-smoke, units, listeners and their rendered systemd drop-ins, status and log sections, build/install/upgrade/uninstall steps, and legacy (pre-store) mode: migrations, the import gate, 'store rollback'
# Sourced by bin/tacctl.sh after lib/backend.sh (see the load block there for ordering); not executable.
#
# Everything tacctl knows about tacquito lives here, in three layers:
#
#   1. The code itself, under the names it has always had
#      (render_tacacs_config, tacacs_render_apply, tacacs_load_smoke,
#      cmd_config_loglevel, apply_tacquito_patches, ...).
#   2. The backend contract (lib/backend.sh): the backend_tacacs_* functions
#      at the end of this file, which is how generic code reaches layer 1.
#   3. Legacy mode. An install from before the store keeps a tacquito.yaml
#      that is its own source of truth until 'tacctl upgrade' moves it into
#      the store through a gate. Only a TACACS+ install can be in that
#      state, so the gate (upgrade_store_flip), 'tacctl store rollback',
#      the in-place migrations and the old-style restore are this module's,
#      and are called by name where generic code branches on model_mode.
#
# tacquito.yaml is an ARTIFACT: everything in it is derived from the model
# (lib/model.sh) and the merged tacctl.yaml view (lib/conf.sh). So is the
# systemd drop-in of each listener's unit (see "Units, listeners and their
# systemd drop-ins"), derived from tacctl.yaml alone.
#
#   render_tacacs_config <model.json> <out>   pure: model -> file, nothing else
#   tacacs_render_apply [--force]             the live config: drift gate,
#                                             render, install, record
#   tacacs_load_smoke <file>                  can the real daemon load it?
#
# The rendered file holds shared secrets and password hashes. The model
# reaches python as a 0600 file, never on argv.

BACKEND_IDS+=(tacacs)

# --- Daemon paths and build constants ---
# The unit of the default listener, and the name operators and tacctl use for
# the service as a whole. Other listeners are instances of tacquito@.service
# (see "Units, listeners and their systemd drop-ins" below).
TACACS_UNIT="tacquito.service"
# The default listener's drop-in directory. TACCTL_OVERRIDE_DIR and
# TACCTL_SYSTEMD_DIR (where unit files and the instances' drop-in
# directories live) are overridable for tests.
OVERRIDE_DIR="${TACCTL_OVERRIDE_DIR:-/etc/systemd/system/tacquito.service.d}"
TACACS_UNIT_DIR="${TACCTL_SYSTEMD_DIR:-$(dirname "$OVERRIDE_DIR")}"
SERVICE_FILE="${TACACS_UNIT_DIR}/tacquito.service"
TEMPLATE_FILE="${TACACS_UNIT_DIR}/tacquito@.service"
# The drop-in tacctl renders into a unit's .d directory, and the hand-managed
# one of installs from before the listener model.
TACACS_DROPIN="tacctl.conf"
OVERRIDE_FILE="${OVERRIDE_DIR}/tacctl-overrides.conf"
# Mirrors of the python constants in _render_tacacs_py and of the
# Environment= defaults in config/backends/tacacs/tacquito.service.
TACACS_LEVEL_DEFAULT=20
TACACS_METRICS_DEFAULT="127.0.0.1:8080"
TACACS_METRICS_SINK="127.0.0.1:0"
# How long a restarted unit must stay up before a settings change counts as
# applied (_tacacs_unit_settled).
TACACS_SETTLE_SECONDS="${TACCTL_SETTLE_SECONDS:-0.5}"
GO_VERSION="1.26.2"
TACQUITO_REPO="https://github.com/facebookincubator/tacquito.git"
# Overridable so tests can point the patch overlay at a scratch checkout.
TACQUITO_SRC="${TACQUITO_SRC:-/opt/tacquito-src}"
TACQUITO_BIN="${TACCTL_BIN}/tacquito"
HASHGEN_BIN="${TACCTL_BIN}/tacquito-hashgen"
GO_BIN="/usr/local/go/bin/go"
# Where a tacctl checkout keeps this backend's shipped files (unit,
# logrotate, the pre-store config template), relative to its root.
TACACS_SHARE="config/backends/tacacs"

# =====================================================================
#  RENDERER
# =====================================================================

# --- Python: renderer and read-back check -----------------------------------
# Appended to _store_py, _model_py, _rendered_py and _listener_py
# (lib/store.sh, lib/model.sh, lib/backend.sh, lib/conf.sh), whose names it
# uses; carries its own command dispatcher.
_render_tacacs_py() {
    cat <<'PY'
import shlex
import shutil

# ---- tacquito.yaml renderer ------------------------------------------------
#
# Emits the layout tacctl has always written (config/backends/tacacs/tacquito.yaml plus what
# 'user add', 'group add', 'scope add' and 'config allow|deny' spliced in):
# type constants, the file accounter, one bcrypt_<user> authenticator anchor
# per user, exec_<group> / junos_exec_<group> service anchors, one group
# anchor per group, the users list, one secrets[] entry per (scope, prefix)
# sorted by specificity, and the prefix filters. Output depends only on the
# inputs -- no timestamps -- so an unchanged model renders byte-identically.

RENDER_HEADER = (
    "# GENERATED by tacctl from /etc/tacctl/store.yaml and tacctl.yaml. Edits here are overwritten.\n"
    "# Use tacctl commands, or 'tacctl store import --replace' to adopt manual edits.\n"
    "#\n"
    "# Tacquito TACACS+ server configuration (Cisco IOS/IOS-XE + Juniper).\n"
)
# The order config/backends/tacacs/tacquito.yaml lists the built-in groups in.
BUILTIN_RENDER_ORDER = ('readonly', 'operator', 'superuser')
# Words PyYAML (YAML 1.1) reads as a boolean or null when left unquoted.
YAML_WORDS = ('y', 'n', 'yes', 'no', 'on', 'off', 'true', 'false', 'null')
# Top-level keys the layout itself uses; a group may not take one of them.
RENDER_TOP_KEYS = set(LEGACY_TOP_KEYS) | set(LEGACY_CONSTANTS) | {'file_accounter'}
RENDER_KEY_PREFIXES = ('exec_', 'junos_exec_', 'bcrypt_', 'group_')
ACTIONS = {'permit': 2, 'deny': 1}


def yq(s):
    """A YAML double-quoted scalar that every YAML parser decodes to exactly s."""
    out = ['"']
    for ch in s:
        o = ord(ch)
        if ch in '"\\':
            out.append('\\' + ch)
        elif 0x20 <= o < 0x7f:
            out.append(ch)
        elif o <= 0xff:
            out.append('\\x%02x' % o)
        elif o <= 0xffff:
            out.append('\\u%04x' % o)
        else:
            out.append('\\U%08x' % o)
    out.append('"')
    return ''.join(out)


def yname(s):
    """A name as a plain scalar, as tacctl always wrote it, unless a parser
    could read that as something other than the string."""
    if re.fullmatch(r'[A-Za-z_][A-Za-z0-9_-]*', s) and s.lower() not in YAML_WORDS:
        return s
    return yq(s)


def group_key(name):
    """Top-level key and anchor of a group: its name, unless that would
    collide with a key the layout owns."""
    if name in RENDER_TOP_KEYS or name.startswith(RENDER_KEY_PREFIXES):
        return 'group_' + name
    return name


def group_order(groups):
    first = [g for g in BUILTIN_RENDER_ORDER if g in groups]
    return first + sorted(g for g in groups if g not in first)


def tacacs_scopes(model):
    """Scopes this backend serves: no protocols filter, or one naming tacacs."""
    return {n: s for n, s in model['scopes'].items()
            if not s.get('protocols') or 'tacacs' in s['protocols']}


def rendered_hash(user):
    """What goes in the file: the real hash, or the marker nothing matches."""
    if user.get('disabled') or user.get('accounting_sink') or not user.get('hash'):
        return DISABLED_MARKER_HEX
    return user['hash']


def group_commands(conf, group):
    """commands.<group> from the merged tacctl.yaml view -> validated rules."""
    rules = (conf.get('commands') or {}).get(group) or []
    if not isinstance(rules, list):
        raise StoreError(f'tacctl.yaml: commands.{group} is not a list of rules')
    out = []
    for r in rules:
        if not isinstance(r, dict) or not isinstance(r.get('name'), str) or not r['name']:
            raise StoreError(f'tacctl.yaml: commands.{group} has a rule without a name')
        action = r.get('action', 'permit')
        if action not in ACTIONS:
            raise StoreError(f"tacctl.yaml: commands.{group}: rule '{r['name']}' has an action that is neither permit nor deny")
        match = r.get('match') or []
        if not isinstance(match, list) or any(not isinstance(m, str) for m in match):
            raise StoreError(f"tacctl.yaml: commands.{group}: rule '{r['name']}' has a match that is not a list of strings")
        out.append({'name': r['name'], 'action': action, 'match': list(match)})
    return out


def render_tacacs(model, conf):
    """Model + merged tacctl.yaml view -> tacquito.yaml text."""
    errs = store_validate(model)
    if errs:
        raise StoreError('cannot render an invalid model:\n  - ' + '\n  - '.join(errs))
    groups, users = model['groups'], model['users']
    scopes = tacacs_scopes(model)
    w = []

    w.append(RENDER_HEADER)
    w.append(
        "\n# --- Type constants ---\n"
        "authenticator_type_bcrypt: &authenticator_type_bcrypt 1\n"
        "action_deny:  &action_deny  1\n"
        "action_permit: &action_permit 2\n"
        "accounter_type_file: &accounter_type_file 3\n"
        "handler_type_start: &handler_type_start 1\n"
        "provider_type_prefix: &provider_type_prefix 1\n"
        "\n# --- Accounting ---\n"
        "file_accounter: &file_accounter\n"
        "  name: tacquito_accounter\n"
        "  type: *accounter_type_file\n"
        "\n# --- Per-user bcrypt authenticators ---\n"
        "# A disabled account and the 'root' accounting sink carry a well-formed\n"
        "# hash that no password matches.\n"
    )
    for name in sorted(users):
        h = rendered_hash(users[name])
        # All-digit hex would read as a number; nothing else needs quotes.
        w.append(
            f"\nbcrypt_{name}: &bcrypt_{name}\n"
            f"  type: *authenticator_type_bcrypt\n"
            f"  options:\n"
            f"    hash: {yq(h) if h.isdigit() else h}\n"
        )

    w.append(
        "\n# --- Services ---\n"
        "# Cisco IOS/IOS-XE sends service=shell for exec authorization and expects\n"
        "# priv-lvl; the anchors keep 'exec' as the label for the tier.\n"
        "# Juniper requests service=junos-exec and expects local-user-name.\n"
        "# Each device type only requests its own service; the other is ignored.\n"
    )
    order = group_order(groups)
    for name in order:
        g = groups[name]
        w.append(
            f"\n# Cisco exec - {name} (priv-lvl {g['priv_lvl']})\n"
            f"exec_{name}: &exec_{name}\n"
            f"  name: shell\n"
            f"  set_values:\n"
            f"    - name: priv-lvl\n"
            f"      values: [{g['priv_lvl']}]\n"
            f"\n# Juniper junos-exec - {name}\n"
            f"# \"{g['juniper_class']}\" must match a local template user on Juniper devices\n"
            f"junos_exec_{name}: &junos_exec_{name}\n"
            f"  name: junos-exec\n"
            f"  set_values:\n"
            f"    - name: local-user-name\n"
            f"      values: [{yq(g['juniper_class'])}]\n"
        )

    w.append("\n# --- Groups ---\n"
             "# Command rules come from commands.<group> in tacctl.yaml.\n")
    for i, name in enumerate(order):
        key = group_key(name)
        w.append(
            f"{'' if i == 0 else chr(10)}{yname(key)}: &{key}\n"
            f"  name: {yname(name)}\n"
            f"  services:\n"
            f"    - *exec_{name}\n"
            f"    - *junos_exec_{name}\n"
        )
        rules = group_commands(conf, name)
        if rules:
            w.append("  commands:\n")
            for r in rules:
                w.append(f"    - name: {yq(r['name'])}\n")
                if r['match']:
                    w.append("      match: [" + ", ".join(yq(m) for m in r['match']) + "]\n")
                w.append(f"      action: *action_{r['action']}\n")
        w.append("  accounter: *file_accounter\n")

    w.append("\n# --- Users ---\n")
    if users:
        w.append("users:\n")
        for name in sorted(users):
            u = users[name]
            mine = [s for s in u['scopes'] if s in scopes]
            w.append(
                f"\n  # {name}\n"
                f"  - name: {yname(name)}\n"
                f"    scopes: [{', '.join(yq(s) for s in mine)}]\n"
                f"    groups: [*{group_key(u['group'])}]\n"
                f"    authenticator: *bcrypt_{name}\n"
                f"    accounter: *file_accounter\n"
            )
    else:
        w.append("users: []\n")

    w.append(
        "\n# --- Secret Providers (Scopes) ---\n"
        "# One entry per (scope, prefix), most specific prefix first: tacquito\n"
        "# answers a client with the first entry whose prefix contains it.\n"
    )
    entries = sorted(((c, n) for n, s in scopes.items() for c in s['prefixes']),
                     key=lambda t: (cidr_key(t[0]), t[1]))
    if entries:
        w.append("secrets:\n")
        for cidr, name in entries:
            w.append(
                f"  - name: {yname(name)}\n"
                f"    secret:\n"
                f"      group: tacquito\n"
                f"      key: {yq(scopes[name]['secret'])}\n"
                f"    handler:\n"
                f"      type: *handler_type_start\n"
                f"    type: *provider_type_prefix\n"
                f"    options:\n"
                f"      prefixes: |\n"
                f"        [\n"
                f"          {json.dumps(cidr)}\n"
                f"        ]\n"
            )
    else:
        w.append("secrets: []\n")

    filters = model.get('filters') or {}
    lines = []
    for store_key, key in (('allow', 'prefix_allow'), ('deny', 'prefix_deny')):
        items = sorted(filters.get(store_key) or [], key=cidr_key)
        if items:
            lines.append(f"{key}: [" + ", ".join(yq(c) for c in items) + "]\n")
    if lines:
        w.append("\n# --- Connection filters ---\n" + "".join(lines))
    return "".join(w)


def readback_problems(path, model):
    """Read a tacquito.yaml with the importer and list where it says
    something other than the model: groups, users (group, scopes, usable
    hash), scopes, filters, or content the store cannot hold. Command rules
    are not compared; they come from tacctl.yaml."""
    back, rep = legacy_load(path)
    problems = [f'importer reports: {m}' for m in rep['errors'] + rep['dropped']]
    scopes = tacacs_scopes(model)

    want_groups = {n: (g['priv_lvl'], g['juniper_class']) for n, g in model['groups'].items()}
    got_groups = {n: (g['priv_lvl'], g['juniper_class']) for n, g in back['groups'].items()}
    if want_groups != got_groups:
        problems.append('groups differ')

    want_users, got_users = {}, {}
    for n, u in model['users'].items():
        h = rendered_hash(u)
        want_users[n] = (u['group'], [s for s in u['scopes'] if s in scopes],
                         None if h == DISABLED_MARKER_HEX else h)
    for n, u in back['users'].items():
        got_users[n] = (u['group'], u['scopes'], None if u['disabled'] else u['hash'])
    if want_users != got_users:
        problems.append('users differ')

    want_scopes = {n: (canonical_cidr_list(list(s['prefixes'])), s['secret']) for n, s in scopes.items()}
    got_scopes = {n: (canonical_cidr_list(list(s['prefixes'])), s['secret']) for n, s in back['scopes'].items()}
    if want_scopes != got_scopes:
        problems.append('scopes differ')

    for k in FILTER_KEYS:
        if canonical_cidr_list(list((model.get('filters') or {}).get(k) or [])) != canonical_cidr_list(back['filters'][k]):
            problems.append(f'filters.{k} differs')

    return problems


def render_readback(path, model, conf):
    """Read a rendered file back with the importer and check it says what
    the model says. Guards every render against a quoting or layout bug:
    a file that fails here is never installed."""
    problems = readback_problems(path, model)
    with open(path) as f:
        doc = yaml.safe_load(f)
    by_name = {v['name']: v for v in doc.values()
               if isinstance(v, dict) and isinstance(v.get('services'), list)}
    for name in model['groups']:
        want = [dict({'name': r['name'], 'action': ACTIONS[r['action']]},
                     **({'match': r['match']} if r['match'] else {}))
                for r in group_commands(conf, name)]
        got = (by_name.get(name) or {}).get('commands') or []
        if want != got:
            problems.append(f"command rules of group '{name}' differ")

    if problems:
        raise StoreError('internal error: the rendered config does not read back as the model ('
                         + '; '.join(problems) + '). Nothing was written.')


def render_to_file(model, conf, out):
    """Render, verify, and move into place (0640, tacquito:tacquito when
    that account exists and we may chown)."""
    text = render_tacacs(model, conf)
    d = os.path.dirname(out) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.tacquito.', suffix='.tmp', dir=d)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), 0o640)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        render_readback(tmp, model, conf)
        with contextlib.suppress(LookupError, OSError):
            shutil.chown(tmp, 'tacquito', 'tacquito')
        os.replace(tmp, out)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise


# ---- systemd drop-ins: one per listener ------------------------------------
#
# A listener of listeners.tacacs in tacctl.yaml is one tacquito process: the
# default one is tacquito.service, every other one an instance of
# tacquito@.service. What differs between them is five flags, which the units
# take from the environment; the drop-in sets them. Like tacquito.yaml it is
# derived from tacctl.yaml alone and rendered byte-identically.

TACACS_LEVEL_DEFAULT = 20
TACACS_METRICS_DEFAULT = '127.0.0.1:8080'
# "No exporter": a loopback port nobody can know. Also what keeps two
# processes from colliding on one metrics port.
TACACS_METRICS_SINK = '127.0.0.1:0'
DROPIN_HEADER = (
    "# GENERATED by tacctl from tacctl.yaml (listeners.tacacs and backends.tacacs). Edits here are overwritten.\n"
    "# Change these with 'tacctl config listen', 'tacctl config loglevel' and 'tacctl config metrics';\n"
    "# unit settings of your own belong in another .conf file of this directory.\n"
)
LEGACY_DROPIN_KEYS = ('TACQUITO_NETWORK', 'TACQUITO_ADDRESS', 'TACQUITO_LEVEL', 'TACQUITO_METRICS_ADDRESS')


def tacacs_units(conf, log_dir):
    """{listener name: drop-in text}, the default listener first. Refuses a
    listener model that cannot be served (invalid entry, two listeners on one
    address, reserved TLS)."""
    problems = listeners_problems(conf)
    if problems:
        raise StoreError('tacctl.yaml: ' + '; '.join(problems))
    backends = conf.get('backends')
    settings = (backends.get('tacacs') if isinstance(backends, dict) else None) or {}
    if not isinstance(settings, dict):
        raise StoreError('tacctl.yaml: backends.tacacs is not a mapping')
    level = settings.get('level', TACACS_LEVEL_DEFAULT)
    if not is_int(level) or not 0 <= level <= 100:
        raise StoreError('tacctl.yaml: backends.tacacs.level is not a log level (10, 20 or 30)')
    metrics = settings.get('metrics_address', TACACS_METRICS_DEFAULT)
    why = host_port_problem(metrics)
    if why:
        raise StoreError(f'tacctl.yaml: backends.tacacs.metrics_address {why}')
    out = {}
    for name, l in listeners_effective(conf, 'tacacs').items():
        if name == 'default':
            mine, log = metrics, 'accounting.log'
        else:
            mine, log = l['metrics_address'] or TACACS_METRICS_SINK, f'accounting-{name}.log'
            if mine == metrics and not mine.endswith(':0'):
                raise StoreError(f'tacctl.yaml: listeners.tacacs.{name}: metrics_address {mine} is the default listener\'s (backends.tacacs.metrics_address)')
        env = (('TACQUITO_NETWORK', l['network']), ('TACQUITO_ADDRESS', l['address']),
               ('TACQUITO_LEVEL', level), ('TACQUITO_METRICS_ADDRESS', mine),
               ('TACQUITO_ACCT_LOG', os.path.join(log_dir, log)))
        # '%' starts a specifier in a unit file.
        out[name] = DROPIN_HEADER + '[Service]\n' + ''.join(
            'Environment="%s=%s"\n' % (k, str(v).replace('%', '%%')) for k, v in env)
    return out


def render_units(conf, out_dir, log_dir, json_path, default_dropin, unit_dir):
    """Write every listener's drop-in to <out_dir>/<name>.conf and an index,
    one '<name>\t<status>\t<live path>' line each; the status is the live
    drop-in's against the render, in the words of render-live."""
    units = tacacs_units(conf, log_dir)
    try:
        records = rendered_load(json_path)
    except StoreError:
        records = None
    os.makedirs(out_dir, exist_ok=True)
    index = []
    for name, text in units.items():
        live = default_dropin if name == 'default' else os.path.join(
            unit_dir, f'tacquito@{name}.service.d', os.path.basename(default_dropin))
        live = os.path.abspath(live)
        with open(os.path.join(out_dir, name + '.conf'), 'w') as f:
            f.write(text)
        same = False
        if os.path.exists(live):
            with open(live, 'rb') as f:
                same = f.read() == text.encode()
        if records is None:
            status = 'same' if same else 'unreadable'
        else:
            status = rendered_status(records, live)
            if same:
                status = 'current' if status == 'ok' else 'same'
        index.append(f'{name}\t{status}\t{live}\n')
    with open(os.path.join(out_dir, 'index'), 'w') as f:
        f.write(''.join(index))


def legacy_dropin_values(path):
    """The settings of a hand-managed tacctl-overrides.conf (the drop-in of
    installs from before the listener model), as {TACQUITO_*: value}. Any
    line that is not one of them is refused, by line: converting would drop
    it, or change which of two drop-ins wins."""
    values, foreign = {}, []
    with open(path) as f:
        lines = f.read().splitlines()
    for n, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line[0] in '#;' or line == '[Service]':
            continue
        ours = False
        if line.startswith('Environment='):
            try:
                items = shlex.split(line[len('Environment='):])
            except ValueError:
                items = []
            pairs = [item.partition('=') for item in items]
            ours = bool(pairs) and all(sep and k in LEGACY_DROPIN_KEYS for k, sep, _v in pairs)
            if ours:
                values.update((k, v) for k, _sep, v in pairs)
        if not ours:
            foreign.append(f'  line {n}: {line}')
    if foreign:
        raise StoreError(
            f'{path} holds lines tacctl did not write and cannot carry over:\n' + '\n'.join(foreign)
            + '\nMove them to a drop-in of your own in that directory (another .conf file) and run this again.')
    return values


def load_conf_view(overrides_path):
    """The merged tacctl.yaml view arrives on stdin. A tacctl.yaml that does
    not parse would silently fall back to shipped defaults there, and with
    it to the default command rules -- refuse instead."""
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


def render_main(argv):
    cmd, rest = argv[0], argv[1:]

    if cmd == 'render':
        # render <model.json> <out> <tacctl.yaml path>; merged view on stdin
        with open(rest[0]) as f:
            model = json.load(f)
        render_to_file(model, load_conf_view(rest[2]), rest[1])

    elif cmd == 'render-live':
        # render-live <store.yaml> <out> <tacctl.yaml path> <rendered.json> <live config>
        #             [<units dir> <log dir> <default drop-in> <unit dir>]
        # (merged view on stdin). With the last four it also renders the
        # listeners' drop-ins (render_units). Renders the store to <out> and prints how
        # the live config stands against it, in one interpreter run:
        #   current     identical to the render, and recorded as such
        #   same        identical to the render, but not (or wrongly) recorded
        #   ok          differs; it is what tacctl last rendered
        #   drift       differs; edited since tacctl rendered it
        #   unrecorded  differs; tacctl never rendered it
        #   missing     there is no live config
        #   unreadable  differs, and the render records cannot be read
        model = store_normalize(store_load_raw(rest[0]))
        conf = load_conf_view(rest[2])
        render_to_file(model, conf, rest[1])
        if len(rest) > 5:
            render_units(conf, rest[5], rest[6], rest[3], rest[7], rest[8])
        live = os.path.abspath(rest[4])
        try:
            status = rendered_status(rendered_load(rest[3]), live)
        except StoreError:
            status = 'unreadable'
        same = False
        if os.path.exists(live):
            with open(rest[1], 'rb') as a, open(live, 'rb') as b:
                same = a.read() == b.read()
        if same:
            print('current' if status == 'ok' else 'same')
        else:
            print(status)

    elif cmd == 'render-units':
        # render-units <units dir> <tacctl.yaml path> <rendered.json> <log dir>
        #              <default drop-in> <unit dir>; merged view on stdin.
        # The drop-ins alone: needs no store.
        render_units(load_conf_view(rest[1]), rest[0], rest[3], rest[2], rest[4], rest[5])

    elif cmd == 'legacy-dropin':
        # legacy-dropin <tacctl-overrides.conf>: its settings, KEY=VALUE lines.
        for k, v in legacy_dropin_values(rest[0]).items():
            print(f'{k}={v}')

    elif cmd == 'matches-model':
        # matches-model <tacquito.yaml>; model on stdin. Exit 0 when the
        # file says exactly what the model says (see readback_problems).
        return 1 if readback_problems(rest[0], json.load(sys.stdin)) else 0

    else:
        raise StoreError(f'internal: unknown command {cmd!r}')
    return 0


if __name__ == '__main__':
    try:
        sys.exit(render_main(sys.argv[1:]))
    except StoreError as e:
        print(f'tacctl render: {e}', file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f'tacctl render: {e.filename or "I/O"}: {e.strerror}', file=sys.stderr)
        sys.exit(1)
PY
}

# Run the render program: _render_python <command> [args...].
_render_python() {
    python3 <(_store_py; _model_py; _rendered_py; _listener_py; _render_tacacs_py) "$@"
}

# --- Renderer ---------------------------------------------------------------

# render_tacacs_config <model.json> <out>
# Render a complete tacquito.yaml from a model (as model_dump prints it) and
# the merged tacctl.yaml view (command rules), and move it into place at
# <out> (0640; tacquito:tacquito when possible). Before the move the file is
# read back through the importer and compared with the model; on any
# mismatch nothing is written. Pure with respect to tacctl state: no drift
# check, no rendered.json, no restart -- see tacacs_render_apply for those.
# Returns 0 rendered, 1 failed (message on stderr).
render_tacacs_config() {
    local model="${1:-}" out="${2:-}"
    if [[ -z "$model" || -z "$out" ]]; then
        error "Usage: render_tacacs_config <model.json> <out>"
        return 1
    fi
    _conf_load_cache
    _render_python render "$model" "$out" "${TACCTL_OVERRIDES_FILE:-}" \
        < <(printf '%s' "$_TACCTL_CFG_CACHE") || return 1
}

# --- Applying a render to the live config -----------------------------------

# tacacs_render_apply [--force]
# Render the current model into $CONFIG.
#   stdout  CHANGED or UNCHANGED (nothing else; messages go to stderr)
#   return  0 done; 1 failed; 3 refused because the file on disk is not what
#           tacctl rendered (hand edit, or never rendered by tacctl) and the
#           new render would replace it.
# --force overwrites such a file after copying it to backups/legacy/.
# A file whose content already equals the new render is never a conflict.
# Requires the store: in legacy mode tacquito.yaml is still the source of
# truth and is not regenerated.
tacacs_render_apply() {
    local force=0
    case "${1:-}" in
        "")      ;;
        --force) force=1 ;;
        *)
            error "Usage: tacacs_render_apply [--force]"
            return 1
            ;;
    esac
    if [[ ! -f "$STORE_FILE" ]]; then
        error "$STORE_NOT_INITIALISED_MSG"
        return 1
    fi
    # Subshell: scopes the temp dir (it holds the model and the candidate,
    # secrets included) and its cleanup trap.
    ( _tacacs_render_apply_run "$force" )
}

# The two halves of tacacs_render_apply, which are also the contract's
# render_stage and render_commit: generic code stages every backend before
# it commits any (lib/backend.sh).

# _tacacs_render_stage <dir> <force 0|1> [units]: render the store into
# <dir>/tacquito.yaml, note in <dir>/status how $CONFIG stands against it,
# and refuse (3) when replacing $CONFIG would discard something and force
# is not set. With 'units' the listeners' drop-ins are staged in <dir>/units
# by the same run (for _tacacs_units_commit); they never refuse. Touches
# nothing outside <dir>.
_tacacs_render_stage() {
    local dir="$1" force="$2" status
    local -a units=()
    [[ "${3:-}" == "units" ]] && units=("${dir}/units")

    # One interpreter run renders the store and reports how the live file
    # stands against the render (see render-live above).
    status=$(_tacacs_render_live "${dir}/tacquito.yaml" ${units[@]+"${units[@]}"}) || return 1

    case "$status" in
        current|same|ok|missing) ;;
        drift|unrecorded)
            if (( ! force )); then
                if [[ "$status" == "drift" ]]; then
                    error "${CONFIG} was edited since tacctl rendered it; rendering would discard those edits."
                else
                    error "${CONFIG} was not rendered by tacctl; rendering would replace it."
                fi
                error "To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'."
                error "To discard it: 'tacctl config render --force' alone. Either way the current file is saved under ${BACKUP_DIR}/legacy/ first."
                return 3
            fi
            ;;
        *)
            error "Cannot read ${RENDERED_FILE}; refusing to overwrite ${CONFIG}."
            return 1
            ;;
    esac
    printf '%s\n' "$status" > "${dir}/status" || return 1
}

# _tacacs_render_commit <dir>: install what _tacacs_render_stage left in
# <dir>. Prints CHANGED or UNCHANGED.
_tacacs_render_commit() {
    local dir="$1" status
    status=$(< "${dir}/status") || return 1

    case "$status" in
        current)
            echo "UNCHANGED"
            return 0
            ;;
        same)
            rendered_record "$CONFIG" || return 1
            echo "UNCHANGED"
            return 0
            ;;
        drift|unrecorded)
            _tacacs_save_displaced "$CONFIG" || return 1
            ;;
    esac

    # Same directory as the target, so the final step is a rename.
    local staged="${CONFIG}.tacctl-new"
    cp "${dir}/tacquito.yaml" "$staged" || return 1
    chmod 640 "$staged"
    chown tacquito:tacquito "$staged" 2>/dev/null || true
    mv -f "$staged" "$CONFIG" || { rm -f "$staged"; return 1; }
    rendered_record "$CONFIG" || return 1
    echo "CHANGED"
    return 0
}

_tacacs_render_apply_run() {
    local force="$1" tmpd
    tmpd=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064  # expand tmpd now; the subshell owns this trap
    trap "rm -rf '${tmpd}'" EXIT

    _tacacs_render_stage "$tmpd" "$force" || exit $?
    _tacacs_render_commit "$tmpd" || exit 1
    exit 0
}

# The gate of store_apply's step 1 (the contract's render_gate). Returns 0
# go ahead; 10 go ahead and adopt the never-rendered file (render with
# --force); 3 refused; 1 failed.
_tacacs_render_gate() {
    local rc=0
    rendered_check "$CONFIG" >/dev/null || rc=$?
    case "$rc" in
        0|2) return 0 ;;
        1)
            error "${CONFIG} was edited since tacctl rendered it; this command would discard those edits."
            ;;
        3)
            if _tacacs_matches_store "$CONFIG"; then
                return 10
            fi
            error "${CONFIG} was not rendered by tacctl and does not say what the store says; this command would replace it."
            ;;
        *)
            error "Cannot read ${RENDERED_FILE}; refusing to overwrite ${CONFIG}."
            return 1
            ;;
    esac
    error "Nothing was changed. To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'."
    error "To discard it: 'tacctl config render --force' alone. Then run this command again."
    return 3
}

# _tacacs_matches_store <tacquito.yaml>: 0 when the file, read with the
# importer, holds the groups, users, scopes and filters of the current store
# and nothing the store cannot represent.
_tacacs_matches_store() {
    model_load 2>/dev/null || return 1
    _render_python matches-model "$1" < <(printf '%s' "$_TACCTL_MODEL_CACHE") 2>/dev/null
}

# tacacs_render_check: trial render of the current store, nothing installed.
# Prints the state of the live config against it (one word; see render-live).
# Returns 1 (message on stderr) when the store cannot be rendered.
tacacs_render_check() {
    ( _tacacs_render_check_run )
}

# With 'units' the word covers the listeners' drop-ins too: the artifact
# furthest from the render decides.
_tacacs_render_check_run() {
    local tmpd status word s _name _live
    local -a states=()
    tmpd=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064  # expand tmpd now; the subshell owns this trap
    trap "rm -rf '${tmpd}'" EXIT
    if [[ "${1:-}" != "units" ]]; then
        _tacacs_render_live "${tmpd}/tacquito.yaml" || exit 1
        exit 0
    fi
    status=$(_tacacs_render_live "${tmpd}/tacquito.yaml" "${tmpd}/units") || exit 1
    states=("$status")
    while IFS=$'\t' read -r _name s _live; do
        [[ -n "$s" ]] && states+=("$s")
    done < "${tmpd}/units/index"
    for word in unreadable drift unrecorded missing ok same current; do
        for s in "${states[@]}"; do
            if [[ "$s" == "$word" ]]; then
                echo "$word"
                exit 0
            fi
        done
    done
    exit 1
}

# _tacacs_render_live <out> [<units dir>]: render the current store into
# <out> and print the state of $CONFIG against that render (one word; see
# render-live). With <units dir> the listeners' drop-ins are rendered there
# too (render_units). Returns 1, message on stderr, when the store or the
# listener model cannot be rendered.
_tacacs_render_live() {
    local -a units=()
    if [[ -n "${2:-}" ]]; then
        units=("$2" "$LOG_DIR" "$(_tacacs_dropin default)" "$TACACS_UNIT_DIR")
    fi
    _conf_load_cache
    _render_python render-live "$STORE_FILE" "$1" "${TACCTL_OVERRIDES_FILE:-}" "$RENDERED_FILE" "$CONFIG" \
        ${units[@]+"${units[@]}"} < <(printf '%s' "$_TACCTL_CFG_CACHE")
}

# Copy a file that is about to be overwritten into backups/legacy/. A file
# the import already kept as the pre-store config is not copied twice.
_tacacs_save_displaced() {
    local src="$1" dir="${BACKUP_DIR}/legacy" dest
    if dest=$(store_pre_store_latest) && cmp -s "$src" "$dest"; then
        info "Previous ${src} is already kept as ${dest}" >&2
        return 0
    fi
    mkdir -p "$dir" || return 1
    chmod 700 "$dir"
    dest="${dir}/$(basename "$src").drift.$(date +%Y%m%d_%H%M%S_%3N)"
    cp "$src" "$dest" || return 1
    chmod 600 "$dest"
    warn "Previous ${src} saved to ${dest}" >&2
}

# --- Daemon load-smoke (plan 4.3 step 4) ------------------------------------

# tacacs_load_smoke <rendered-file>
# Start the real tacquito on a copy of the file and see whether it loads it.
# Returns 0 loaded and serving; 2 skipped (no daemon binary); 1 failed.
#
# Isolation: every flag that names a resource is set explicitly, so nothing
# falls back to a production default -- the listener and the metrics
# exporter bind 127.0.0.1 on a kernel-chosen port (never :49), the
# accounting log and the config live in a private temp dir. The daemon is
# run under 'timeout' (so it dies even if tacctl is killed), is killed as
# soon as the verdict is known, and the temp dir is removed on exit.
TACACS_SMOKE_SECONDS=5

tacacs_load_smoke() {
    local rendered="${1:-}"
    [[ -x "$TACQUITO_BIN" ]] || return 2
    command -v timeout >/dev/null 2>&1 || return 2
    if [[ ! -f "$rendered" ]]; then
        error "Load-smoke: ${rendered} not found."
        return 1
    fi
    ( _tacacs_load_smoke_run "$rendered" )
}

_tacacs_load_smoke_run() {
    local rendered="$1" tmpd i verdict=1
    _TACACS_SMOKE_PID=""
    tmpd=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064  # expand tmpd now; the pid is read when the trap fires
    trap "_tacacs_smoke_stop; rm -rf '${tmpd}'" EXIT

    # tacquito watches the config's DIRECTORY and logs every event in it, so
    # the config gets a directory of its own, apart from the logs.
    mkdir "${tmpd}/conf" "${tmpd}/run" || exit 1
    cp "$rendered" "${tmpd}/conf/tacquito.yaml" || exit 1

    timeout -k 1 "$(( TACACS_SMOKE_SECONDS + 1 ))" "$TACQUITO_BIN" \
        -config "${tmpd}/conf/tacquito.yaml" \
        -network tcp -address 127.0.0.1:0 \
        -acct-log-path "${tmpd}/run/accounting.log" \
        -metrics-address 127.0.0.1:0 \
        -level 20 >/dev/null 2>"${tmpd}/run/stderr.log" &
    _TACACS_SMOKE_PID=$!

    # Loaded = the listener is up AND the loader built its providers from
    # the file. A config the loader rejects logs 'error fetching config' and
    # the process exits (with status 0, so the log is what counts).
    for (( i = 0; i < TACACS_SMOKE_SECONDS * 10; i++ )); do
        if grep -q 'serve on ' "${tmpd}/run/stderr.log" 2>/dev/null \
            && grep -q 'updated all providers from config source' "${tmpd}/run/stderr.log" 2>/dev/null; then
            verdict=0
            break
        fi
        kill -0 "$_TACACS_SMOKE_PID" 2>/dev/null || break
        sleep 0.1
    done

    if (( verdict != 0 )); then
        # Name the cause without echoing the daemon's log: a YAML error can
        # quote a line of the config.
        if grep -q 'no users were unmarshalled' "${tmpd}/run/stderr.log" 2>/dev/null; then
            error "Load-smoke: tacquito refuses a config with no users."
        elif grep -q 'no secret providers were unmarshalled' "${tmpd}/run/stderr.log" 2>/dev/null; then
            error "Load-smoke: tacquito refuses a config with no scopes."
        elif grep -q 'error fetching config' "${tmpd}/run/stderr.log" 2>/dev/null; then
            error "Load-smoke: tacquito could not parse the config."
        else
            error "Load-smoke: tacquito did not start serving within ${TACACS_SMOKE_SECONDS}s."
        fi
    fi
    exit "$verdict"
}

_tacacs_smoke_stop() {
    [[ -n "${_TACACS_SMOKE_PID:-}" ]] || return 0
    kill "$_TACACS_SMOKE_PID" 2>/dev/null || true
    wait "$_TACACS_SMOKE_PID" 2>/dev/null || true
    _TACACS_SMOKE_PID=""
}

# =====================================================================
#  SERVICE, LISTENERS AND SYSTEMD DROP-INS
# =====================================================================

# Most recent login timestamp for a user, or "never". Parses the accounting
# log for JSON lines that pair "User":"<name>" with cmd=login (Flags:2 START).
# Session stops (cmd=logout / cmd=exit on Flags:4) are excluded.
# Every listener has an accounting log of its own; the newest login wins.
_tacacs_last_login() {
    local username="$1" log ts best=""
    for log in "$ACCT_LOG" "$LOG_DIR"/accounting-*.log; do
        [[ -r "$log" ]] || continue
        ts=$(grep -F "\"User\":\"${username}\"" "$log" 2>/dev/null \
            | grep -F 'cmd=login' \
            | tail -1 \
            | grep -oE '[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}' \
            | head -1) || ts=""
        if [[ -n "$ts" && ( -z "$best" || "$ts" > "$best" ) ]]; then
            best="$ts"
        fi
    done
    if [[ -z "$best" ]]; then
        echo "never"
    else
        echo "${best//\//-}"
    fi
}

# --- Units, listeners and their systemd drop-ins ---
#
# One tacquito process serves one listener, so a listener of
# listeners.tacacs in tacctl.yaml (lib/conf.sh: _listener_py) is one systemd
# unit:
#
#   default           tacquito.service, the unit it has always been
#   any other <name>  tacquito@<name>.service, an instance of the template
#                     unit tacquito@.service
#
# The default listener is deliberately not 'tacquito@default'. systemd has no
# way to make 'tacquito.service' a name of a template instance: an Alias= in
# the template's [Install] section is refused when the instance is enabled
# ("cannot alias"), and a symlink tacquito.service -> tacquito@default.service
# is rejected when units are loaded ("symlink target name type does not match
# source"); a plain unit may only be aliased by a plain name (systemd.unit(5),
# checked with systemd 255). A wrapper unit of that name would answer
# 'systemctl is-active tacquito' for itself, not for the daemon, and
# 'journalctl -u tacquito' matches on the unit a process runs in, so it would
# show nothing of the daemon. Keeping the default listener in tacquito.service
# keeps every one of those exactly as it was. The instances are PartOf= and
# WantedBy= tacquito.service: stop, restart, start, enable and disable of
# 'tacquito' act on all listeners.
#
# The flags that differ per listener (-network, -address, -level,
# -metrics-address, -acct-log-path) reach a unit as TACQUITO_* environment
# variables from a drop-in, <unit>.d/tacctl.conf. The drop-in is an ARTIFACT
# like tacquito.yaml: rendered from tacctl.yaml (listeners.tacacs.<name>,
# backends.tacacs.level, backends.tacacs.metrics_address), staged and
# committed with it (backend_tacacs_render_stage/_commit), recorded in
# rendered.json. Unlike tacquito.yaml it holds nothing tacctl.yaml does not,
# so a hand edit never refuses a command: the next render replaces it and
# keeps a copy under backups/legacy/.
#
# Changing a listener, the log level or the metrics address
# (_tacacs_settings_apply) does not go through store_apply: it renders no
# tacquito.yaml, so it needs no store and works on an install still in
# legacy mode, as these commands always did; and it proves the change by
# restarting the unit and puts everything back when the unit does not come up,
# which store_apply does not do. It snapshots first when there is a store.
#
# Installs from before the listener model kept these settings in a
# hand-managed drop-in, tacquito.service.d/tacctl-overrides.conf, which was
# also their source of truth. While that file exists the install is "not
# converted": its values are what is in effect and what is shown, and tacctl
# renders no drop-in beside it. 'tacctl upgrade' converts
# (_tacacs_units_install), and so does the first settings change.

# Read one Environment= value of the hand-managed drop-in of an install that
# is not converted; echo empty if not set.
# `|| true` absorbs grep's exit-1-on-no-match so `pipefail + set -e`
# callers don't abort when the override file doesn't exist / is empty.
read_service_override() {
    local key="$1"
    { grep -oP "^Environment=\"${key}=\K[^\"]*" "$OVERRIDE_FILE" 2>/dev/null || true; } | tail -1
}

# True while the hand-managed drop-in is still there.
_tacacs_units_legacy() {
    [[ -f "$OVERRIDE_FILE" ]]
}

# _tacacs_unit <listener>: the systemd unit that serves it.
_tacacs_unit() {
    if [[ "${1:-default}" == "default" ]]; then
        echo "$TACACS_UNIT"
    else
        echo "tacquito@${1}.service"
    fi
}

# _tacacs_dropin <listener>: the drop-in tacctl renders for it.
_tacacs_dropin() {
    if [[ "${1:-default}" == "default" ]]; then
        echo "${OVERRIDE_DIR}/${TACACS_DROPIN}"
    else
        echo "${TACACS_UNIT_DIR}/tacquito@${1}.service.d/${TACACS_DROPIN}"
    fi
}

# _tacacs_acct_log <listener>: its accounting log.
_tacacs_acct_log() {
    if [[ "${1:-default}" == "default" ]]; then
        echo "$ACCT_LOG"
    else
        echo "${LOG_DIR}/accounting-${1}.log"
    fi
}

# The listeners in effect, one '<name> <network> <address>' line each, the
# default listener first. Most installs have the default listener on its
# default address, which costs no read of tacctl.yaml.
_tacacs_listener_lines() {
    if _tacacs_units_legacy; then
        local net addr
        net=$(read_service_override TACQUITO_NETWORK)
        addr=$(read_service_override TACQUITO_ADDRESS)
        echo "default ${net:-tcp} ${addr:-:49}"
        return 0
    fi
    if ! grep -qs 'listeners' "$TACCTL_OVERRIDES_FILE"; then
        echo "default tcp :49"
        return 0
    fi
    local name net addr _rest
    while IFS=$'\t' read -r name net addr _rest; do
        echo "${name} ${net} ${addr}"
    done < <(backend_listeners tacacs)
}

# _tacacs_setting <level|metrics_address>: '<value> <override|default>'.
_tacacs_setting() {
    local key="$1" value="" fallback
    case "$key" in
        level) fallback="$TACACS_LEVEL_DEFAULT" ;;
        *)     fallback="$TACACS_METRICS_DEFAULT" ;;
    esac
    if _tacacs_units_legacy; then
        case "$key" in
            level) value=$(read_service_override TACQUITO_LEVEL) ;;
            *)     value=$(read_service_override TACQUITO_METRICS_ADDRESS) ;;
        esac
    elif grep -qs 'backends' "$TACCTL_OVERRIDES_FILE" && conf_has_override "backends.tacacs.${key}"; then
        value=$(conf_get "backends.tacacs.${key}")
    fi
    if [[ -n "$value" ]]; then
        echo "${value} override"
    else
        echo "${fallback} default"
    fi
}

# -u arguments for journalctl, one per line: the default listener's unit as
# it has always been named, then every other listener's.
_tacacs_journal_units() {
    printf '%s\n' -u tacquito
    local name _net _addr
    while read -r name _net _addr; do
        [[ "$name" == "default" ]] || printf '%s\n' -u "$(_tacacs_unit "$name")"
    done < <(_tacacs_listener_lines)
}

# --- Rendering the drop-ins ---

# _tacacs_units_stage <dir>: render every listener's drop-in into
# <dir>/units (see render_units) without a store. Returns 1, message on
# stderr, when the listener model cannot be served.
_tacacs_units_stage() {
    _conf_load_cache
    _render_python render-units "${1}/units" "${TACCTL_OVERRIDES_FILE:-}" "$RENDERED_FILE" \
        "$LOG_DIR" "$(_tacacs_dropin default)" "$TACACS_UNIT_DIR" \
        < <(printf '%s' "$_TACCTL_CFG_CACHE")
}

# _tacacs_units_commit <dir>: install the drop-ins staged in <dir>/units and
# remove those of listeners that are gone. Prints the unit of every drop-in
# it wrote or removed, one per line (nothing: all were current). Files only:
# the caller reloads systemd and restarts.
_tacacs_units_commit() {
    local dir="${1}/units" name status live f inst
    local -a names=()
    [[ -f "${dir}/index" ]] || return 0
    while IFS=$'\t' read -r name status live; do
        [[ -n "$name" ]] || continue
        names+=("$name")
        case "$status" in
            current)
                continue
                ;;
            same)
                rendered_record "$live" || return 1
                continue
                ;;
            unreadable)
                error "Cannot read ${RENDERED_FILE}; refusing to overwrite ${live}."
                return 1
                ;;
            drift|unrecorded)
                _tacacs_save_displaced "$live" || return 1
                ;;
        esac
        mkdir -p "$(dirname "$live")" || return 1
        chmod 755 "$(dirname "$live")"
        cp "${dir}/${name}.conf" "${live}.tacctl-new" || return 1
        chmod 644 "${live}.tacctl-new"
        mv -f "${live}.tacctl-new" "$live" || { rm -f "${live}.tacctl-new"; return 1; }
        rendered_record "$live" || return 1
        _tacacs_unit "$name"
    done < "${dir}/index"

    for f in "$TACACS_UNIT_DIR"/tacquito@*.service.d/"$TACACS_DROPIN"; do
        [[ -f "$f" ]] || continue
        inst="${f%.service.d/*}"
        inst="${inst##*/tacquito@}"
        [[ " ${names[*]} " == *" ${inst} "* ]] && continue
        rm -f "$f" || return 1
        rmdir "$(dirname "$f")" 2>/dev/null || true
        rendered_forget "$f" || return 1
        _tacacs_unit "$inst"
    done
    return 0
}

# --- Copies to put back when a change does not hold ---

# Every file a settings change or a unit install can touch.
_tacacs_units_files() {
    printf '%s\n' "$TACCTL_OVERRIDES_FILE" "$RENDERED_FILE" "$SERVICE_FILE" "$TEMPLATE_FILE" \
        "$OVERRIDE_FILE" "$(_tacacs_dropin default)"
    local f
    for f in "$TACACS_UNIT_DIR"/tacquito@*.service.d/"$TACACS_DROPIN"; do
        [[ -f "$f" ]] && printf '%s\n' "$f"
    done
    return 0
}

# _tacacs_units_keep <dir>: copy them. Line n of <dir>/index names the file
# kept as <dir>/n (no such copy: the file did not exist).
_tacacs_units_keep() {
    local dir="$1" path n=0
    mkdir -p "$dir" || return 1
    : > "${dir}/index" || return 1
    while IFS= read -r path; do
        [[ -n "$path" ]] || continue
        n=$((n + 1))
        printf '%s\n' "$path" >> "${dir}/index"
        if [[ -f "$path" ]]; then
            cp -p "$path" "${dir}/${n}" || return 1
        fi
    done < <(_tacacs_units_files)
}

# _tacacs_units_restore <dir>: put them back, and remove drop-ins of
# instances that did not exist then. Never fails: it warns per file.
_tacacs_units_restore() {
    local dir="$1" path n=0 f
    while IFS= read -r path; do
        n=$((n + 1))
        if [[ -f "${dir}/${n}" ]]; then
            mkdir -p "$(dirname "$path")" || true
        fi
        _backends_render_put "${dir}/${n}" "$path"
    done < "${dir}/index"
    for f in "$TACACS_UNIT_DIR"/tacquito@*.service.d/"$TACACS_DROPIN"; do
        [[ -f "$f" ]] || continue
        if ! grep -qxF -- "$f" "${dir}/index"; then
            rm -f "$f"
            rmdir "$(dirname "$f")" 2>/dev/null || true
        fi
    done
    rmdir "$OVERRIDE_DIR" 2>/dev/null || true
    _conf_invalidate
    return 0
}

# tacctl.yaml must parse before a setting is written into it: conf_set reads
# a file it cannot parse as empty and would replace it. Returns 1, message on
# stderr.
_tacacs_overrides_readable() {
    [[ -f "$TACCTL_OVERRIDES_FILE" ]] || return 0
    python3 -c '
import sys, yaml
doc = yaml.safe_load(open(sys.argv[1]))
sys.exit(0 if doc is None or isinstance(doc, dict) else 1)
' "$TACCTL_OVERRIDES_FILE" 2>/dev/null && return 0
    error "${TACCTL_OVERRIDES_FILE} is not valid YAML ('tacctl config validate' shows where); fix it first."
    return 1
}

# --- Installs that are not converted yet ---

# _tacacs_listener_json <name> <network> <address>: the listener's entry in
# tacctl.yaml with these two set and its other keys kept, as JSON.
_tacacs_listener_json() {
    python3 -c '
import json, sys
cur = json.loads(sys.argv[1])
cur = cur if isinstance(cur, dict) else {}
cur.update(network=sys.argv[2], address=sys.argv[3])
print(json.dumps(cur))
' "$(conf_get_json "listeners.tacacs.${1}")" "$2" "$3"
}

# Write what the hand-managed drop-in says into tacctl.yaml: a key it sets is
# set, a key it does not set goes back to the default (the file is the truth
# for as long as it exists). The file itself stays; _tacacs_legacy_retire
# removes it once the rendered drop-in is in place. Returns 1, message on
# stderr, for a file tacctl cannot carry over or a value the schema refuses.
_tacacs_legacy_import() {
    local out key value net="" addr="" level="" metrics=""
    out=$(_render_python legacy-dropin "$OVERRIDE_FILE") || return 1
    while IFS='=' read -r key value; do
        case "$key" in
            TACQUITO_NETWORK)         net="$value" ;;
            TACQUITO_ADDRESS)         addr="$value" ;;
            TACQUITO_LEVEL)           level="$value" ;;
            TACQUITO_METRICS_ADDRESS) metrics="$value" ;;
        esac
    done <<< "$out"
    if [[ -n "${net}${addr}" ]]; then
        conf_set_json listeners.tacacs.default \
            "$(printf '{"network": "%s", "address": "%s"}' "${net:-tcp}" "${addr:-:49}")" || return 1
    else
        conf_unset listeners.tacacs.default || return 1
    fi
    if [[ -n "$level" ]]; then
        conf_set backends.tacacs.level "$level" || return 1
    else
        conf_unset backends.tacacs.level || return 1
    fi
    if [[ -n "$metrics" ]]; then
        conf_set backends.tacacs.metrics_address "$metrics" || return 1
    else
        conf_unset backends.tacacs.metrics_address || return 1
    fi
}

# Remove the hand-managed drop-in, keeping a copy under backups/legacy/.
# Called once the drop-in rendered from its imported values is installed.
_tacacs_legacy_retire() {
    _tacacs_units_legacy || return 0
    local dir="${BACKUP_DIR}/legacy" dest
    mkdir -p "$dir" || return 1
    chmod 700 "$dir"
    dest="${dir}/$(basename "$OVERRIDE_FILE").$(date +%Y%m%d_%H%M%S_%3N)"
    cp "$OVERRIDE_FILE" "$dest" || return 1
    chmod 600 "$dest"
    rm -f "$OVERRIDE_FILE" "${OVERRIDE_FILE}.bak" || return 1
    info "Listener, log level and metrics settings moved from ${OVERRIDE_FILE} into ${TACCTL_OVERRIDES_FILE} (the old drop-in is kept as ${dest})."
}

# --- Instances ---

# Bring the template instances in line with the listeners: every listener
# other than the default one has its instance enabled and running, and an
# enabled instance without a listener is stopped and disabled. Cheap when
# there is neither. Never fails the caller.
_tacacs_instances_sync() {
    local name _net _addr link inst
    local -a names=()
    while read -r name _net _addr; do
        [[ -n "$name" && "$name" != "default" ]] || continue
        names+=("$name")
        systemctl enable --quiet --now "$(_tacacs_unit "$name")" 2>/dev/null \
            || warn "Could not enable and start $(_tacacs_unit "$name") — check: systemctl status $(_tacacs_unit "$name")"
    done < <(_tacacs_listener_lines)
    for link in "$TACACS_UNIT_DIR"/tacquito.service.wants/tacquito@*.service; do
        [[ -L "$link" ]] || continue
        inst="${link##*/tacquito@}"
        inst="${inst%.service}"
        [[ " ${names[*]-} " == *" ${inst} "* ]] && continue
        systemctl disable --quiet --now "$(_tacacs_unit "$inst")" 2>/dev/null || true
    done
    return 0
}

# Has <unit> stayed up? A daemon that cannot bind its address exits within
# milliseconds of a start systemd already called successful.
_tacacs_unit_settled() {
    sleep "$TACACS_SETTLE_SECONDS"
    systemctl is-active --quiet "$1"
}

# --- Changing a setting ---

# _tacacs_settings_apply <all|listener> <writer> [<arg>...]
# Run <writer> (conf_* calls changing listeners.tacacs or backends.tacacs)
# and make the units follow: render the drop-ins, reload systemd, restart
# what the change concerns and check that it stayed up.
#   all        the change concerns every listener (log level, metrics, the
#              default listener: restarting tacquito.service restarts all)
#   <listener> only that listener's instance is restarted, started (new) or
#              stopped (removed)
# An install that is not converted is converted first.
#   return 0  applied
#          1  failed or refused; tacctl.yaml, the drop-ins and the units are
#             as they were (message on stderr)
# No store is needed. Call it in the current shell.
_tacacs_settings_apply() {
    local target="$1"
    shift
    local keep unit
    _tacacs_overrides_readable || return 1
    mkdir -p "$TACCTL_STATE_DIR" || return 1
    keep=$(mktemp -d "${TACCTL_STATE_DIR}/.units.XXXXXX") || return 1
    if ! _tacacs_units_keep "${keep}/keep"; then
        rm -rf "$keep"
        return 1
    fi
    if ! backup_snapshot; then
        rm -rf "$keep"
        error "Nothing was changed: the pre-change snapshot could not be made."
        return 1
    fi

    if { _tacacs_units_legacy && ! _tacacs_legacy_import; } || ! "$@" || ! _tacacs_units_stage "$keep"; then
        _tacacs_units_restore "${keep}/keep"
        rm -rf "$keep"
        error "Nothing was changed."
        return 1
    fi
    if ! _tacacs_units_commit "$keep" > /dev/null || ! _tacacs_legacy_retire; then
        _tacacs_units_restore "${keep}/keep"
        rm -rf "$keep"
        systemctl daemon-reload
        error "The change could not be installed. Settings and drop-ins are as they were."
        return 1
    fi
    systemctl daemon-reload

    if [[ "$target" == "all" || "$target" == "default" ]]; then
        unit="tacquito"
        systemctl restart "$unit"
        _tacacs_instances_sync
    else
        unit=$(_tacacs_unit "$target")
        if [[ ! -f "$(_tacacs_dropin "$target")" ]]; then
            # The listener was removed: nothing to prove.
            systemctl disable --quiet --now "$unit" 2>/dev/null || true
            rm -rf "$keep"
            return 0
        fi
        systemctl enable --quiet "$unit" 2>/dev/null || true
        systemctl restart "$unit"
    fi

    if _tacacs_unit_settled "$unit"; then
        rm -rf "$keep"
        return 0
    fi
    error "${unit%.service} failed to start. Restoring previous override."
    _tacacs_units_restore "${keep}/keep"
    rm -rf "$keep"
    systemctl daemon-reload
    if [[ "$unit" == "tacquito" || -f "$(_tacacs_dropin "$target")" ]]; then
        systemctl restart "$unit"
    else
        systemctl disable --quiet --now "$unit" 2>/dev/null || true
    fi
    return 1
}

# --- CONFIG LOGLEVEL ---
cmd_config_loglevel() {
    local new_level="${1:-}"

    local current_num _src
    read -r current_num _src < <(_tacacs_setting level)

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

    # The default level (20) is not written down (conf_set prunes a value
    # equal to the default), so a later release can move the default.
    _tacacs_settings_apply all conf_set backends.tacacs.level "$level_num" || return 1

    info "Log level changed to ${new_level} (${level_num}). Service restarted."
    echo ""
}

# --- CONFIG LISTEN (the contract's 'listeners' verb; CLI in lib/backend.sh) ---

# _tacacs_listener_get <name>: sets L_NET, L_ADDR and L_SRC (override|default)
# of a listener in effect. Returns 1 when there is none of that name.
_tacacs_listener_get() {
    local want="$1" name net addr
    L_NET="" L_ADDR="" L_SRC="default"
    while read -r name net addr; do
        if [[ "$name" == "$want" ]]; then
            L_NET="$net"
            L_ADDR="$addr"
        fi
    done < <(_tacacs_listener_lines)
    [[ -n "$L_NET" ]] || return 1
    if _tacacs_units_legacy; then
        if [[ -n "$(read_service_override TACQUITO_NETWORK)$(read_service_override TACQUITO_ADDRESS)" ]]; then
            L_SRC="override"
        fi
    elif [[ "$want" != "default" ]] || conf_has_override "listeners.tacacs.${want}"; then
        L_SRC="override"
    fi
    return 0
}

_tacacs_listener_show() {
    local want="$1" name net addr
    if ! _tacacs_listener_get "$want"; then
        error "No listener '${want}'. Create it: tacctl config listen --listener ${want} tcp <address>"
        return 1
    fi
    if [[ "$want" != "default" ]]; then
        echo "  Listener '${want}': ${L_NET} ${L_ADDR}"
        echo "  ($(_tacacs_unit "$want"); set in ${TACCTL_OVERRIDES_FILE})"
        return 0
    fi
    echo "  Current listener: ${L_NET} ${L_ADDR}"
    if [[ "$L_SRC" != "override" ]]; then
        echo "  (template default)"
    elif _tacacs_units_legacy; then
        echo "  (override in ${OVERRIDE_FILE})"
    else
        echo "  (override in ${TACCTL_OVERRIDES_FILE})"
    fi
    while read -r name net addr; do
        [[ "$name" == "default" ]] || echo "  Listener '${name}': ${net} ${addr} ($(_tacacs_unit "$name"))"
    done < <(_tacacs_listener_lines)
}

# Would listeners.tacacs.<name> = <json> collide with another listener or be
# refused by the schema? Checked before anything is written. Message on stderr.
_tacacs_listener_check() {
    _conf_load_cache
    python3 <(_listener_py; cat <<'PY'
import json, sys
doc, name, value = json.loads(sys.argv[1]), sys.argv[2], json.loads(sys.argv[3])
section = doc.get('listeners') if isinstance(doc.get('listeners'), dict) else {}
mine = section.get('tacacs') if isinstance(section.get('tacacs'), dict) else {}
doc['listeners'] = dict(section, tacacs=dict(mine, **{name: value}))
path = f'listeners.tacacs.{name}'
bad = listeners_problems(doc, only=path)
if bad:
    print(bad[0][len(path) + 2:], file=sys.stderr)
    sys.exit(1)
PY
) "$_TACCTL_CFG_CACHE" "$1" "$2"
}

_tacacs_listener_set() {
    local name="$1" sub="$2" addr="$3"
    case "$sub" in
        tcp|tcp6) ;;
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

    local existed=1
    _tacacs_listener_get "$name" || existed=0
    if [[ "$L_NET" == "$sub" && "$L_ADDR" == "$addr" ]]; then
        info "Already listening on ${sub} ${addr}."
        return
    fi

    local json why
    json=$(_tacacs_listener_json "$name" "$sub" "$addr") || return 1
    if ! why=$(_tacacs_listener_check "$name" "$json" 2>&1); then
        error "Cannot listen on ${sub} ${addr}: ${why}"
        return 1
    fi

    if [[ "$sub" == "tcp6" && "$L_NET" != "tcp6" ]]; then
        echo ""
        warn "tcp6 enables dual-stack sockets on most platforms."
        warn "IPv4 clients connect with mapped addresses (::ffff:a.b.c.d)"
        warn "which do NOT match IPv4 rules in 'tacctl scope prefixes <name>',"
        warn "'config allow', or 'config deny' -- effectively bypassing them."
        echo ""
        read -rp "  Proceed with tcp6? [y/N]: " confirm || true
        if [[ ! "$confirm" =~ ^[Yy] ]]; then
            info "Aborted."
            return
        fi
    fi

    # A unit that does not come up with the new address gets the previous
    # settings back (see _tacacs_settings_apply).
    _tacacs_settings_apply "$name" conf_set_json "listeners.tacacs.${name}" "$json" || return 1

    if [[ "$name" == "default" ]]; then
        info "Listener changed to ${sub} ${addr}. Service restarted."
    elif (( existed )); then
        info "Listener '${name}' changed to ${sub} ${addr}. $(_tacacs_unit "$name") restarted."
    else
        info "Listener '${name}' added on ${sub} ${addr}. $(_tacacs_unit "$name") enabled and started."
        info "It logs accounting to $(_tacacs_acct_log "$name") and exports no metrics unless listeners.tacacs.${name}.metrics_address is set."
    fi
    echo ""
}

_tacacs_listener_reset() {
    local name="$1"
    if ! _tacacs_listener_get "$name"; then
        error "No listener '${name}'."
        return 1
    fi
    if [[ "$name" != "default" ]]; then
        # Only the built-in listener has a default to go back to.
        _tacacs_settings_apply "$name" conf_unset "listeners.tacacs.${name}" || return 1
        info "Listener '${name}' removed. $(_tacacs_unit "$name") stopped and disabled."
        echo ""
        return
    fi
    if [[ "$L_SRC" == "default" ]]; then
        info "No listener override set. Already on template default (${L_NET} ${L_ADDR})."
        return
    fi
    if ! _tacacs_settings_apply default conf_unset listeners.tacacs.default; then
        error "tacquito failed to start after reset."
        return 1
    fi
    info "Listener override removed. Using template default. Service restarted."
    echo ""
}

# --- CONFIG METRICS ---
# Control the prometheus exporter's listen address (tacquito's -metrics-address
# flag). `disable` binds the exporter to 127.0.0.1:0 — a loopback address on
# an ephemeral port that no scraper can discover, so from any reader's
# perspective the exporter is gone even though the goroutine still runs.
# We deliberately do NOT toggle tacquito's -export-promhttp flag: upstream's
# goroutine unconditionally cancels the server context when the exporter
# returns, so `-export-promhttp=false` would tear down the whole daemon.
# This is the default listener's exporter; another listener exports metrics
# only when listeners.tacacs.<name>.metrics_address is set.
cmd_config_metrics() {
    local sub="${1:-}"
    local arg="${2:-}"

    # Defaults must match config/backends/tacacs/tacquito.service Environment= lines.
    # Loopback-only by default: local scrapers on the box can reach it, external
    # ones can't without an explicit `tacctl config metrics address` change.
    local default_addr="$TACACS_METRICS_DEFAULT"
    local disable_sink="$TACACS_METRICS_SINK"

    local cur_addr addr_src
    read -r cur_addr addr_src < <(_tacacs_setting metrics_address)

    local state state_color
    if [[ "$cur_addr" == "$disable_sink" ]]; then
        state="disabled"; state_color="$RED"
    elif [[ "$cur_addr" == 127.* || "$cur_addr" == "[::1]"* || "$cur_addr" == "localhost:"* ]]; then
        state="enabled (loopback-only)"; state_color="$GREEN"
    else
        state="enabled (externally reachable)"; state_color="$YELLOW"
    fi

    case "$sub" in
        ""|show|-h|--help|help)
            echo ""
            echo -e "${BOLD}Prometheus metrics exporter${NC}"
            echo "--------------------------------------------"
            echo -e "  State:    ${state_color}${state}${NC}"
            echo -e "  Address:  ${cur_addr}  (${addr_src})"
            if [[ "$state" != "disabled" ]]; then
                echo ""
                local scrape_url
                if [[ "$cur_addr" == :* ]]; then
                    scrape_url="http://localhost${cur_addr}/metrics"
                else
                    scrape_url="http://${cur_addr}/metrics"
                fi
                echo "  Scrape URL: ${scrape_url}"
            fi
            echo ""
            echo "Usage:"
            echo "  tacctl config metrics                      Show current state"
            echo "  tacctl config metrics enable               Revert to default (${default_addr})"
            echo "  tacctl config metrics disable              Sink to ${disable_sink} (no scraper can reach)"
            echo "  tacctl config metrics address <host:port>  Explicit bind (e.g. 10.1.0.1:8080 for external)"
            echo "  tacctl config metrics reset                Clear override (revert to unit default)"
            echo ""
            if [[ "$state" == "disabled" ]]; then
                echo "  Note: tacquito still runs the exporter goroutine, bound to an"
                echo "        ephemeral loopback port unknown to any scraper. This is the"
                echo "        closest we can get without patching tacquito upstream."
                echo ""
            fi
            return
            ;;
        enable)
            if [[ "$state" != "disabled" && "$addr_src" == "default" ]]; then
                info "Already enabled on default (${default_addr})."
                return
            fi
            _tacacs_settings_apply all conf_unset backends.tacacs.metrics_address || return 1
            info "Metrics exporter enabled on ${default_addr}/metrics."
            echo ""
            ;;
        disable)
            if [[ "$state" == "disabled" ]]; then
                info "Already disabled (sunk to ${disable_sink})."
                return
            fi
            _tacacs_settings_apply all conf_set backends.tacacs.metrics_address "$disable_sink" || return 1
            info "Metrics exporter sunk to ${disable_sink} — no scraper can reach it."
            warn "Note: the exporter goroutine still runs; bind-to-loopback-0 is the"
            warn "closest 'off' state tacquito supports without an upstream patch."
            echo ""
            ;;
        address)
            if [[ -z "$arg" ]]; then
                error "Usage: tacctl config metrics address <host:port>"
                error "Examples:  127.0.0.1:8080  (loopback only — default)"
                error "           :8080           (all interfaces — external scrapers can reach)"
                error "           10.1.0.1:9090   (specific mgmt IP + custom port)"
                exit 1
            fi
            if [[ "$arg" != *:* ]]; then
                error "Address must include a port (e.g. '127.0.0.1:8080' or ':8080')."
                exit 1
            fi
            # The default address is not written down (conf_set prunes it).
            _tacacs_settings_apply all conf_set backends.tacacs.metrics_address "$arg" || return 1
            info "Metrics listen address set to ${arg}. Service restarted."
            if [[ "$arg" != 127.* && "$arg" != "[::1]"* && "$arg" != "$disable_sink" ]]; then
                warn "Exporter is now externally reachable. Ensure downstream scrapers"
                warn "have appropriate network-level access controls."
            fi
            echo ""
            ;;
        reset)
            _tacacs_settings_apply all conf_unset backends.tacacs.metrics_address || return 1
            info "Metrics override cleared. Using unit default (${default_addr})."
            echo ""
            ;;
        *)
            error "Unknown subcommand: '${sub}'"
            error "Run 'tacctl config metrics' with no arguments for usage."
            exit 1
            ;;
    esac
}

# =====================================================================
#  STATUS SECTIONS (tacctl status)
# =====================================================================

# Service state, uptime, PID, memory, listener, log level: the default
# listener's unit as this report always showed it, then one line per other
# listener's instance.
_tacacs_status_service() {
    # Service state. is-active prints the state and fails for anything but
    # 'active': the word is what is shown.
    local state
    state=$(systemctl is-active tacquito 2>/dev/null) || true
    state=${state:-unknown}
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

    # Listening port: the default listener's, from the listener model.
    local listeners name net addr port listen
    listeners=$(_tacacs_listener_lines)
    read -r name net addr <<< "$listeners"
    port="${addr##*:}"
    listen=$(ss -tlnp 2>/dev/null | { grep ":${port} " || true; } | awk '{print $4}' | head -1)
    if [[ -n "$listen" ]]; then
        echo -e "  ${BOLD}Listening:${NC}            ${GREEN}${listen}${NC}"
    else
        echo -e "  ${BOLD}Listening:${NC}            ${RED}port ${port} not detected${NC}"
    fi

    # The other listeners, one instance each.
    local unit istate ipid
    while read -r name net addr; do
        [[ -n "$name" && "$name" != "default" ]] || continue
        unit=$(_tacacs_unit "$name")
        istate=$(systemctl is-active "$unit" 2>/dev/null) || true
        istate=${istate:-unknown}
        state_color="$GREEN"
        [[ "$istate" != "active" ]] && state_color="$RED"
        ipid=$(systemctl show "$unit" --property=MainPID 2>/dev/null | cut -d= -f2)
        if [[ -n "$ipid" && "$ipid" != "0" ]]; then
            ipid=", PID ${ipid}"
        else
            ipid=""
        fi
        echo -e "  ${BOLD}Listener ${name}:${NC} ${state_color}${istate}${NC} — ${net} ${addr} (${unit}${ipid})"
    done <<< "$listeners"

    # Log level: the backend's setting (tacctl.yaml; the hand-managed drop-in
    # on an install that is not converted). Every listener runs at it.
    local loglevel _src
    read -r loglevel _src < <(_tacacs_setting level)
    local level_name
    case "$loglevel" in
        10) level_name="error" ;;
        20) level_name="info" ;;
        30) level_name="debug" ;;
        *)  level_name="unknown" ;;
    esac
    echo -e "  ${BOLD}Log level:${NC}            ${level_name} (${loglevel})"
}

_tacacs_status_accounting() {
    # Accounting log size
    if [[ -f "$ACCT_LOG" ]]; then
        local log_size
        log_size=$(du -sh "$ACCT_LOG" 2>/dev/null | awk '{print $1}')
        local log_lines
        log_lines=$(wc -l < "$ACCT_LOG" 2>/dev/null)
        echo -e "  ${BOLD}Accounting log:${NC}       ${log_size} (${log_lines} entries)"
    fi
    # The other listeners' logs.
    local log name
    for log in "$LOG_DIR"/accounting-*.log; do
        [[ -f "$log" ]] || continue
        name="${log##*/accounting-}"
        echo -e "  ${BOLD}Accounting log (${name%.log}):${NC} $(du -sh "$log" 2>/dev/null | awk '{print $1}') ($(wc -l < "$log" 2>/dev/null) entries)"
    done
}

# Print the four counters of the exporter at <metrics address>, or why there
# are none. Respects the tacctl config metrics address: when the exporter is
# bound to 127.0.0.1:0 (our "disabled" sink) we skip scraping and report the
# disabled state explicitly rather than pretending the service is unreachable.
_tacacs_status_stats() {
    local metrics_addr="$1" metrics_url
    if [[ "$metrics_addr" == "$TACACS_METRICS_SINK" ]]; then
        echo -e "    ${YELLOW}Metrics exporter disabled (tacctl config metrics enable)${NC}"
        return 0
    fi
    if [[ "$metrics_addr" == :* ]]; then
        metrics_url="http://localhost${metrics_addr}/metrics"
    else
        metrics_url="http://${metrics_addr}/metrics"
    fi
    local metrics
    metrics=$(curl -s "$metrics_url" 2>/dev/null || true)
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
        echo -e "    ${YELLOW}Metrics unavailable (${metrics_url})${NC}"
    fi
}

# Authentication counters from the metrics exporter, then recent errors. The
# first block is the default listener's exporter (backends.tacacs.metrics_address);
# every other listener is its own process and has an exporter only when it
# sets metrics_address, so each has a block of its own (or a line saying it
# has none). With only the default listener the report is what it always was.
_tacacs_status_activity() {
    echo ""
    echo -e "  ${BOLD}Authentication Stats (since last restart):${NC}"
    local metrics_addr _src
    read -r metrics_addr _src < <(_tacacs_setting metrics_address)
    _tacacs_status_stats "$metrics_addr"

    local name _net _addr _role maddr _origin
    if ! _tacacs_units_legacy && (( $(_tacacs_listener_lines | wc -l) > 1 )); then
        while IFS=$'\t' read -r name _net _addr _role maddr _origin; do
            [[ -n "$name" && "$name" != "default" ]] || continue
            echo ""
            if [[ -z "$maddr" || "$maddr" == "-" ]]; then
                echo -e "  ${BOLD}Authentication Stats, listener ${name}:${NC} no metrics exporter (listeners.tacacs.${name}.metrics_address)"
            else
                echo -e "  ${BOLD}Authentication Stats, listener ${name} (since last restart):${NC}"
                _tacacs_status_stats "$maddr"
            fi
        done < <(backend_listeners tacacs)
    fi

    # Recent errors
    echo ""
    echo -e "  ${BOLD}Recent Errors (last 5):${NC}"
    local errors
    local -a units
    mapfile -t units < <(_tacacs_journal_units)
    errors=$(journalctl "${units[@]}" --no-pager -n 100 --since "24 hours ago" 2>/dev/null | grep "ERROR:" | tail -5 || true)
    if [[ -n "$errors" ]]; then
        echo "$errors" | while IFS= read -r line; do
            echo -e "    ${RED}${line}${NC}"
        done
    else
        echo -e "    ${GREEN}No errors in the last 24 hours${NC}"
    fi
}

# =====================================================================
#  LOG COMMANDS
# =====================================================================

# Purge the tacquito journal and truncate the file-based accounting log.
# Destructive — prompts for confirmation. Accepts `--force` / `-y` to skip
# the prompt for scripted use (e.g. scheduled cleanups).
cmd_log_clear() {
    local force=false
    case "${1:-}" in
        -y|--force|--yes) force=true ;;
    esac

    echo ""
    echo -e "${BOLD}Clear tacquito logs${NC}"
    echo "--------------------------------------------"
    warn "This permanently deletes tacquito journal entries and truncates ${ACCT_LOG}."
    local log
    for log in "$LOG_DIR"/accounting-*.log; do
        [[ -f "$log" ]] && warn "Also truncated: ${log}"
    done
    warn "Historical authentication and accounting records will be lost."

    if [[ "$force" != "true" ]]; then
        read -rp "  Continue? [y/N]: " confirm || true
        if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
            info "Cancelled."
            return 0
        fi
    fi

    # Rotate closes the active journal file so the vacuum step can evict it;
    # --vacuum-time=1s then drops everything older than one second. The
    # per-unit filter keeps other services' journals intact.
    journalctl --rotate 2>/dev/null || true
    if ! journalctl --vacuum-time=1s -u tacquito >/dev/null 2>&1; then
        warn "journalctl vacuum failed — run manually: sudo journalctl --vacuum-time=1s -u tacquito"
    fi

    # Truncate in place so logrotate's ownership/permissions stay intact.
    for log in "$ACCT_LOG" "$LOG_DIR"/accounting-*.log; do
        [[ -f "$log" ]] || continue
        : > "$log" 2>/dev/null || warn "Could not truncate ${log} (check permissions)."
    done

    info "Logs cleared (journal + accounting)."
    echo ""
}

# =====================================================================
#  LEGACY MODE (pre-store tacquito.yaml) AND THE MOVE INTO THE STORE
# =====================================================================

# Old-style backup of tacquito.yaml alone. Only the legacy (no store yet)
# paths use it: a pre-store install keeps backing up the file that is still
# its source of truth. With a store, backup_snapshot is the backup.
backup_config() {
    mkdir -p "$BACKUP_DIR"
    chmod 750 "$BACKUP_DIR"
    chown tacquito:tacquito "$BACKUP_DIR" 2>/dev/null || true
    # Milliseconds (%3N) avoid collisions when two mutating commands land in
    # the same wall-clock second.
    local ts
    ts=$(date +%Y%m%d_%H%M%S_%3N)
    cp "$CONFIG" "${BACKUP_DIR}/tacquito.yaml.${ts}"
    chmod 640 "${BACKUP_DIR}/tacquito.yaml.${ts}"
    chown tacquito:tacquito "${BACKUP_DIR}/tacquito.yaml.${ts}" 2>/dev/null || true
    info "Config backed up to ${BACKUP_DIR}/tacquito.yaml.${ts}"

    # Prune old backups, keep last $BACKUP_RETENTION. Same no-match
    # guard as cmd_status: avoid set -e tripping the caller when the
    # backups directory is empty.
    local count
    count=$(find "${BACKUP_DIR}" -maxdepth 1 -name 'tacquito.yaml.*' 2>/dev/null | wc -l || true)
    if [[ "$count" -gt "$BACKUP_RETENTION" ]]; then
        # shellcheck disable=SC2012  # mtime order needed; names are tacctl-generated tacquito.yaml.<timestamp>
        ls -1t "${BACKUP_DIR}"/tacquito.yaml.* | tail -n +$((BACKUP_RETENTION + 1)) | xargs rm -f
    fi
}

# No store yet: copy the old-style file back, as it always did.
_backup_restore_unflipped() {
    local id="$1" file
    if ! file=$(_backup_legacy_path "$id"); then
        if _backup_is_snapshot "$id"; then
            error "Snapshot ${id} holds the store, which is not initialised here. ${STORE_NOT_INITIALISED_MSG}"
        else
            error "Backup not found: ${id}"
            error "Run 'tacctl backup list' to see available backups."
        fi
        return 1
    fi

    echo ""
    echo "  Restoring config from: ${id}"
    echo ""
    echo -e "  ${BOLD}Changes that will be applied:${NC}"
    diff --color=always "$CONFIG" "$file" || true
    echo ""
    _backup_confirm || return 0

    # Back up current config before restoring (safety net)
    backup_config
    cp "$file" "$CONFIG"
    chown tacquito:tacquito "$CONFIG"
    chmod 640 "$CONFIG"
    backend_tacacs_service restart
    info "Config restored from backup ${id}."
    echo ""
}

# --- One-shot: ingest existing tacquito.yaml `commands:` blocks into tacctl.yaml ---
# On upgrade from the pre-unified-commands model, tacquito.yaml is the
# source of operator customizations. We scrape each group's commands: block,
# compare to the shipped default, and write an override in tacctl.yaml when
# the scraped rules diverge. Silent no-op when scrape matches the default
# (no override is written — defaults already produce the right state).
# Idempotent: a second run scrapes the same (now-regenerated) blocks and
# sees no divergence.
conf_migrate_command_rules() {
    # Legacy installs only: once the store exists tacquito.yaml is rendered
    # from tacctl.yaml and holds nothing to ingest.
    [[ -f "$STORE_FILE" ]] && return 0
    [[ -r "$CONFIG" ]] || return 0
    _conf_load_cache
    # One python invocation emits "<group>\t<rules-json>" per group whose
    # scraped commands: block differs from the current merged view. Silent
    # when everything already matches.
    local group rules_json
    while IFS=$'\t' read -r group rules_json; do
        [[ -z "$group" ]] && continue
        conf_set_json "commands.${group}" "$rules_json"
        info "Migrated tacquito.yaml commands: block for group '${group}' → commands.${group}"
    done < <(python3 - "$CONFIG" "$_TACCTL_CFG_CACHE" <(_conf_schema_py) <<'PY'
import json, re, sys
exec(open(sys.argv[3]).read())  # command_match_is_dead
cfg = open(sys.argv[1]).read()
merged = json.loads(sys.argv[2])
current_commands = (merged.get('commands') or {})
for gm in re.finditer(
    r'^(\w+): &\1\n(?:[ \t].*\n)+',
    cfg, re.MULTILINE,
):
    block = gm.group(0)
    group = gm.group(1)
    cm = re.search(r'^  commands:\n((?:    -.*\n(?:      .*\n)*)+)', block, re.MULTILINE)
    if not cm:
        continue
    rules_text = cm.group(1)
    rules = []
    for rm in re.finditer(
        r'    - name:\s*(?P<name>"[^"]*"|\S+)\s*\n'
        r'(?:      match:\s*\[(?P<match>[^\]]*)\]\s*\n)?'
        r'      action:\s*\*action_(?P<action>permit|deny)\s*\n',
        rules_text,
    ):
        name = rm.group('name').strip().strip('"')
        matches_str = (rm.group('match') or '').strip()
        matches = [m.strip().strip('"') for m in re.findall(r'"([^"]+)"', matches_str)] if matches_str else []
        # Drop match regexes that can never fire (they repeat the command
        # word; tacquito tests match against the arguments only). Older
        # shipped defaults had this shape, so a stale block normalizes to
        # the current default instead of being scraped into an override.
        matches = [m for m in matches if not command_match_is_dead(name, m)]
        rule = {'name': name, 'action': rm.group('action')}
        if matches:
            rule['match'] = matches
        rules.append(rule)
    if rules and current_commands.get(group) != rules:
        print(f"{group}\t{json.dumps(rules)}")
PY
)
}

# --- One-shot: migrate legacy Cisco exec service name `exec` -> `shell` ---
# Pre-a1e39e6 installs named the Cisco exec service `name: exec`, but real
# devices request `service=shell` for EXEC authorization (Cisco
# `aaa authorization exec`, Peplink Balance, etc.). tacquito's session
# authorizer only returns AVPs for a service whose name matches the requested
# service, so legacy `name: exec` blocks never match `service=shell`:
# authorization fails AFTER a successful authentication, which clients surface
# as "invalid password". This rewrites the `exec_*` service anchors of a
# legacy (pre-store) tacquito.yaml in place. With a store there is nothing
# to do: the importer reads either name and the renderer writes `shell`.
# Idempotent: silent no-op once every exec anchor already says `name: shell`.
conf_migrate_exec_service_name() {
    [[ -f "$STORE_FILE" ]] && return 0
    [[ -r "$CONFIG" ]] || return 0
    # Count eligible legacy lines first so we only back up / write when there's
    # something to do. Only the service-name line directly under a Cisco
    # `exec_<group>: &exec_<group>` anchor matches; the `^exec_` anchor and
    # trailing `$` keep junos blocks (`junos_exec_*` / `name: junos-exec`) and
    # group bodies untouched.
    local n
    n=$(python3 -c "
import re, sys
cfg = open(sys.argv[1]).read()
print(len(re.findall(r'(?m)^exec_\w+: &exec_\w+\n  name: exec\$', cfg)))
" "$CONFIG" 2>/dev/null) || return 0
    [[ "${n:-0}" -gt 0 ]] || return 0

    # Snapshot before mutating so the backup is the pre-migration file, then
    # rewrite atomically (mirrors regenerate_tacquito_commands).
    backup_config
    python3 - "$CONFIG" <<'PY'
import re, sys, tempfile, os
cfg_path = sys.argv[1]
cfg = open(cfg_path).read()
new_cfg = re.sub(r'(?m)^(exec_\w+: &exec_\w+\n  name: )exec$', r'\1shell', cfg)
tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(cfg_path) or '.', delete=False)
tmp.write(new_cfg)
tmp.close()
os.chmod(tmp.name, 0o640)
os.rename(tmp.name, cfg_path)
PY
    chown tacquito:tacquito "$CONFIG" 2>/dev/null || true
    info "Migrated tacquito.yaml service name(s) exec → shell for ${n} group(s)"
}

# --- Bring tacquito.yaml's per-group `commands:` blocks in line with tacctl.yaml ---
# Called by config_sync_existing (below, on install and upgrade) and
# by tests, after commands.<group> in tacctl.yaml may have changed. Commands
# do not call it: they render.
#
# With a store, tacquito.yaml is an artifact, so this re-renders it. A
# refused render (hand-edited file) is reported and left for the operator;
# it never aborts the install or upgrade that called us.
#
# Without one (a legacy install whose import has not happened yet) the file
# is still the source of truth for everything but command rules, and this
# splices each group's commands: block in place -- the only regex editor of
# tacquito.yaml left besides the other legacy migrations. Idempotent.
#
# If `$1` is given, only that group's block is regenerated (legacy mode).
# shellcheck disable=SC2120  # the group argument is optional; config_sync_existing passes none
regenerate_tacquito_commands() {
    if [[ -f "$STORE_FILE" ]]; then
        tacacs_render_apply > /dev/null \
            || warn "tacquito.yaml was not re-rendered; run 'tacctl config render' once the problem above is fixed."
        return 0
    fi
    local only_group="${1:-}"
    _conf_load_cache
    python3 - "$CONFIG" "$_TACCTL_CFG_CACHE" "$only_group" <<'PY'
import json, re, sys, tempfile, os
cfg_path, merged_json, only_group = sys.argv[1], sys.argv[2], sys.argv[3]
if not os.path.isfile(cfg_path):
    sys.exit(0)
cfg = open(cfg_path).read()
merged = json.loads(merged_json)
commands = merged.get('commands') or {}

def render_block(rules):
    """Emit a tacquito-shaped `  commands:` block for a rule list."""
    if not rules:
        return ""
    lines = ["  commands:\n"]
    for r in rules:
        name = r.get("name", "")
        action = r.get("action", "permit")
        match = r.get("match") or []
        lines.append(f'    - name: "{name}"\n')
        if match:
            quoted = ", ".join(f'"{m}"' for m in match)
            lines.append(f"      match: [{quoted}]\n")
        lines.append(f"      action: *action_{action}\n")
    return "".join(lines)

def splice_group(cfg, group, new_block):
    """Replace (or insert/delete) the `commands:` section of <group>."""
    # Match from "<group>: &<group>\n" to the line before "  accounter:"
    # (every tacctl-managed group has exactly one accounter: line at the
    # bottom — that's the block's terminal sentinel).
    hdr = re.escape(group) + r': &' + re.escape(group)
    m = re.search(
        r'(^' + hdr + r'\n(?:[ \t].*\n)*?)'
        r'(^  commands:\n(?:    -.*\n(?:      .*\n)*)+)?'
        r'(^  accounter:.*\n)',
        cfg, re.MULTILINE,
    )
    if not m:
        return cfg  # group absent or shape unexpected; leave alone
    pre, _old_commands, accounter = m.group(1), m.group(2) or "", m.group(3)
    return cfg[:m.start()] + pre + new_block + accounter + cfg[m.end():]

# Figure out which groups to sync. Under -g (only_group) mode, just that
# one. Otherwise walk every group that either has a tacctl rule list OR
# has a commands: block in tacquito.yaml today.
if only_group:
    groups_to_sync = [only_group]
else:
    tacquito_groups = set(re.findall(r'^(\w+): &\1\n  name: \1\n', cfg, re.MULTILINE))
    groups_to_sync = sorted(set(commands.keys()) | tacquito_groups)

new_cfg = cfg
for g in groups_to_sync:
    rules = commands.get(g) or []
    new_cfg = splice_group(new_cfg, g, render_block(rules))

# Normalize runs of blank lines the splicing might leave behind.
new_cfg = re.sub(r'\n{3,}', '\n\n', new_cfg)

if new_cfg == cfg:
    sys.exit(0)

tmp = tempfile.NamedTemporaryFile('w', dir=os.path.dirname(cfg_path) or '.', delete=False)
tmp.write(new_cfg)
tmp.close()
os.chmod(tmp.name, 0o640)
os.rename(tmp.name, cfg_path)
PY
    chown tacquito:tacquito "$CONFIG" 2>/dev/null || true
}

# --- The daemon's config: seeding, syncing, and the move into the store ---
#
# Users, groups, scopes and filters live in the store and tacquito.yaml is
# rendered from it. A fresh install is created that way (install_seed_config).
# An install from before the store still has a tacquito.yaml that is its own
# source of truth; upgrade moves it into the store through a gate
# (upgrade_store_flip) and otherwise leaves it exactly as it is.

# The daemon runs as the 'tacquito' user and must be able to read its config.
# The renderer's own chown is best-effort because the test suite runs
# unprivileged; install and upgrade run as root, where a failure is real.
config_service_access() {
    [[ $EUID -eq 0 && -f "$CONFIG" ]] || return 0
    chown tacquito:tacquito "$CONFIG" && chmod 640 "$CONFIG"
}

# Set by config_sync_existing: 1 when it changed the rendered tacquito.yaml,
# so the caller knows the daemon has to be restarted.
CONFIG_SYNC_RENDERED=0

# config_sync_existing: bring an existing install's config in line with this
# release. Idempotent; run by every upgrade (the 'config' phase, after the
# build and the scripts pull) before the store gate looks at the config.
#
# Without a store, these are the in-place migrations of the legacy
# tacquito.yaml that upgrades have always run. They must stay ahead of the
# store gate: it judges the file as they leave it.
#
# With a store the legacy migrations are no-ops and the config is re-rendered
# (a new release can ship new default command rules). One case gets finished
# here: a store beside a tacquito.yaml tacctl never rendered -- an upgrade
# interrupted between writing the store and rendering, or a manual
# 'tacctl store import'. When the render passes what the gate asks for
# (equivalent to that file, and the daemon loads it) it replaces the file;
# when it does not, the file is the operator's to resolve and is left alone.
config_sync_existing() {
    CONFIG_SYNC_RENDERED=0
    # Pre-unified-commands installs kept operator-customized commands:
    # blocks in tacquito.yaml; scrape those back into tacctl.yaml as
    # overrides (idempotent: no-op once scraped).
    conf_migrate_command_rules
    # tacctl <= 0.1.10 shipped match regexes that repeated the command word
    # (`^show .*$`); tacquito tests match against the arguments only, so
    # operator/readonly users were denied every `show`. Heal overrides that
    # still carry that shape.
    conf_migrate_dead_command_matches
    # Legacy installs named the Cisco exec service `name: exec`; devices request
    # `service=shell`, so authorization silently failed post-auth. Heal in place.
    conf_migrate_exec_service_name
    if [[ ! -f "$STORE_FILE" ]]; then
        # The legacy migrations edit tacquito.yaml in place; the daemon only
        # needs a restart when they changed it.
        local sum_before
        sum_before=$(sha256sum "$CONFIG" 2>/dev/null | awk '{print $1}')
        regenerate_tacquito_commands
        if [[ "$(sha256sum "$CONFIG" 2>/dev/null | awk '{print $1}')" != "$sum_before" ]]; then
            CONFIG_SYNC_RENDERED=1
        fi
        return 0
    fi

    local force=() result rc=0
    rendered_check "$CONFIG" > /dev/null || rc=$?
    if (( rc == 3 )); then
        if ! ( _config_render_is_proven ); then
            warn "${CONFIG} was not rendered by tacctl, and what the store renders is not proven equivalent to it; it was left as it is."
            warn "To keep what the file says: 'tacctl store import --replace', then 'tacctl config render --force'."
            warn "To replace it with the store's content: 'tacctl config render --force'."
            return 0
        fi
        info "${CONFIG} is equivalent to what the store renders; replacing it with the rendered file."
        force=(--force)
    fi
    rc=0
    result=$(tacacs_render_apply "${force[@]}") || rc=$?
    if (( rc != 0 )); then
        warn "tacquito.yaml was not re-rendered; run 'tacctl config render' once the problem above is fixed."
    elif [[ "$result" == "CHANGED" ]]; then
        CONFIG_SYNC_RENDERED=1
    fi
    return 0
}

# Run in a subshell (it owns a temp dir holding a rendered config): succeeds
# when what the store renders is equivalent to the live tacquito.yaml and the
# daemon loads it. As at the gate, a load-smoke that cannot run is not a pass.
_config_render_is_proven() {
    local tmpd
    tmpd=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064  # expand tmpd now; the subshell owns this trap
    trap "rm -rf '${tmpd}'" EXIT
    _tacacs_render_live "${tmpd}/tacquito.yaml" > /dev/null || exit 1
    store_equiv_check "$CONFIG" "${tmpd}/tacquito.yaml" > /dev/null 2>&1 || exit 1
    store_smoke_hook "${tmpd}/tacquito.yaml" || exit 1
    exit 0
}

# upgrade_store_flip: move a legacy install into the store, if and only if
# that is proven not to change what the daemon does.
#   return 0   flipped: store written, tacquito.yaml rendered from it and
#              recorded. The caller restarts the daemon.
#          10  nothing to do: a store exists. It is never re-imported.
#          20  stopped: nothing was changed, the install stays in legacy
#              read-only mode, the daemon must not be restarted on our account.
#
# The gate is 'tacctl store import --check': import, validate, render,
# equivalence with the live file, and the daemon loading the rendered file.
# Only its "proven" verdict (exit 0) passes; a failed check (1) and a clean
# import whose equivalence was not proven (3) both stop. So does a missing
# daemon binary: the check would skip the load-smoke and still report
# success, and an upgrade always has the binary it just built or kept.
# Nothing is forced and the legacy file is not rewritten to make it pass.
#
# Order after the gate, and what an interruption leaves behind:
#   1. the legacy file is kept as backups/legacy/tacquito.yaml.pre-store.<ts>
#      (interrupted here: still legacy mode; the next run reuses the copy);
#   2. the store is written (interrupted here: store mode with the legacy
#      file still live and equivalent; config_sync_existing finishes the
#      render on the next upgrade, and so does any mutating command);
#   3. tacquito.yaml is rendered and its checksum recorded;
#   4. the installed file is compared with the kept one once more. If 3 or 4
#      fails the store is removed again and the legacy file is live as before.
upgrade_store_flip() {
    if [[ -f "$STORE_FILE" ]]; then
        return 10
    fi
    echo ""
    info "Store migration: ${STORE_FILE} does not exist yet."
    if [[ ! -f "$CONFIG" ]]; then
        _upgrade_flip_stopped "there is no ${CONFIG} to import"
        return 20
    fi
    if [[ ! -x "$TACQUITO_BIN" ]] || ! command -v timeout > /dev/null 2>&1; then
        _upgrade_flip_stopped "the daemon load-smoke cannot run (${TACQUITO_BIN} or 'timeout' is missing), so the rendered config cannot be proven to load"
        return 20
    fi

    info "Checking that ${CONFIG} can move into the store without changing what tacquito does (the check writes nothing)..."
    local rc=0
    store_import --check || rc=$?
    case "$rc" in
        0) ;;
        3)
            _upgrade_flip_stopped "the import is clean but its equivalence with ${CONFIG} was not proven"
            return 20
            ;;
        *)
            _upgrade_flip_stopped "the check above did not pass"
            return 20
            ;;
    esac

    info "Gate passed: writing the store and rendering ${CONFIG} from it..."
    # The report was printed by the check; errors still reach stderr.
    if ! store_import > /dev/null; then
        _upgrade_flip_stopped "the import failed after a clean check"
        return 20
    fi
    local pre
    if ! pre=$(store_pre_store_latest); then
        rm -f "$STORE_FILE"
        _model_invalidate
        _upgrade_flip_stopped "the pre-store copy of ${CONFIG} is missing"
        return 20
    fi
    # --force, deliberately: this is the first render over a file tacctl
    # never rendered, and that file is the pre-store copy just kept.
    if ! tacacs_render_apply --force > /dev/null; then
        _store_unflip "$pre" || true
        _upgrade_flip_stopped "${CONFIG} could not be rendered from the store (the store was removed again)"
        return 20
    fi
    if ! store_equiv_check "$pre" "$CONFIG" > /dev/null 2>&1; then
        _store_unflip "$pre" || true
        _upgrade_flip_stopped "the rendered ${CONFIG} was not equivalent to the file it replaced (that file is back and the store was removed again)"
        return 20
    fi
    config_service_access \
        || warn "Could not make ${CONFIG} readable by the tacquito service user (expected tacquito:tacquito, 0640); fix that before the service restarts."

    info "Store migration complete: users, groups, scopes and filters now live in ${STORE_FILE}."
    info "  ${CONFIG} is rendered from the store; change it with tacctl commands."
    info "  'tacctl store rollback' returns to the kept pre-store file."
    return 0
}

# Said when the daemon does not come back after an upgrade that flipped.
_upgrade_flip_hint() {
    [[ "$1" == "flipped" ]] || return 0
    error "This upgrade moved the configuration into the store. If the rendered ${CONFIG} is the cause, 'tacctl store rollback' restores the previous file."
}

_upgrade_flip_stopped() {
    echo ""
    warn "Store migration stopped: $1."
    warn "${CONFIG} and the running daemon were left as they are."
    warn "tacctl stays in legacy read-only mode: read commands work; commands that change users, groups, scopes or filters are refused."
    warn "To proceed: 'tacctl store import --check' prints the report again. Fix what it lists in ${CONFIG} and run 'tacctl upgrade' again,"
    warn "or accept the difference yourself: 'tacctl store import' (--force drops what the store cannot hold), then 'tacctl config render --force'."
    echo ""
}

# --- Rollback of the move into the store (plan 4.4) -------------------------
# The pre-store copy itself is kept by the importer (lib/store.sh:
# store_keep_pre_store, store_pre_store_latest).

# _store_unflip <pre-store-file>: make <pre-store-file> the live tacquito.yaml
# again (0640, tacquito:tacquito when possible; left alone when it already
# says the same, byte for byte) and remove the store and the render records.
# The config goes back first: if that fails nothing was removed. No snapshot,
# no restart -- callers do those.
_store_unflip() {
    local pre="$1" staged="${CONFIG}.tacctl-new"
    if ! cmp -s "$pre" "$CONFIG"; then
        cp "$pre" "$staged" || { rm -f "$staged"; return 1; }
        chmod 640 "$staged"
        chown tacquito:tacquito "$staged" 2>/dev/null || true
        mv -f "$staged" "$CONFIG" || { rm -f "$staged"; return 1; }
    fi
    rm -f "$STORE_FILE" "$RENDERED_FILE" || return 1
    _model_invalidate
}

# tacctl store rollback
# Returns 0 rolled back (or cancelled at the prompt); 1 refused or failed,
# with the store untouched; 2 usage.
cmd_store_rollback() {
    if (( $# )); then
        error "Usage: tacctl store rollback"
        return 2
    fi
    if [[ ! -f "$STORE_FILE" ]]; then
        error "There is no store at ${STORE_FILE}: this install is already in legacy read-only mode. Nothing to roll back."
        return 1
    fi
    # Legacy mode is TACACS+ only: with another backend enabled, the rollback
    # would leave it serving a store that is gone.
    local _b others=""
    _backends_load || return 1
    for _b in "${BACKENDS_ENABLED[@]}"; do
        [[ "$_b" == "tacacs" ]] || others+="${others:+, }${_b}"
    done
    if [[ -n "$others" ]]; then
        error "Backend(s) ${others} are enabled, and legacy mode (what a rollback returns to) serves TACACS+ only."
        error "Disable them first ('tacctl backend disable <id>'). Nothing was changed."
        return 1
    fi
    local pre
    if ! pre=$(store_pre_store_latest); then
        error "No pre-store config (tacquito.yaml.pre-store.<timestamp>) under ${BACKUP_DIR}/legacy/: there is nothing to roll back to."
        error "A fresh install starts with its store and never had a legacy tacquito.yaml. The store was left untouched."
        return 1
    fi
    # Legacy mode reads everything from this file; one the loader cannot
    # read would leave tacctl without a model.
    if ! _store_python dump-legacy "$pre" "$PASSWORD_DATES_DIR" "${BACKUP_DIR}/disabled" > /dev/null; then
        error "${pre} cannot be read as a tacquito.yaml. Nothing was changed."
        return 1
    fi

    echo ""
    echo -e "${BOLD}Roll back to the pre-store configuration${NC}"
    echo ""
    echo "  This restores ${pre}"
    echo "  as ${CONFIG}, removes ${STORE_FILE} and the render records,"
    echo "  and restarts the service. tacctl is then in legacy read-only mode: read commands"
    echo "  work, commands that change users, groups, scopes or filters are refused."
    echo "  The store is snapshotted first (see 'tacctl backup list')."
    if ! _tacacs_matches_store "$pre"; then
        echo ""
        warn "The store no longer says what the pre-store file says: users, groups, scopes or filters changed since the import."
        warn "Those changes stop being in effect. They stay in the snapshot, not in ${CONFIG}."
    fi
    echo ""
    local confirm
    read -rp "  Roll back? [y/N]: " confirm || true
    if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
        info "Cancelled."
        return 0
    fi

    backup_snapshot || { error "Could not snapshot the store. Nothing was changed."; return 1; }
    # A rendered config somebody edited by hand is not in the snapshot.
    if [[ -f "$CONFIG" ]] && ! rendered_check "$CONFIG" > /dev/null; then
        _tacacs_save_displaced "$CONFIG" || { error "Could not keep a copy of ${CONFIG}. Nothing was changed."; return 1; }
    fi
    if ! _store_unflip "$pre"; then
        error "Rollback failed: ${CONFIG} could not be replaced. The store was left untouched."
        return 1
    fi
    backend_tacacs_service restart
    info "Rolled back: ${CONFIG} is the pre-store file again and the store is gone (legacy read-only mode)."
    info "To move to the store again: 'tacctl store import --check', then 'tacctl upgrade' (or 'tacctl store import' and 'tacctl config render --force')."
    echo ""
}

# =====================================================================
#  BUILD, INSTALL, UPGRADE, UNINSTALL
# =====================================================================

# --- tacquito source patch overlay (see patches/README.md) ---
# tacquito is built from an upstream checkout; behaviors we depend on but that
# are not upstream live as git-apply diffs in $PATCH_DIR and are re-applied
# after every upstream pull so they survive updates.

# tacquito_patches_applied succeeds only when EVERY patch is already applied to
# the working tree (reverse-check). Lets an upgrade that found no upstream change
# still decide to rebuild when a newly-shipped patch isn't in the binary yet.
# No patches at all counts as satisfied.
tacquito_patches_applied() {
    local patch
    shopt -s nullglob
    for patch in "$PATCH_DIR"/*.patch; do
        if ! git -C "$TACQUITO_SRC" apply --reverse --check "$patch" 2>/dev/null; then
            shopt -u nullglob
            return 1
        fi
    done
    shopt -u nullglob
    return 0
}

# apply_tacquito_patches applies every patch in $PATCH_DIR onto the tacquito
# source tree. Callers run `git checkout -- .` before the upstream pull, so the
# tree is pristine upstream when we apply. Idempotent: an already-applied patch
# (reverse-check passes) is skipped. Aborts the run if a patch will not apply
# (upstream drift) rather than silently building an unpatched binary. Returns 0
# if it applied at least one patch, 1 if there was nothing to do.
apply_tacquito_patches() {
    [[ -d "$PATCH_DIR" ]] || return 1
    local patch applied=0
    shopt -s nullglob
    for patch in "$PATCH_DIR"/*.patch; do
        if git -C "$TACQUITO_SRC" apply --reverse --check "$patch" 2>/dev/null; then
            continue  # already applied
        fi
        if ! git -C "$TACQUITO_SRC" apply --check "$patch" 2>/dev/null; then
            shopt -u nullglob
            error "tacquito patch will not apply cleanly: $(basename "$patch")."
            error "Upstream likely changed the patched file; refresh the diff in patches/."
            exit 1
        fi
        git -C "$TACQUITO_SRC" apply "$patch"
        info "Applied tacquito patch: $(basename "$patch")"
        applied=$((applied + 1))
    done
    shopt -u nullglob
    [[ $applied -gt 0 ]]
}

# install_readme <src>: put README.md in the config directory, readable by
# everyone (the script's umask would leave it 0600). No-op without <src>.
install_readme() {
    local src="$1" dest="${CONFIG_DIR}/README.md"
    [[ -f "$src" ]] || return 0
    cp "$src" "$dest" && chmod 644 "$dest"
}

# The steps of 'tacctl install', 'upgrade' and 'uninstall' that are
# tacquito's, as the phases of the contract (lib/backend.sh). Each is the
# block the command used to carry inline. <tree> is the tacctl checkout the
# shipped files come from.

# install build: Go, the tacquito checkout with the patch overlay, the binaries.
_tacacs_install_build() {
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
        cd "$TACQUITO_SRC"
        # Drop any previously-applied source patches so the pull stays clean.
        git checkout -- . 2>/dev/null || true
        git pull --quiet
    else
        info "Cloning tacquito..."
        git clone --quiet "$TACQUITO_REPO" "$TACQUITO_SRC"
    fi

    # Re-apply our source patch overlay on top of pristine upstream (see
    # patches/README.md). Aborts on a patch that no longer applies.
    apply_tacquito_patches || true

    info "Building tacquito server..."
    cd "${TACQUITO_SRC}/cmds/server"
    go build -o "$TACQUITO_BIN" .

    info "Building password hash generator..."
    cd "${TACQUITO_SRC}/cmds/server/config/authenticators/bcrypt/generator"
    go build -o "$HASHGEN_BIN" .

    # go build honors umask (often 022 → 755), but stricter umask settings
    # (077) or existing 700 binaries from prior builds leave the tacquito
    # binary unreadable/unexecutable by the service user. Pin 755 so
    # systemd's User=tacquito can always exec.
    chmod 755 "$TACQUITO_BIN" "$HASHGEN_BIN"

    info "Binaries installed:"
    info "  Server:  ${TACQUITO_BIN}"
    info "  Hashgen: ${HASHGEN_BIN}"
    ensure_safe_directory "$TACQUITO_SRC"
}

# install files <tree>
_tacacs_install_files() {
    local PROJECT_DIR="$1"
    # Install logrotate config
    if [[ -f "${PROJECT_DIR}/${TACACS_SHARE}/tacquito.logrotate" ]]; then
        cp "${PROJECT_DIR}/${TACACS_SHARE}/tacquito.logrotate" /etc/logrotate.d/tacquito
        info "Log rotation installed: /etc/logrotate.d/tacquito"
    fi
}

# install account <tree>: service user, config and log directories, README.
_tacacs_install_account() {
    local PROJECT_DIR="$1"
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
    install_readme "${PROJECT_DIR}/README.md" || warn "Could not install ${CONFIG_DIR}/README.md."
}

# install start <tree>: after the first render. Unit, enable, start, verify.
_tacacs_install_start() {
    local PROJECT_DIR="$1" CONFIG_FILE="$CONFIG"
    if ! config_service_access; then
        error "Could not make ${CONFIG_FILE} readable by the tacquito service user."
        exit 1
    fi

    # --- Step 7: Install systemd service ---
    # The unit, the template for further listeners and the drop-ins; over an
    # earlier install this is the same conversion as on upgrade.
    info "Installing systemd service..."
    if ! _tacacs_units_install "$PROJECT_DIR"; then
        error "Could not install the systemd units (see above)."
        exit 1
    fi
    _tacacs_units_keep_discard
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
    _tacacs_instances_sync

    # --- Step 9: Verify ---
    _tacacs_listen_check
}

# Is the default listener's port open? Said after a start or a restart.
_tacacs_listen_check() {
    local _name _net addr port
    read -r _name _net addr < <(_tacacs_listener_lines)
    port="${addr##*:}"
    if [[ -n "$(ss -tlnp | grep ":${port} " || true)" ]]; then
        info "Listening on port ${port}/tcp"
    else
        warn "Port ${port} not detected — check logs."
    fi
}

# --- The units on disk: install, upgrade, conversion ---
#
# _tacacs_units_install <tree>: bring the unit files and drop-ins of this
# machine to what this release ships and what tacctl.yaml says. One function
# for a fresh install, an upgrade and the conversion of an install from
# before the listener model; idempotent, and it needs no store.
#
#   1. copies   everything it may touch is copied first (_tacacs_units_keep)
#   2. import   the settings of the old layout go into tacctl.yaml: the
#               hand-managed drop-in (_tacacs_legacy_import) and, for units
#               older still, literal -network/-address/-level flags
#   3. stage    the drop-ins are rendered from tacctl.yaml and proven
#               (_tacacs_units_stage): a listener model that cannot be
#               served stops here
#   4. files    tacquito.service, tacquito@.service, the drop-ins; then the
#               hand-managed drop-in is retired; daemon-reload
#
# The running daemon is not touched: systemd keeps the process it started
# until the caller restarts the unit, and that restart is the whole
# authentication gap. Until step 4 nothing systemd reads has changed. A
# failure in 2-4 puts every file back from the copies (and reloads), so the
# old unit keeps running under the old files.
#
# What an interruption leaves, and why a re-run converges: the hand-managed
# drop-in is removed last, and for as long as it exists it is what every
# reader shows and what step 2 imports again, so a run that died anywhere
# before that repeats from the start with the same result; the unit files
# and drop-ins are written by rename and compared before they are written,
# so a second pass over finished work changes nothing. A reload that never
# happened is caught by asking systemd (NeedDaemonReload).
#
# Sets TACACS_UNITS_STATE: '' nothing to do, 'changed', or 'stopped'
# (refused or failed, files as they were; returns 1). After 'changed' the
# copies stay in TACACS_UNITS_KEEP until the caller has restarted the unit:
# _tacacs_units_keep_discard when it came up, _tacacs_units_rollback when it
# did not.
TACACS_UNITS_STATE=""
TACACS_UNITS_KEEP=""
# What _tacacs_units_install did, one line each, for the caller to print.
TACACS_UNITS_NOTES=()

_tacacs_units_install() {
    local tree="$1" src keep f dest legacy=0 changed=0 why=""
    src="${tree}/${TACACS_SHARE}"
    TACACS_UNITS_STATE=""
    TACACS_UNITS_KEEP=""
    TACACS_UNITS_NOTES=()
    if [[ ! -f "${src}/tacquito.service" || ! -f "${src}/tacquito@.service" ]]; then
        _tacacs_units_stopped "the unit files are not under ${src}"
        return 1
    fi
    if ! _tacacs_overrides_readable; then
        _tacacs_units_stopped "${TACCTL_OVERRIDES_FILE} cannot be read"
        return 1
    fi

    mkdir -p "$TACCTL_STATE_DIR" "$TACACS_UNIT_DIR" || return 1
    # Copies an interrupted run left behind.
    rm -rf "${TACCTL_STATE_DIR}"/.units.* 2>/dev/null || true
    keep=$(mktemp -d "${TACCTL_STATE_DIR}/.units.XXXXXX") || return 1
    if ! _tacacs_units_keep "${keep}/keep"; then
        rm -rf "$keep"
        _tacacs_units_stopped "the current unit files could not be copied"
        return 1
    fi

    _tacacs_units_legacy && legacy=1
    if ! _tacacs_units_import_old; then
        why="its settings could not be moved into ${TACCTL_OVERRIDES_FILE}"
    elif ! _tacacs_units_stage "$keep"; then
        why="the drop-ins could not be rendered from ${TACCTL_OVERRIDES_FILE}"
    fi
    if [[ -n "$why" ]]; then
        _tacacs_units_restore "${keep}/keep"
        rm -rf "$keep"
        _tacacs_units_stopped "$why"
        return 1
    fi

    for f in tacquito.service "tacquito@.service"; do
        dest="${TACACS_UNIT_DIR}/${f}"
        cmp -s "${src}/${f}" "$dest" && continue
        if [[ "$f" == "tacquito.service" && -f "$dest" ]]; then
            cp "$dest" "${dest}.bak" || why="${dest} could not be backed up"
            TACACS_UNITS_NOTES+=("Updated: ${f} (previous backed up to ${dest}.bak)")
        elif [[ -f "$dest" ]]; then
            TACACS_UNITS_NOTES+=("Updated: ${f}")
        else
            TACACS_UNITS_NOTES+=("Installed: ${f}")
        fi
        if [[ -z "$why" ]] && cp "${src}/${f}" "${dest}.tacctl-new" \
            && chmod 644 "${dest}.tacctl-new" && mv -f "${dest}.tacctl-new" "$dest"; then
            changed=1
        else
            rm -f "${dest}.tacctl-new"
            why="${why:-${dest} could not be written}"
            break
        fi
    done

    local written=""
    if [[ -z "$why" ]]; then
        if written=$(_tacacs_units_commit "$keep"); then
            if [[ -n "$written" ]]; then
                changed=1
                TACACS_UNITS_NOTES+=("Rendered: the listener drop-in of ${written//$'\n'/, }")
            fi
        else
            why="a drop-in could not be installed"
        fi
    fi
    if [[ -z "$why" ]] && (( legacy )); then
        if _tacacs_legacy_retire; then
            changed=1
        else
            why="${OVERRIDE_FILE} could not be retired"
        fi
    fi
    if [[ -n "$why" ]]; then
        _tacacs_units_restore "${keep}/keep"
        rm -rf "$keep"
        systemctl daemon-reload || true
        _tacacs_units_stopped "$why"
        return 1
    fi

    if (( changed )) || [[ "$(systemctl show tacquito --property=NeedDaemonReload 2>/dev/null | cut -d= -f2)" == "yes" ]]; then
        systemctl daemon-reload
    fi
    if (( changed )); then
        TACACS_UNITS_STATE="changed"
        TACACS_UNITS_KEEP="$keep"
    else
        rm -rf "$keep"
    fi
    return 0
}

# Step 2 of _tacacs_units_install.
_tacacs_units_import_old() {
    if _tacacs_units_legacy; then
        _tacacs_legacy_import || return 1
    fi
    # Units from before the drop-in carried the flags as literals in
    # ExecStart; today's take them from the environment (${TACQUITO_*}).
    # A literal that differs from the default and that tacctl.yaml does not
    # already set is kept.
    [[ -f "$SERVICE_FILE" ]] || return 0
    # `grep | head` under pipefail + set -e: when grep finds nothing it exits
    # 1. `|| true` on each keeps this best-effort.
    local mig_net mig_addr mig_level
    mig_net=$(grep -oP '\-network \K\S+' "$SERVICE_FILE" 2>/dev/null | head -1 || true)
    mig_addr=$(grep -oP '\-address \K\S+' "$SERVICE_FILE" 2>/dev/null | head -1 || true)
    mig_level=$(grep -oP '\-level \K\d+' "$SERVICE_FILE" 2>/dev/null | head -1 || true)
    [[ "$mig_net" == \$* ]] && mig_net=""
    [[ "$mig_addr" == \$* ]] && mig_addr=""
    if [[ -n "${mig_net}${mig_addr}" && "${mig_net:-tcp} ${mig_addr:-:49}" != "tcp :49" ]] \
        && ! conf_has_override listeners.tacacs.default; then
        conf_set_json listeners.tacacs.default \
            "$(printf '{"network": "%s", "address": "%s"}' "${mig_net:-tcp}" "${mig_addr:-:49}")" || return 1
        info "  Migrated custom -network/-address flags of tacquito.service to ${TACCTL_OVERRIDES_FILE}"
    fi
    if [[ -n "$mig_level" && "$mig_level" != "$TACACS_LEVEL_DEFAULT" ]] \
        && ! conf_has_override backends.tacacs.level; then
        conf_set backends.tacacs.level "$mig_level" || return 1
        info "  Migrated the custom -level flag of tacquito.service to ${TACCTL_OVERRIDES_FILE}"
    fi
    return 0
}

_tacacs_units_stopped() {
    TACACS_UNITS_STATE="stopped"
    echo ""
    warn "Unit update stopped: $1."
    warn "tacquito.service, its drop-in and the running daemon were left as they are; ${TACCTL_OVERRIDES_FILE} is unchanged."
    warn "Listener, log level and metrics settings keep working from the files in place. Fix what is reported above and run 'tacctl upgrade' again."
    echo ""
}

# The restart proved the new unit files: drop the copies.
_tacacs_units_keep_discard() {
    [[ -n "$TACACS_UNITS_KEEP" ]] && rm -rf "$TACACS_UNITS_KEEP"
    TACACS_UNITS_KEEP=""
    return 0
}

# The unit did not come up under the new files: put the previous ones back
# (unit, template, drop-ins, tacctl.yaml, render records) and reload. The
# caller restarts.
_tacacs_units_rollback() {
    [[ -n "$TACACS_UNITS_KEEP" ]] || return 1
    _tacacs_units_restore "${TACACS_UNITS_KEEP}/keep"
    _tacacs_units_keep_discard
    systemctl daemon-reload || true
    return 0
}

# State the upgrade phases share: set by 'build', read by 'finish'.
SKIP_BUILD=""
CURRENT_COMMIT=""
NEW_COMMIT=""

# upgrade preflight: nothing is touched when the build cannot run.
_tacacs_upgrade_preflight() {
    if [[ ! -d "$TACQUITO_SRC" ]]; then
        error "Tacquito source not found at ${TACQUITO_SRC}. Run 'tacctl install' first."
        exit 1
    fi

    if [[ ! -x "$GO_BIN" ]]; then
        error "Go not found at ${GO_BIN}. Install Go first."
        exit 1
    fi

    export PATH=$PATH:/usr/local/go/bin
    ensure_safe_directory "$TACQUITO_SRC"
}

# upgrade build: pull tacquito, rebuild when upstream or the patch overlay moved.
_tacacs_upgrade_build() {
    # --- Record current version ---
    CURRENT_COMMIT=$(cd "$TACQUITO_SRC" && git rev-parse --short HEAD)
    info "Current commit: ${CURRENT_COMMIT}"

    # --- Pull latest source ---
    info "Pulling latest source..."
    cd "$TACQUITO_SRC"
    git fetch --quiet
    local LOCAL REMOTE
    # Default to the current commit so the summary is always defined even when a
    # rebuild is driven by a patch overlay change rather than an upstream pull.
    NEW_COMMIT="$CURRENT_COMMIT"
    LOCAL=$(git rev-parse HEAD)
    REMOTE=$(git rev-parse '@{u}')

    # Rebuild when upstream advanced, OR a shipped source patch isn't applied
    # yet (a new patch can land with unchanged upstream), OR the binary is
    # missing. patches/ lives in the management repo; on an upgrade that ships a
    # new patch, tacctl self-updates and re-execs (below) before reaching here,
    # so PATCH_DIR is current by this point.
    if [[ "$LOCAL" == "$REMOTE" ]] && tacquito_patches_applied && [[ -f "$TACQUITO_BIN" ]]; then
        info "Tacquito source already up to date (${CURRENT_COMMIT}); patches applied."
        SKIP_BUILD=true
    else
        SKIP_BUILD=false
        if [[ -f "$TACQUITO_BIN" ]]; then
            cp "$TACQUITO_BIN" "${TACQUITO_BIN}.bak"
            info "Backed up current binary to ${TACQUITO_BIN}.bak"
        fi
    fi

    if [[ "$SKIP_BUILD" == "false" ]]; then
        # Drop previously-applied patches so the pull is clean, then rebuild from
        # pristine upstream + our patch overlay (see patches/README.md).
        git checkout -- . 2>/dev/null || true
        if [[ "$LOCAL" != "$REMOTE" ]]; then
            git pull --quiet
            NEW_COMMIT=$(git rev-parse --short HEAD)
            info "Updated: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"

            echo ""
            info "Changes:"
            git log --oneline "${CURRENT_COMMIT}..${NEW_COMMIT}" | head -20
            echo ""
        fi
        apply_tacquito_patches || true

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

        # Same rationale as install: pin 755 so the service user can exec.
        chmod 755 "$TACQUITO_BIN"
        [[ -x "$HASHGEN_BIN" ]] && chmod 755 "$HASHGEN_BIN"
    fi
}

# The units and drop-ins on upgrade (_tacacs_units_install, which also
# converts an install from before the listener model): report, and count in
# SCRIPTS_UPDATED. 'finish' restarts when TACACS_UNITS_STATE is 'changed'. A unit update that stops is not
# an upgrade failure: the files in place keep working, and the summary says so.
_tacacs_upgrade_units() {
    local note
    _tacacs_units_install "$1" || true
    case "$TACACS_UNITS_STATE" in
        changed)
            for note in ${TACACS_UNITS_NOTES[@]+"${TACACS_UNITS_NOTES[@]}"}; do
                info "  ${note}"
            done
            SCRIPTS_UPDATED=$((SCRIPTS_UPDATED + 1))
            ;;
        stopped)
            UPGRADE_SUMMARY_NOTES+=("Units: NOT updated — the previous unit files are in place (see 'Unit update stopped' above)")
            ;;
        *)
            info "  Unchanged: tacquito.service"
            ;;
    esac
}

# upgrade files <tree>: the units, README.md in the config directory,
# logrotate. Counts what it replaced in SCRIPTS_UPDATED.
_tacacs_upgrade_files() {
    local ACTIVE_DEPLOY_DIR="$1"
    _tacacs_upgrade_units "$ACTIVE_DEPLOY_DIR"

    update_if_changed "${ACTIVE_DEPLOY_DIR}/README.md" "${CONFIG_DIR}/README.md" "README.md"
    # Installs before the README fix have it 0600 root, or not at all.
    chmod 644 "${CONFIG_DIR}/README.md" 2>/dev/null || true
    update_if_changed "${ACTIVE_DEPLOY_DIR}/${TACACS_SHARE}/tacquito.logrotate" "/etc/logrotate.d/tacquito" "logrotate config"
    # Older installs left CONFIG_DIR at 0750, which blocks non-root reads of README.md; normalize to 0755 (sensitive files inside stay 0640).
    chmod 755 "$CONFIG_DIR" 2>/dev/null || true
}

# upgrade finish: the store gate, then one restart for everything this
# upgrade changed, with the binary rolled back if the daemon does not come
# up. Leaves the headline and the store line for the closing summary.
_tacacs_upgrade_finish() {
    # --- Move a legacy install into the store (gated; see upgrade_store_flip) ---
    # Here rather than next to the migrations above, so the gate's load-smoke
    # runs the daemon binary this upgrade leaves in place, and so one restart
    # below covers the new binary and the rendered config. A stop is not an
    # upgrade failure: the code is installed and the daemon keeps its config.
    local STORE_STATE="present" flip_rc=0
    upgrade_store_flip || flip_rc=$?
    case "$flip_rc" in
        0)  STORE_STATE="flipped" ;;
        10) ;;
        *)  STORE_STATE="stopped" ;;
    esac

    # --- Restart service (if the binary, a unit or drop-in, or the config changed) ---
    # Only what the daemon reads counts: a new README, logrotate file, template
    # or completion script is no reason to drop its sessions.
    if [[ "$SKIP_BUILD" == "false" ]] || [[ "${TACACS_UNITS_STATE:-}" == "changed" ]] \
        || [[ "$STORE_STATE" == "flipped" ]] || [[ "$CONFIG_SYNC_RENDERED" == "1" ]]; then
        info "Restarting tacquito service..."
        systemctl restart tacquito.service
        sleep 2

        if systemctl is-active --quiet tacquito.service; then
            info "Tacquito is running."
            rm -f "${TACQUITO_BIN}.bak"
            _tacacs_units_keep_discard
            _tacacs_instances_sync
        else
            # Everything this upgrade replaced under the daemon goes back at
            # once -- unit files with their settings, and the binary -- and
            # one restart follows: the shortest way back to a listener.
            local -a rolled=()
            if _tacacs_units_rollback; then
                error "Tacquito failed to start after upgrade. The previous unit files and settings were restored."
                rolled+=("unit files")
            fi
            if [[ "$SKIP_BUILD" == "false" ]]; then
                error "Tacquito failed to start after upgrade. Rolling back binary..."
                mv "${TACQUITO_BIN}.bak" "$TACQUITO_BIN"
                rolled+=("binary")
            fi
            if (( ${#rolled[@]} )); then
                systemctl restart tacquito.service
                sleep 2
                if systemctl is-active --quiet tacquito.service; then
                    warn "Rolled back to the previous ${rolled[*]}. Service is running."
                else
                    error "Rollback failed. Check: journalctl -u tacquito"
                fi
                _upgrade_flip_hint "$STORE_STATE"
                exit 1
            else
                error "Tacquito failed to start. Check: journalctl -u tacquito"
                _upgrade_flip_hint "$STORE_STATE"
                exit 1
            fi
        fi

        _tacacs_listen_check
    else
        # Nothing to restart for; unit files (if any changed) count as proven.
        _tacacs_units_keep_discard
    fi

    if [[ "$SKIP_BUILD" == "false" && "$CURRENT_COMMIT" != "$NEW_COMMIT" ]]; then
        UPGRADE_SUMMARY_HEAD="Upgrade Complete: ${CURRENT_COMMIT} -> ${NEW_COMMIT}"
    elif [[ "$SKIP_BUILD" == "false" ]]; then
        UPGRADE_SUMMARY_HEAD="Upgrade Complete: rebuilt at ${CURRENT_COMMIT} (patch overlay refreshed)"
    else
        UPGRADE_SUMMARY_HEAD="Scripts Updated (source unchanged at ${CURRENT_COMMIT})"
    fi
    if [[ "$TACACS_UNITS_STATE" == "changed" ]]; then
        UPGRADE_SUMMARY_NOTES+=("Units: tacquito.service and its listener drop-in are current (settings in ${TACCTL_OVERRIDES_FILE})")
    fi
    case "$STORE_STATE" in
        flipped) UPGRADE_SUMMARY_NOTES+=("Store: migrated from tacquito.yaml ('tacctl store rollback' undoes it)") ;;
        stopped) UPGRADE_SUMMARY_NOTES+=("Store: NOT migrated — legacy read-only mode (see 'Store migration stopped' above)") ;;
    esac
}

# The instance units this machine knows of, one per line: from the drop-in
# directories and from the links 'systemctl enable' made.
_tacacs_instance_units() {
    local f
    for f in "$TACACS_UNIT_DIR"/tacquito@*.service.d \
             "$TACACS_UNIT_DIR"/tacquito.service.wants/tacquito@*.service \
             "$TACACS_UNIT_DIR"/multi-user.target.wants/tacquito@*.service; do
        [[ -e "$f" || -L "$f" ]] || continue
        f="${f##*/}"
        echo "${f%.d}"
    done | sort -u
}

# uninstall stop: every listener's unit. An install from before the listener
# model has only tacquito.service.
_tacacs_uninstall_stop() {
    # --- Stop and disable service ---
    local unit
    while IFS= read -r unit; do
        [[ -n "$unit" ]] || continue
        info "Stopping ${unit}..."
        systemctl disable --quiet --now "$unit" 2>/dev/null || true
    done < <(_tacacs_instance_units)
    if systemctl is-active --quiet tacquito 2>/dev/null; then
        info "Stopping tacquito service..."
        systemctl stop tacquito
    fi
    if systemctl is-enabled --quiet tacquito 2>/dev/null; then
        systemctl disable tacquito 2>/dev/null || true
    fi
}

# uninstall program: binaries (silently, under the generic step's message), then the units.
_tacacs_uninstall_program() {
    rm -f /usr/local/bin/tacquito
    rm -f /usr/local/bin/tacquito.bak
    rm -f /usr/local/bin/tacquito-hashgen

    # --- Remove systemd unit ---
    info "Removing systemd unit..."
    _tacacs_uninstall_units
}

# Remove every unit file, drop-in directory and enablement link of either
# layout: tacquito.service with the hand-managed drop-in (before the listener
# model), or with the rendered one plus the template and its instances.
_tacacs_uninstall_units() {
    local dir="${TACACS_UNIT_DIR:?}"
    rm -f "$SERVICE_FILE" "${SERVICE_FILE}.bak" "$TEMPLATE_FILE"
    rm -rf "${OVERRIDE_DIR:?}" "${dir}/tacquito.service.d" "${dir}/tacquito.service.wants"
    rm -rf "${dir}"/tacquito@*.service.d
    rm -f "${dir}"/multi-user.target.wants/tacquito@*.service "${dir}/multi-user.target.wants/tacquito.service"
    systemctl daemon-reload
}

# uninstall data [--keep-logs]: logrotate config, the config directory, the logs.
_tacacs_uninstall_data() {
    local PRESERVE_LOGS=false LOG_ARCHIVE=""
    if [[ "${1:-}" == "--keep-logs" ]]; then
        PRESERVE_LOGS=true
    fi
    rm -f /etc/logrotate.d/tacquito
    # rm -rf does not follow the compatibility symlinks left in /etc/tacquito.
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
    if [[ -n "$LOG_ARCHIVE" ]]; then
        UNINSTALL_SAVED+=("Accounting logs saved to: ${LOG_ARCHIVE}")
    fi
}

# uninstall account: the source checkout's safe.directory entry, the service user.
_tacacs_uninstall_account() {
    git config --system --unset-all safe.directory "$(printf '^%s$' "$TACQUITO_SRC")" 2>/dev/null || true

    # --- Remove service user ---
    if id tacquito &>/dev/null; then
        info "Removing tacquito service user..."
        userdel tacquito 2>/dev/null || true
    fi
}

# =====================================================================
#  THE BACKEND CONTRACT (lib/backend.sh)
# =====================================================================

backend_tacacs_describe() {
    printf '%s\n' \
        "protocol=tacacs" \
        "impl=tacquito" \
        "units=$(_tacacs_units_all)" \
        "user=tacquito" \
        "config_dir=${CONFIG_DIR}" \
        "log_dir=${LOG_DIR}" \
        "import_cmd=tacctl store import --replace"
}

# Every listener's unit, space-separated, the default listener's first.
_tacacs_units_all() {
    local name _net _addr out=""
    while read -r name _net _addr; do
        [[ -n "$name" ]] && out+="${out:+ }$(_tacacs_unit "$name")"
    done < <(_tacacs_listener_lines)
    echo "$out"
}

backend_tacacs_installed() {
    [[ -x "$TACQUITO_BIN" && -f "$SERVICE_FILE" ]]
}

backend_tacacs_install() {
    local phase="${1:-}" tree="${2:-}"
    case "$phase" in
        build)   _tacacs_install_build ;;
        files)   _tacacs_install_files "$tree" ;;
        account) _tacacs_install_account "$tree" ;;
        start)   _tacacs_install_start "$tree" ;;
    esac
}

backend_tacacs_upgrade() {
    local phase="${1:-}" tree="${2:-}"
    case "$phase" in
        preflight) _tacacs_upgrade_preflight ;;
        config)    config_sync_existing ;;
        build)     _tacacs_upgrade_build ;;
        files)     _tacacs_upgrade_files "$tree" ;;
        finish)    _tacacs_upgrade_finish ;;
    esac
}

backend_tacacs_uninstall() {
    local phase="${1:-}"
    shift || true
    case "$phase" in
        stop)    _tacacs_uninstall_stop ;;
        program) _tacacs_uninstall_program ;;
        data)    _tacacs_uninstall_data "$@" ;;
        account) _tacacs_uninstall_account ;;
    esac
}

# tacquito.yaml, then the drop-in of every listener. An install that is not
# converted (hand-managed drop-in still in place) has no rendered drop-ins.
backend_tacacs_artifacts() {
    printf '%s\n' "$CONFIG"
    _tacacs_units_legacy && return 0
    local name _net _addr
    while read -r name _net _addr; do
        [[ -n "$name" ]] && _tacacs_dropin "$name"
    done < <(_tacacs_listener_lines)
    return 0
}

backend_tacacs_render_check() {
    if _tacacs_units_legacy; then
        tacacs_render_check
    else
        ( _tacacs_render_check_run units )
    fi
}

backend_tacacs_render_gate() {
    _tacacs_render_gate
}

backend_tacacs_render_stage() {
    local dir="${1:-}" overwrite=0
    case "${2:-}" in
        "")      ;;
        --force) overwrite=1 ;;
        *)
            error "Usage: backend_tacacs_render_stage <dir> [--force]"
            return 1
            ;;
    esac
    if _tacacs_units_legacy; then
        _tacacs_render_stage "$dir" "$overwrite"
    else
        _tacacs_render_stage "$dir" "$overwrite" units
    fi
}

# CHANGED when tacquito.yaml or a drop-in was replaced. systemd is told about
# changed drop-ins here (once there is a unit to reload); the restart that
# makes a process use them is the 'service restart' that follows a CHANGED.
backend_tacacs_render_commit() {
    local dir="${1:-}" result written
    result=$(_tacacs_render_commit "$dir") || return 1
    written=$(_tacacs_units_commit "$dir") || return 1
    if [[ -n "$written" && -f "$SERVICE_FILE" ]]; then
        systemctl daemon-reload >&2 || true
    fi
    if [[ "$result" == "CHANGED" || -n "$written" ]]; then
        echo "CHANGED"
    else
        echo "UNCHANGED"
    fi
}

backend_tacacs_render_notes() {
    if [[ -z "$(model_users)" || -z "$(model_scopes)" ]]; then
        warn "The store has no users or no scopes; tacquito refuses to serve such a config."
    fi
}

# sed -i and python rewrites change the file inode, breaking fsnotify
# hot-reload, so a changed config is always followed by a restart; tacquito
# has no reload of its own.
#
# service <action> [<listener>]: without a listener the action is on
# tacquito.service, which for stop, start and restart is every listener (the
# instances are PartOf= and WantedBy= it), and for is-active, since and pid
# the default listener's process. With one, it is on that listener's unit
# only ('default' restarts everything, for the same reason).
backend_tacacs_service() {
    local unit="tacquito"
    if [[ -n "${2:-}" && "$2" != "default" ]]; then
        unit=$(_tacacs_unit "$2")
    fi
    case "${1:-}" in
        restart|reload)
            if systemctl restart "$unit" 2>/dev/null; then
                info "Service restarted."
            else
                warn "Service restart failed — run: sudo systemctl restart ${unit}"
            fi
            # A render may have added or removed a listener.
            [[ "$unit" != "tacquito" ]] || _tacacs_instances_sync
            ;;
        start)     systemctl start "$unit" ;;
        stop)      systemctl stop "$unit" ;;
        enable|disable)
            # At boot: every listener's unit, as 'start' and 'stop' reach them
            # through tacquito.service. A unit that is not there (an instance
            # whose listener was removed) is not an error for 'disable'.
            local -a units
            if [[ "$unit" == "tacquito" ]]; then
                read -ra units <<< "$(_tacacs_units_all)"
            else
                units=("$unit")
            fi
            systemctl "$1" "${units[@]}"
            ;;
        is-active) systemctl is-active "$unit" 2>/dev/null ;;
        since)     systemctl show "$unit" --property=ActiveEnterTimestamp 2>/dev/null | cut -d= -f2 ;;
        pid)       systemctl show "$unit" --property=MainPID 2>/dev/null | cut -d= -f2 ;;
        *)
            error "Usage: backend_tacacs_service <start|stop|restart|reload|enable|disable|is-active|since|pid> [<listener>]"
            return 2
            ;;
    esac
}

# listeners list                      '<name> <network> <address>' per listener, default first
# listeners show [<name>]             the listener as 'tacctl config listen' prints it
# listeners set <name> <net> <addr>   create or change it; restarts its unit
# listeners reset [<name>]            the default listener back to its default address; any other is removed
backend_tacacs_listeners() {
    case "${1:-}" in
        list)  _tacacs_listener_lines ;;
        show)  _tacacs_listener_show "${2:-default}" ;;
        set)   _tacacs_listener_set "${2:-default}" "${3:-}" "${4:-}" ;;
        reset) _tacacs_listener_reset "${2:-default}" ;;
        *)
            error "Usage: backend_tacacs_listeners <list|show [<name>]|set <name> <network> <address>|reset [<name>]>"
            return 2
            ;;
    esac
}

backend_tacacs_status() {
    case "${1:-}" in
        service)    _tacacs_status_service ;;
        config)     echo -e "  ${BOLD}Config:${NC}               ${CONFIG}" ;;
        accounting) _tacacs_status_accounting ;;
        activity)   _tacacs_status_activity ;;
        *)          return 2 ;;
    esac
}

backend_tacacs_log() {
    local subcmd="${1:-}"
    shift || true
    # Every listener's unit (just 'tacquito' with only the default listener).
    local -a units
    mapfile -t units < <(_tacacs_journal_units)

    case "$subcmd" in
        tail)
            local count="${1:-20}"
            echo ""
            echo -e "${BOLD}Recent TACACS+ Log Entries${NC}"
            echo "--------------------------------------------"
            journalctl "${units[@]}" --no-pager -n "$count" 2>/dev/null || echo "  No log entries found."
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
            journalctl "${units[@]}" --no-pager --since "7 days ago" 2>/dev/null | grep -i -e "$term" || echo "  No matches found."
            echo ""
            ;;
        failures)
            echo ""
            echo -e "${BOLD}Authentication Failures (last 24 hours)${NC}"
            echo "--------------------------------------------"
            local failures
            failures=$(journalctl "${units[@]}" --no-pager --since "24 hours ago" 2>/dev/null | grep -i "ERROR\|fail\|bad secret" || true)
            if [[ -n "$failures" ]]; then
                echo "$failures"
            else
                echo -e "  ${GREEN}No failures in the last 24 hours${NC}"
            fi
            echo ""
            ;;
        clear)
            cmd_log_clear "$@"
            ;;
        *)
            return 2
            ;;
    esac
}

backend_tacacs_accounting() {
    local subcmd="${1:-}"
    shift || true

    case "$subcmd" in
        tail)
            local count="${1:-20}"
            echo ""
            echo -e "${BOLD}Recent Accounting Entries${NC}"
            echo "--------------------------------------------"
            if [[ -f "$ACCT_LOG" ]]; then
                tail -n "$count" "$ACCT_LOG"
            else
                echo "  No accounting log found at ${ACCT_LOG}"
            fi
            # The other listeners' logs, each under its name.
            local log
            for log in "$LOG_DIR"/accounting-*.log; do
                [[ -f "$log" ]] || continue
                echo ""
                echo -e "${BOLD}${log}${NC}"
                tail -n "$count" "$log"
            done
            echo ""
            ;;
        *)
            return 2
            ;;
    esac
}

backend_tacacs_last_login() {
    _tacacs_last_login "$@"
}

# tacquito takes any key; length and strength are tacctl's own rules
# (secret.min_length, 'scope secret set').
backend_tacacs_secret_constraints() {
    printf '%s\n' "max_len=" "charset="
}

# The TACACS+ device templates take everything from the model and
# tacctl.yaml; nothing comes from the daemon.
backend_tacacs_device_vars() {
    return 0
}
