# shellcheck shell=bash
# tacctl lib/store.sh -- canonical store (store.yaml): schema, validation, atomic writer, typed mutations, import, 'tacctl store'
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.
#
# store.yaml is tacctl's protocol-neutral source of truth for users, groups,
# scopes and prefix filters. This file owns every WRITE to it; lib/model.sh
# owns every READ. Nothing else should open the file.
#
# Secrets and password hashes pass through here. Rules this file keeps:
#   - values reach python on stdin or through 0600 temp files, never on argv
#     (argv is world-readable in /proc/<pid>/cmdline);
#   - error and report text names the user/scope/field, never the value;
#   - the store is written 0600 by tempfile + rename in its own directory.

# Canonical store location. TACCTL_STATE_DIR is introduced by the state-dir
# work package; the fallback keeps this file self-contained until then.
STORE_FILE="${TACCTL_STATE_DIR:-/etc/tacctl}/store.yaml"

# Message every mutating verb prints while the install is still in legacy
# read-only mode (plan 4.4).
STORE_NOT_INITIALISED_MSG="store not initialised — review 'tacctl store import --check' and run 'tacctl store import [--force]'"

# --- Python: schema, validation, canonical form, atomic write, typed ops ----
# Emitted as source so one interpreter run can combine it with the model code
# (lib/model.sh: _model_py) and the command dispatcher (_store_main_py).
# STORE_SCHEMA is the one description of what is legal in store.yaml.
#
# _store_base_py is the part with no file I/O and no YAML: the schema, the
# constants and the hash/CIDR helpers. The model's read accessors run on it
# alone (lib/model.sh: _model_python), which keeps the many small reads a
# command makes cheap -- importing PyYAML and compiling the rest costs more
# than the read itself. _store_py is the base plus everything else.
_store_base_py() {
    cat <<'PY'
import binascii, ipaddress, json, os, re, sys


class StoreError(Exception):
    """A problem to report to the operator as one line, without a traceback."""


STORE_VERSION = 1
# name -> (default priv-lvl, default Juniper class). Present in every store
# and never removable.
BUILTIN_GROUPS = {
    'readonly': (1, 'RO-CLASS'),
    'operator': (7, 'OP-CLASS'),
    'superuser': (15, 'RW-CLASS'),
}
KNOWN_PROTOCOLS = ('tacacs', 'radius')
# 'tacquito' collides with the service user; 'root' may exist only as the
# accounting sink (see reject_reserved_username in lib/core.sh).
RESERVED_USERS = ('tacquito',)
SINK_USERS = ('root',)
# '$2b$12$' + 53 dots, hex-encoded. Must equal DISABLED_MARKER_HEX in
# lib/users.sh (a unit test pins the two together).
DISABLED_MARKER_HEX = '24326224313224' + '2e' * 53

RE_USER = re.compile(r'[a-zA-Z0-9_-]+')
RE_GROUP = re.compile(r'[a-z][a-z0-9_-]*')
RE_SCOPE = re.compile(r'[a-zA-Z][a-zA-Z0-9_-]{0,31}')
RE_CLASS = re.compile(r'[A-Za-z0-9_-]+')
RE_DATE = re.compile(r'\d{4}-\d{2}-\d{2}')

STORE_SCHEMA = {
    'groups': {
        'label': 'group', 'name': RE_GROUP,
        'fields': {
            'priv_lvl':      {'type': 'int', 'min': 0, 'max': 15, 'required': True},
            'juniper_class': {'type': 'string', 'pattern': RE_CLASS, 'required': True},
            'builtin':       {'type': 'bool'},
        },
    },
    'users': {
        'label': 'user', 'name': RE_USER,
        'fields': {
            'group':            {'type': 'string', 'required': True},
            'scopes':           {'type': 'string_list', 'required': True},
            'hash':             {'type': 'bcrypt_hex', 'nullable': True, 'required': True},
            'disabled':         {'type': 'bool', 'required': True},
            'password_changed': {'type': 'date', 'nullable': True},
            'accounting_sink':  {'type': 'bool'},
        },
    },
    'scopes': {
        'label': 'scope', 'name': RE_SCOPE,
        'fields': {
            'prefixes':  {'type': 'cidr_list', 'min_items': 1, 'required': True},
            'secret':    {'type': 'secret', 'required': True},
            'protocols': {'type': 'enum_list', 'values': KNOWN_PROTOCOLS,
                          'min_items': 1, 'nullable': True},
        },
    },
}
FILTER_KEYS = ('allow', 'deny')
TOP_KEYS = ('version', 'groups', 'users', 'scopes', 'filters')


def is_int(v):
    return isinstance(v, int) and not isinstance(v, bool)


def bcrypt_hex_ok(h):
    """True for a lower-case hex string that decodes to a '$2a/b/y$' hash."""
    if not isinstance(h, str) or len(h) % 2 or not re.fullmatch(r'[0-9a-f]+', h):
        return False
    try:
        raw = binascii.unhexlify(h).decode('ascii')
    except (binascii.Error, ValueError, UnicodeDecodeError):
        return False
    return re.match(r'\$2[aby]\$', raw) is not None


def normalize_hash(value):
    """Raw '$2b$..' or hex of either case -> canonical hex, else None.
    Mirrors normalize_bcrypt_hash in lib/users.sh."""
    if not isinstance(value, str):
        return None
    value = value.strip()
    if re.match(r'\$2[aby]\$', value):
        return binascii.hexlify(value.encode()).decode()
    low = value.lower()
    return low if bcrypt_hex_ok(low) else None


def cidr_key(c):
    """Render order: IPv4 first, narrower/earlier ranges first. Same key as
    sort_cidrs_by_specificity (lib/core.sh)."""
    n = ipaddress.ip_network(c, strict=False)
    return (n.version, int(n.broadcast_address), int(n.network_address))


def canonical_cidr(c):
    """Canonical string for a CIDR, or None when it does not parse."""
    if not isinstance(c, str):
        return None
    try:
        return str(ipaddress.ip_network(c.strip(), strict=False))
    except ValueError:
        return None


def canonical_cidr_list(items):
    """Canonicalise, dedupe and sort a list whose entries all parse; a list
    with an unparseable entry is returned untouched for the validator."""
    if not isinstance(items, list):
        return items
    out = []
    for c in items:
        canon = canonical_cidr(c)
        if canon is None:
            return items
        if canon not in out:
            out.append(canon)
    return sorted(out, key=cidr_key)


PY
}

_store_py() {
    _store_base_py
    cat <<'PY'

import contextlib, datetime, difflib, fcntl, hashlib, hmac, tempfile
import yaml


def _check_field(spec, val):
    """Return a problem description for one field value, or None.
    Never echoes the value of a 'secret' or 'bcrypt_hex' field."""
    t = spec['type']
    if val is None:
        return None if spec.get('nullable') else 'must not be null'
    if t == 'int':
        if not is_int(val):
            return 'must be an integer'
        if val < spec['min'] or val > spec['max']:
            return f"must be {spec['min']}-{spec['max']}"
    elif t == 'bool':
        if not isinstance(val, bool):
            return 'must be true or false'
    elif t == 'string':
        if not isinstance(val, str) or not val:
            return 'must be a non-empty string'
        if 'pattern' in spec and not spec['pattern'].fullmatch(val):
            return 'contains characters that are not allowed'
    elif t == 'string_list':
        if not isinstance(val, list) or any(not isinstance(x, str) or not x for x in val):
            return 'must be a list of names'
        if len(set(val)) != len(val):
            return 'lists the same name twice'
    elif t == 'enum_list':
        if not isinstance(val, list) or any(x not in spec['values'] for x in val):
            return 'must be a list drawn from: ' + ', '.join(spec['values'])
        if len(set(val)) != len(val):
            return 'lists the same value twice'
        if len(val) < spec.get('min_items', 0):
            return 'must not be empty (omit it to mean every enabled backend)'
    elif t == 'cidr_list':
        if not isinstance(val, list):
            return 'must be a list of CIDRs'
        for c in val:
            canon = canonical_cidr(c)
            if canon is None:
                return f'contains an invalid CIDR ({c!r})'
            if canon != c:
                return f'contains a non-canonical CIDR ({c!r}, canonical form {canon})'
        if len(set(val)) != len(val):
            return 'lists the same CIDR twice'
        if len(val) < spec.get('min_items', 0):
            return 'must list at least one CIDR'
    elif t == 'secret':
        if not isinstance(val, str) or not val:
            return 'must be a non-empty string'
        if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in val):
            return 'contains control characters'
    elif t == 'bcrypt_hex':
        if isinstance(val, str) and val.lower() == DISABLED_MARKER_HEX:
            return 'is the disabled marker (store the real hash or null, and set disabled: true)'
        if not bcrypt_hex_ok(val):
            return 'is not a hex-encoded bcrypt hash'
    elif t == 'date':
        if not isinstance(val, str) or not RE_DATE.fullmatch(val):
            return 'must be a YYYY-MM-DD date'
        try:
            datetime.date.fromisoformat(val)
        except ValueError:
            return 'is not a real calendar date'
    return None


def store_validate(store):
    """Validate a store (raw from disk or normalised). Returns error strings;
    an empty list means valid."""
    errs = []
    if not isinstance(store, dict):
        return ['store is not a YAML mapping']
    for k in store:
        if k not in TOP_KEYS:
            errs.append(f"unknown top-level key '{k}'")
    if not is_int(store.get('version')) or store.get('version') != STORE_VERSION:
        errs.append(f'version must be {STORE_VERSION}')

    sections = {}
    for sec, spec in STORE_SCHEMA.items():
        body = store.get(sec)
        if body is None:
            body = {}
        if not isinstance(body, dict):
            errs.append(f"'{sec}' must be a mapping keyed by name")
            body = {}
        sections[sec] = body
        label = spec['label']
        for name, ent in body.items():
            if not isinstance(name, str) or not spec['name'].fullmatch(name):
                errs.append(f"{label} {name!r}: invalid name")
                continue
            if not isinstance(ent, dict):
                errs.append(f"{label} '{name}': must be a mapping")
                continue
            for f in ent:
                if f not in spec['fields']:
                    errs.append(f"{label} '{name}': unknown field '{f}'")
            for f, fspec in spec['fields'].items():
                if f not in ent:
                    if fspec.get('required'):
                        errs.append(f"{label} '{name}': missing '{f}'")
                    continue
                problem = _check_field(fspec, ent[f])
                if problem:
                    errs.append(f"{label} '{name}': {f} {problem}")

    groups, users, scopes = sections['groups'], sections['users'], sections['scopes']

    # Built-in groups: always present, flagged, and nothing else is flagged.
    for b in BUILTIN_GROUPS:
        g = groups.get(b)
        if not isinstance(g, dict):
            errs.append(f"built-in group '{b}' is missing")
        elif g.get('builtin') is not True:
            errs.append(f"group '{b}': built-in group must carry builtin: true")
    for name, g in groups.items():
        if isinstance(g, dict) and g.get('builtin') is True and name not in BUILTIN_GROUPS:
            errs.append(f"group '{name}': builtin: true is reserved for the built-in groups")

    for name, u in users.items():
        if not isinstance(u, dict) or not isinstance(name, str):
            continue
        if name in RESERVED_USERS:
            errs.append(f"user '{name}': reserved name (matches the service user)")
        grp = u.get('group')
        if isinstance(grp, str) and grp and grp not in groups:
            errs.append(f"user '{name}': group '{grp}' does not exist")
        if isinstance(u.get('scopes'), list):
            for s in u['scopes']:
                if isinstance(s, str) and s and s not in scopes:
                    errs.append(f"user '{name}': scope '{s}' does not exist")
        sink = u.get('accounting_sink') is True
        if name in SINK_USERS and not sink:
            errs.append(f"user '{name}': reserved name, allowed only as the accounting sink (accounting_sink: true)")
        if sink:
            if name not in SINK_USERS:
                errs.append(f"user '{name}': accounting_sink is reserved for: " + ', '.join(SINK_USERS))
            if u.get('hash') is not None:
                errs.append(f"user '{name}': the accounting sink must not carry a password hash")
            if u.get('disabled') is not True:
                errs.append(f"user '{name}': the accounting sink must stay disabled")

    # One prefix, one scope (see model_prefix_owner). Overlap between
    # scopes is fine -- only the identical network is exclusive.
    owner = {}
    for name, s in scopes.items():
        if not isinstance(s, dict) or not isinstance(s.get('prefixes'), list):
            continue
        for c in s['prefixes']:
            canon = canonical_cidr(c)
            if canon is None:
                continue
            if canon in owner and owner[canon] != name:
                errs.append(f"prefix {canon} is claimed by scopes '{owner[canon]}' and '{name}' (one scope per prefix)")
            owner.setdefault(canon, name)

    filters = store.get('filters')
    if filters is not None:
        if not isinstance(filters, dict):
            errs.append("'filters' must be a mapping with allow and deny")
        else:
            for k, v in filters.items():
                if k not in FILTER_KEYS:
                    errs.append(f"filters: unknown key '{k}'")
                    continue
                problem = _check_field({'type': 'cidr_list'}, [] if v is None else v)
                if problem:
                    errs.append(f"filters.{k} {problem}")
    return errs


def store_normalize(raw):
    """Raw store -> model: every optional field present, YAML-native dates
    turned back into strings. Raises StoreError only when the shape is too
    broken to walk; field-level problems are store_validate's job."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise StoreError('store is not a YAML mapping')
    model = {'version': raw.get('version', STORE_VERSION),
             'groups': {}, 'users': {}, 'scopes': {},
             'filters': {'allow': [], 'deny': []}}
    for k in raw:
        if k not in TOP_KEYS:
            model[k] = raw[k]          # kept so store_validate reports it
    defaults = {
        'groups': {'builtin': False},
        'users': {'password_changed': None, 'accounting_sink': False},
        'scopes': {'protocols': None},
    }
    for sec in STORE_SCHEMA:
        body = raw.get(sec)
        if body is None:
            continue
        if not isinstance(body, dict):
            raise StoreError(f"'{sec}' must be a mapping keyed by name")
        for name, ent in body.items():
            if not isinstance(ent, dict):
                raise StoreError(f"{STORE_SCHEMA[sec]['label']} {name!r}: must be a mapping")
            out = dict(ent)
            for f, dv in defaults[sec].items():
                out.setdefault(f, dv)
            model[sec][name] = out
    for u in model['users'].values():
        pc = u.get('password_changed')
        if isinstance(pc, (datetime.date, datetime.datetime)):
            u['password_changed'] = pc.strftime('%Y-%m-%d')
    filters = raw.get('filters')
    if filters is not None:
        if not isinstance(filters, dict):
            raise StoreError("'filters' must be a mapping with allow and deny")
        for k, v in filters.items():
            model['filters'][k] = [] if v is None else v
    return model


def store_canonicalize(model):
    """Put a model into the one form that gets written: prefixes and filters
    canonical and sorted, hashes lower-case, user scope lists de-duplicated
    (order kept -- it is what 'user list' shows), flags derived from names."""
    for name, g in model['groups'].items():
        if isinstance(g, dict):
            g['builtin'] = name in BUILTIN_GROUPS
    for u in model['users'].values():
        if not isinstance(u, dict):
            continue
        if isinstance(u.get('hash'), str):
            u['hash'] = u['hash'].lower()
        if isinstance(u.get('scopes'), list):
            seen = []
            for s in u['scopes']:
                if s not in seen:
                    seen.append(s)
            u['scopes'] = seen
    for s in model['scopes'].values():
        if isinstance(s, dict):
            s['prefixes'] = canonical_cidr_list(s.get('prefixes'))
    for k in list(model['filters']):
        model['filters'][k] = canonical_cidr_list(model['filters'][k])
    return model


def store_disk_form(model):
    """Model -> the dict written to store.yaml: names sorted for stable
    diffs, fields in a fixed order, optional fields omitted when unset."""
    out = {'version': STORE_VERSION, 'groups': {}, 'users': {}, 'scopes': {},
           'filters': {'allow': list(model['filters'].get('allow') or []),
                       'deny': list(model['filters'].get('deny') or [])}}
    for name in sorted(model['groups']):
        g = model['groups'][name]
        ent = {'priv_lvl': g.get('priv_lvl'), 'juniper_class': g.get('juniper_class')}
        if g.get('builtin'):
            ent['builtin'] = True
        out['groups'][name] = ent
    for name in sorted(model['users']):
        u = model['users'][name]
        ent = {'group': u.get('group'), 'scopes': list(u.get('scopes') or []),
               'hash': u.get('hash'), 'disabled': u.get('disabled')}
        if u.get('password_changed'):
            ent['password_changed'] = u['password_changed']
        if u.get('accounting_sink'):
            ent['accounting_sink'] = True
        out['users'][name] = ent
    for name in sorted(model['scopes']):
        s = model['scopes'][name]
        ent = {'prefixes': list(s.get('prefixes') or []), 'secret': s.get('secret')}
        if s.get('protocols'):
            ent['protocols'] = list(s['protocols'])
        out['scopes'][name] = ent
    return out


STORE_HEADER = (
    "# tacctl canonical store: users, groups, scopes, prefix filters.\n"
    "# Managed by tacctl -- change it with tacctl commands. Contains shared\n"
    "# secrets and password hashes; keep it 0600.\n\n"
)


def store_dump_text(model):
    return STORE_HEADER + yaml.safe_dump(
        store_disk_form(model), sort_keys=False, default_flow_style=None, width=4096)


def yaml_problem(path, exc):
    """One-line description of a YAML error. Deliberately omits PyYAML's
    context snippet, which can quote a line holding a secret."""
    mark = getattr(exc, 'problem_mark', None)
    problem = getattr(exc, 'problem', None) or 'invalid YAML'
    where = f' (line {mark.line + 1}, column {mark.column + 1})' if mark else ''
    return f'{path}: {problem}{where}'


def store_load_raw(path):
    try:
        with open(path) as f:
            return yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise StoreError(yaml_problem(path, e))
    except OSError as e:
        raise StoreError(f'{path}: {e.strerror}')


def atomic_write(path, text, mode=0o600):
    """Write via a temp file in the same directory, fsync, rename."""
    d = os.path.dirname(path) or '.'
    fd, tmp = tempfile.mkstemp(prefix='.store.', suffix='.tmp', dir=d)
    try:
        with os.fdopen(fd, 'w') as f:
            os.fchmod(f.fileno(), mode)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp)
        raise
    with contextlib.suppress(OSError):
        dfd = os.open(d, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)


@contextlib.contextmanager
def store_lock(path):
    """Serialise load-mutate-write across concurrent tacctl invocations."""
    d = os.path.dirname(path) or '.'
    os.makedirs(d, mode=0o700, exist_ok=True)
    fd = os.open(os.path.join(d, '.store.lock'), os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


def store_write_validated(path, model):
    """Canonicalise, validate, write. Returns False when the file already
    holds exactly this content. Raises StoreError listing every problem."""
    model = store_canonicalize(model)
    errs = store_validate(model)
    if errs:
        raise StoreError('store validation failed:\n  - ' + '\n  - '.join(errs))
    text = store_dump_text(model)
    try:
        with open(path) as f:
            if f.read() == text:
                return False
    except OSError:
        pass
    atomic_write(path, text)
    return True


def empty_model():
    model = {'version': STORE_VERSION, 'groups': {}, 'users': {}, 'scopes': {},
             'filters': {'allow': [], 'deny': []}}
    for name, (priv, cls) in BUILTIN_GROUPS.items():
        model['groups'][name] = {'priv_lvl': priv, 'juniper_class': cls, 'builtin': True}
    return model


# ---- typed mutations (run inside store_mutate with `store` and `args`) ----

def _kv(args):
    out = {}
    for a in args:
        if '=' not in a:
            raise StoreError(f"expected <field>=<value>, got {a.split('=')[0]!r}")
        k, v = a.split('=', 1)
        out[k] = v
    return out


def _csv(value):
    return [x.strip() for x in value.split(',') if x.strip()]


def _bool(field, value):
    if value not in ('true', 'false'):
        raise StoreError(f'{field} must be true or false')
    return value == 'true'


def _need_name(args, what):
    if not args or not args[0]:
        raise StoreError(f'{what} name required')
    return args[0]


def op_user_set(store, args):
    name = _need_name(args, 'user')
    fields = _kv(args[1:])
    users = store['users']
    new = name not in users
    sink = name in SINK_USERS
    if new:
        if 'group' not in fields:
            raise StoreError(f"user '{name}': group is required when creating a user")
        users[name] = {'group': None, 'scopes': [], 'hash': None, 'disabled': True,
                       'password_changed': None, 'accounting_sink': sink}
    u = users[name]
    for k, v in fields.items():
        if k == 'group':
            u['group'] = v
        elif k == 'scopes':
            u['scopes'] = _csv(v)
        elif k == 'hash':
            if sink:
                raise StoreError(f"user '{name}' is the accounting sink and never carries a password")
            if v in ('', 'null'):
                u['hash'] = None
            else:
                h = normalize_hash(v)
                if h is None:
                    raise StoreError(f"user '{name}': hash is not a bcrypt hash")
                if h == DISABLED_MARKER_HEX:
                    raise StoreError(f"user '{name}': the disabled marker is not a password hash; use disabled=true")
                u['hash'] = h
            # A brand-new user is usable as soon as it has a password,
            # unless the caller says otherwise.
            if new and 'disabled' not in fields:
                u['disabled'] = u['hash'] is None
        elif k == 'disabled':
            u['disabled'] = _bool('disabled', v)
        elif k == 'password_changed':
            if v in ('', 'null'):
                u['password_changed'] = None
            elif v == 'today':
                u['password_changed'] = datetime.date.today().strftime('%Y-%m-%d')
            else:
                u['password_changed'] = v
        else:
            raise StoreError(f"user '{name}': unknown field '{k}'")


def op_user_del(store, args):
    name = _need_name(args, 'user')
    if name not in store['users']:
        raise StoreError(f"user '{name}' does not exist")
    del store['users'][name]


def op_user_rename(store, args):
    if len(args) != 2:
        raise StoreError('usage: <old> <new>')
    old, new = args
    users = store['users']
    if old not in users:
        raise StoreError(f"user '{old}' does not exist")
    if new in users:
        raise StoreError(f"user '{new}' already exists")
    u = users.pop(old)
    u['accounting_sink'] = new in SINK_USERS
    users[new] = u


def op_group_set(store, args):
    name = _need_name(args, 'group')
    fields = _kv(args[1:])
    groups = store['groups']
    if name not in groups:
        missing = [f for f in ('priv_lvl', 'juniper_class') if f not in fields]
        if missing:
            raise StoreError(f"group '{name}': " + ' and '.join(missing) + ' required when creating a group')
        groups[name] = {'priv_lvl': None, 'juniper_class': None, 'builtin': False}
    g = groups[name]
    for k, v in fields.items():
        if k == 'priv_lvl':
            if not re.fullmatch(r'[0-9]+', v):
                raise StoreError(f"group '{name}': priv_lvl must be 0-15")
            g['priv_lvl'] = int(v)
        elif k == 'juniper_class':
            g['juniper_class'] = v
        else:
            raise StoreError(f"group '{name}': unknown field '{k}'")


def op_group_del(store, args):
    name = _need_name(args, 'group')
    if name not in store['groups']:
        raise StoreError(f"group '{name}' does not exist")
    if name in BUILTIN_GROUPS:
        raise StoreError(f"cannot remove built-in group '{name}'")
    members = sorted(n for n, u in store['users'].items() if u.get('group') == name)
    if members:
        raise StoreError(f"cannot remove group '{name}': {len(members)} user(s) are assigned to it")
    del store['groups'][name]


def op_scope_set(store, args):
    name = _need_name(args, 'scope')
    fields = _kv(args[1:])
    scopes = store['scopes']
    if name not in scopes:
        missing = [f for f in ('prefixes', 'secret') if f not in fields]
        if missing:
            raise StoreError(f"scope '{name}': " + ' and '.join(missing) + ' required when creating a scope')
        scopes[name] = {'prefixes': [], 'secret': None, 'protocols': None}
    s = scopes[name]
    for k, v in fields.items():
        if k == 'prefixes':
            items = _csv(v)
            for c in items:
                if canonical_cidr(c) is None:
                    raise StoreError(f"scope '{name}': invalid CIDR {c!r}")
            s['prefixes'] = items
        elif k == 'secret':
            s['secret'] = v
        elif k == 'protocols':
            s['protocols'] = None if v in ('', 'null') else _csv(v)
        else:
            raise StoreError(f"scope '{name}': unknown field '{k}'")


def op_scope_del(store, args):
    name = _need_name(args, 'scope')
    strip = '--strip-users' in args[1:]
    if name not in store['scopes']:
        raise StoreError(f"scope '{name}' does not exist")
    members = sorted(n for n, u in store['users'].items() if name in (u.get('scopes') or []))
    if members and not strip:
        raise StoreError(f"cannot remove scope '{name}': {len(members)} user(s) still reference it")
    for n in members:
        store['users'][n]['scopes'] = [s for s in store['users'][n]['scopes'] if s != name]
    del store['scopes'][name]


def op_scope_rename(store, args):
    if len(args) != 2:
        raise StoreError('usage: <old> <new>')
    old, new = args
    scopes = store['scopes']
    if old not in scopes:
        raise StoreError(f"scope '{old}' does not exist")
    if new in scopes:
        raise StoreError(f"scope '{new}' already exists")
    scopes[new] = scopes.pop(old)
    for u in store['users'].values():
        u['scopes'] = [new if s == old else s for s in (u.get('scopes') or [])]


def op_filters_set(store, args):
    if len(args) != 2 or args[0] not in FILTER_KEYS:
        raise StoreError('usage: allow|deny <cidr>[,<cidr>...]')
    items = _csv(args[1])
    for c in items:
        if canonical_cidr(c) is None:
            raise StoreError(f"filters.{args[0]}: invalid CIDR {c!r}")
    store['filters'][args[0]] = items


# What a fresh install starts with besides the built-in groups: one account
# per shipped tier, each without a password and therefore disabled until
# 'tacctl user passwd <name>', and 'root' as the accounting sink. Junos
# devices send accounting records with User=root whenever an internal daemon
# runs a CLI command, and tacquito logs an error for a user it does not know;
# the sink gives those records a home and can never authenticate.
SEED_USERS = (('engineer', 'superuser'), ('operator', 'operator'),
              ('viewer', 'readonly'), ('root', 'readonly'))


def op_seed_fresh(store, args):
    if len(args) != 3:
        raise StoreError('usage: <scope> <cidr>[,<cidr>...] <secret>')
    scope, prefixes, secret = args
    op_scope_set(store, [scope, 'prefixes=' + prefixes, 'secret=' + secret])
    for name, group in SEED_USERS:
        op_user_set(store, [name, 'group=' + group, 'scopes=' + scope])
PY
}

# --- Python: command dispatcher --------------------------------------------
# Appended after _store_py and _model_py. Data that may hold secrets arrives
# on stdin or in a 0600 file named on argv; argv itself carries only paths,
# names and flags.
_store_main_py() {
    cat <<'PY'

def _stdin_args():
    data = sys.stdin.buffer.read().decode()
    if not data:
        return []
    return data[:-1].split('\0') if data.endswith('\0') else data.split('\0')


def _write_private(path, text):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as f:
        f.write(text)


def main(argv):
    cmd, rest = argv[0], argv[1:]

    if cmd == 'dump-store':
        model = store_normalize(store_load_raw(rest[0]))
        print(json.dumps(model, sort_keys=True))

    elif cmd == 'dump-legacy':
        model, _report = legacy_load(rest[0], rest[1], rest[2])
        print(json.dumps(store_canonicalize(model), sort_keys=True))

    elif cmd == 'get':
        return model_get(json.load(sys.stdin), rest)

    elif cmd == 'show':
        model = json.load(sys.stdin)
        if rest and rest[0] == 'json':
            print(json.dumps(model, indent=4, sort_keys=True))
        else:
            sys.stdout.write(yaml.safe_dump(
                model, sort_keys=False, default_flow_style=None, width=4096))

    elif cmd == 'validate':
        raw = store_load_raw(rest[0])
        if isinstance(raw, dict):
            raw = store_normalize(raw)
        errs = store_validate(raw)
        for e in errs:
            print(f'tacctl store: {e}', file=sys.stderr)
        return 1 if errs else 0

    elif cmd == 'mutate':
        # mutate <store-path> <create:0|1> <snippet>; args NUL-separated on stdin.
        path, create, snippet = rest[0], rest[1] == '1', rest[2]
        args = _stdin_args()
        with store_lock(path):
            if os.path.exists(path):
                if create:
                    raise StoreError(f'{path} already exists')
                store = store_normalize(store_load_raw(path))
            elif create:
                store = empty_model()
            else:
                raise StoreError(STORE_NOT_INITIALISED)
            env = dict(globals())
            env.update(store=store, args=args)
            exec(compile(snippet, '<store_mutate>', 'exec'), env)
            store_write_validated(path, env['store'])

    elif cmd == 'import-load':
        # import-load <src> <dates-dir> <disabled-dir> <existing-store|''> <force:0|1> <model-out>
        src, dates_dir, disabled_dir, existing, force, model_out = rest
        ok, model = import_load(src, dates_dir, disabled_dir, existing, force == '1')
        if not ok:
            return 1
        _write_private(model_out, json.dumps(model, sort_keys=True))

    elif cmd == 'import-write':
        # import-write <model.json> <store-path>
        with open(rest[0]) as f:
            model = json.load(f)
        with store_lock(rest[1]):
            store_write_validated(rest[1], model)

    elif cmd == 'equiv':
        return equiv_check(rest[0], rest[1])

    else:
        raise StoreError(f'internal: unknown command {cmd!r}')
    return 0


STORE_NOT_INITIALISED = os.environ.get('TACCTL_STORE_NOT_INITIALISED_MSG', 'store not initialised')

if __name__ == '__main__':
    try:
        sys.exit(main(sys.argv[1:]))
    except StoreError as e:
        print(f'tacctl store: {e}', file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        # e.g. the state directory is not writable. Path and reason only.
        print(f'tacctl store: {e.filename or "I/O"}: {e.strerror}', file=sys.stderr)
        sys.exit(1)
PY
}

# Run the combined python program: _store_python <command> [args...].
_store_python() {
    TACCTL_STORE_NOT_INITIALISED_MSG="$STORE_NOT_INITIALISED_MSG" \
        python3 <(_store_py; _model_py; _store_main_py) "$@"
}

# --- Hooks filled in by later work packages --------------------------------

# store_snapshot_hook: called before every write to an existing store.
# Delegates to backup_snapshot once the snapshot package defines it.
store_snapshot_hook() {
    if declare -F backup_snapshot >/dev/null; then
        backup_snapshot
    fi
}

# store_render_hook <model.json> <out-file>: render a tacquito.yaml from a
# model for 'store import --check' (plan 4.3 step 2). Delegates to
# render_tacacs_config once the renderer package defines it.
# Returns 0 rendered, 2 no renderer available, anything else render failed.
store_render_hook() {
    if declare -F render_tacacs_config >/dev/null; then
        render_tacacs_config "$1" "$2"
        return
    fi
    return 2
}

# store_smoke_hook <rendered-file>: daemon load-smoke of a rendered config
# (plan 4.3 step 4). Delegates to tacacs_load_smoke once it exists.
# Returns 0 passed, 2 skipped (no implementation or no daemon binary),
# anything else failed.
store_smoke_hook() {
    if declare -F tacacs_load_smoke >/dev/null; then
        tacacs_load_smoke "$1"
        return
    fi
    return 2
}

# --- Validation -------------------------------------------------------------

# store_validate [<file>]: validate a store file (default: the live store).
# Prints one 'tacctl store: <problem>' line per error on stderr. 0 = valid.
store_validate() {
    local file="${1:-$STORE_FILE}"
    if [[ ! -f "$file" ]]; then
        error "Store not found at ${file}."
        return 1
    fi
    _store_python validate "$file"
}

# --- Writer -----------------------------------------------------------------

# store_mutate <python-snippet> [<arg>...]
# load -> run snippet -> canonicalise -> validate -> atomic write (0600).
# The snippet sees `store` (the normalised model dict, mutated in place) and
# `args` (the remaining arguments as strings), plus everything _store_py
# defines. Arguments travel on stdin, so they may carry a secret or a hash.
# Nothing is written when the snippet raises or the result fails validation.
# In legacy mode (no store yet) it fails with STORE_NOT_INITIALISED_MSG.
# Call it in the current shell, not in $(...), or the model cache of the
# caller is not invalidated.
store_mutate() {
    local snippet="$1"
    shift
    if [[ ! -f "$STORE_FILE" ]]; then
        error "$STORE_NOT_INITIALISED_MSG"
        return 1
    fi
    store_snapshot_hook || return 1
    local rc=0
    _store_python mutate "$STORE_FILE" 0 "$snippet" \
        < <( (( $# )) && printf '%s\0' "$@" ) || rc=$?
    _model_invalidate
    return "$rc"
}

# store_init: create a new store holding only the built-in groups. Fails if
# a store already exists. For fresh installs; upgrades use store_import.
store_init() {
    if [[ -e "$STORE_FILE" ]]; then
        error "Store already exists at ${STORE_FILE}."
        return 1
    fi
    local rc=0
    _store_python mutate "$STORE_FILE" 1 "pass" </dev/null || rc=$?
    _model_invalidate
    return "$rc"
}

# store_seed_fresh <scope> <cidr>[,<cidr>...]   (shared secret on stdin)
# Create the store of a fresh install in one validated write: the built-in
# groups, the scope, and the seed users (SEED_USERS above) as members of it.
# Fails, writing nothing, if a store already exists.
store_seed_fresh() {
    local scope="${1:-}" prefixes="${2:-}" secret="" rc=0
    if [[ -e "$STORE_FILE" ]]; then
        error "Store already exists at ${STORE_FILE}."
        return 1
    fi
    IFS= read -r secret || true
    if [[ -z "$scope" || -z "$prefixes" || -z "$secret" ]]; then
        error "Usage: store_seed_fresh <scope> <cidr>[,<cidr>...]  (shared secret on stdin)"
        return 1
    fi
    _store_python mutate "$STORE_FILE" 1 'op_seed_fresh(store, args)' \
        < <(printf '%s\0' "$scope" "$prefixes" "$secret") || rc=$?
    _model_invalidate
    return "$rc"
}

# --- Typed mutations --------------------------------------------------------
# Each is one validated atomic write. They create-or-update ("set") or fail
# when the target is missing ("del"); callers decide whether "already exists"
# is an error by asking the model first.

# store_user_set <name> [group=<g>] [scopes=<a,b>] [hash=<hex|$2b$..|null>]
#                [disabled=true|false] [password_changed=<YYYY-MM-DD|today|null>]
# group= is required when the user is new. A new user given hash= starts
# enabled; without one it starts disabled. 'root' is always the accounting
# sink and rejects hash=.
store_user_set() { store_mutate 'op_user_set(store, args)' "$@"; }

# store_user_del <name>
store_user_del() { store_mutate 'op_user_del(store, args)' "$@"; }

# store_user_rename <old> <new>
store_user_rename() { store_mutate 'op_user_rename(store, args)' "$@"; }

# store_group_set <name> [priv_lvl=<0-15>] [juniper_class=<class>]
# Both fields are required when the group is new.
store_group_set() { store_mutate 'op_group_set(store, args)' "$@"; }

# store_group_del <name>   (refuses built-ins and groups that still have users)
store_group_del() { store_mutate 'op_group_del(store, args)' "$@"; }

# store_scope_set <name> [prefixes=<cidr,cidr>] [secret=<key>] [protocols=<a,b|null>]
# prefixes= replaces the whole list. prefixes= and secret= are required when
# the scope is new.
store_scope_set() { store_mutate 'op_scope_set(store, args)' "$@"; }

# store_scope_del <name> [--strip-users]
# Refuses while users reference the scope unless --strip-users is given.
store_scope_del() { store_mutate 'op_scope_del(store, args)' "$@"; }

# store_scope_rename <old> <new>   (rewrites every user's scope list too)
store_scope_rename() { store_mutate 'op_scope_rename(store, args)' "$@"; }

# store_filters_set allow|deny <cidr>[,<cidr>...]   (empty list clears it)
store_filters_set() { store_mutate 'op_filters_set(store, args)' "$@"; }

# --- Equivalence (plan 4.3 step 3) ------------------------------------------

# store_equiv_check <live-tacquito.yaml> <rendered-tacquito.yaml>
# Normalises both files to what the daemon would act on and compares.
# Prints EQUIVALENT (0) or a unified diff of the normalised forms (1).
# Shared secrets and hashes appear only as per-run fingerprints.
store_equiv_check() {
    _store_python equiv "$1" "$2"
}

# --- Import -----------------------------------------------------------------

# store_import [--check] [--force] [--replace] [<file>]
# One-time import of a legacy tacquito.yaml (default: $CONFIG) into the store.
#   (no flag)  import; fails and writes nothing when the file holds content
#              the store cannot represent, listing each item.
#   --force    drop the unrepresentable items (each is printed) and import.
#   --check    write nothing; report the import, then the equivalence proof
#              (render, compare, daemon load-smoke) as far as the hooks allow.
#   --replace  allow overwriting an existing store. Fields the legacy file
#              cannot carry (scope protocols, password dates, the real hash
#              of a disabled user) are kept from the existing store.
# Exit: 0 ok; 1 failed; 2 usage; 3 (--check only) import is clean but
# equivalence was not proven because no renderer is available.
store_import() {
    local check=0 force=0 replace=0 src=""
    while (( $# )); do
        case "$1" in
            --check)   check=1 ;;
            --force)   force=1 ;;
            --replace) replace=1 ;;
            -*)
                error "Unknown option '$1'. Usage: tacctl store import [--check|--force] [--replace] [<file>]"
                return 2
                ;;
            *)
                if [[ -n "$src" ]]; then
                    error "Only one file may be given."
                    return 2
                fi
                src="$1"
                ;;
        esac
        shift
    done
    src="${src:-$CONFIG}"
    if [[ ! -f "$src" ]]; then
        error "Cannot import: ${src} not found."
        return 1
    fi
    if (( ! check )) && [[ -f "$STORE_FILE" ]] && (( ! replace )); then
        error "A store already exists at ${STORE_FILE}; importing would overwrite it."
        error "Use 'tacctl store import --check' to compare, or add --replace to overwrite."
        return 1
    fi
    local rc=0
    # Subshell: scopes the temp dir (it briefly holds the model, secrets
    # included) and its cleanup trap.
    ( _store_import_run "$check" "$force" "$src" ) || rc=$?
    _model_invalidate
    return "$rc"
}

_store_import_run() {
    local check="$1" force="$2" src="$3"
    local tmpd existing=""
    tmpd=$(mktemp -d) || exit 1
    # shellcheck disable=SC2064  # expand tmpd now; the subshell owns this trap
    trap "rm -rf '${tmpd}'" EXIT
    [[ -f "$STORE_FILE" ]] && existing="$STORE_FILE"

    echo ""
    if ! _store_python import-load "$src" "$PASSWORD_DATES_DIR" \
            "${BACKUP_DIR}/disabled" "$existing" "$force" "${tmpd}/model.json"; then
        echo ""
        error "Import failed. Nothing was written."
        exit 1
    fi
    echo ""

    if (( ! check )); then
        local pre=""
        if [[ -n "$existing" ]]; then
            store_snapshot_hook || exit 1
        elif [[ "$src" -ef "$CONFIG" ]]; then
            # The flip: the live config is about to stop being the source of
            # truth. Keep it, so 'tacctl store rollback' can go back.
            if ! pre=$(store_keep_pre_store "$src"); then
                error "Import failed: could not keep a copy of ${src} under ${BACKUP_DIR}/legacy/. Nothing was written."
                exit 1
            fi
        fi
        if ! _store_python import-write "${tmpd}/model.json" "$STORE_FILE"; then
            error "Import failed. Nothing was written."
            exit 1
        fi
        info "Store written to ${STORE_FILE}."
        if [[ -n "$pre" ]]; then
            info "Pre-store ${src} kept as ${pre} ('tacctl store rollback' returns to it)."
        fi
        exit 0
    fi

    # --check: steps 2-4 of the equivalence proof. Nothing persistent.
    echo "  import + validate:   OK"
    local rc=0 proven=1
    store_render_hook "${tmpd}/model.json" "${tmpd}/tacquito.yaml" || rc=$?
    if (( rc == 2 )); then
        echo "  render:              SKIPPED (no renderer available)"
        echo "  equivalence:         SKIPPED"
        echo "  daemon load-smoke:   SKIPPED"
        proven=0
    elif (( rc != 0 )); then
        echo "  render:              FAILED"
        exit 1
    else
        echo "  render:              OK"
        echo "  equivalence:"
        local diff_out
        rc=0
        diff_out=$(store_equiv_check "$src" "${tmpd}/tacquito.yaml") || rc=$?
        printf '%s\n' "$diff_out" | sed 's/^/    /'
        if (( rc != 0 )); then
            echo ""
            error "Rendered config is not equivalent to ${src}."
            exit 1
        fi
        rc=0
        store_smoke_hook "${tmpd}/tacquito.yaml" || rc=$?
        if (( rc == 2 )); then
            echo "  daemon load-smoke:   SKIPPED"
        elif (( rc != 0 )); then
            echo "  daemon load-smoke:   FAILED"
            exit 1
        else
            echo "  daemon load-smoke:   OK"
        fi
    fi
    echo ""
    if (( ! proven )); then
        warn "Import is clean, but equivalence with ${src} was not proven."
        exit 3
    fi
    info "Check passed. Nothing was written."
    exit 0
}

# --- The pre-store config and rollback (plan 4.4) ---------------------------
#
# The first import of the live tacquito.yaml ("the flip") keeps that file as
# backups/legacy/tacquito.yaml.pre-store.<ts> (0600: it holds the shared
# secrets and hashes). 'tacctl store rollback' puts the newest one back and
# removes the store, which returns the install to legacy read-only mode.

# store_pre_store_latest: print the path of the newest pre-store file.
# Returns 1, printing nothing, when there is none.
store_pre_store_latest() {
    local f newest=""
    for f in "${BACKUP_DIR}/legacy"/tacquito.yaml.pre-store.*; do
        [[ -f "$f" && ! -L "$f" ]] || continue
        if [[ -z "$newest" || "$f" > "$newest" ]]; then
            newest="$f"
        fi
    done
    [[ -n "$newest" ]] || return 1
    echo "$newest"
}

# store_keep_pre_store <file>: keep a copy of <file> as a pre-store file and
# print its path. An identical newest copy is reused, so a repeated or
# resumed import does not pile them up.
store_keep_pre_store() {
    local src="$1" dir="${BACKUP_DIR}/legacy" newest ts dest n=0
    if newest=$(store_pre_store_latest) && cmp -s "$src" "$newest"; then
        echo "$newest"
        return 0
    fi
    mkdir -p "$dir" || return 1
    chmod 700 "$dir" || return 1
    ts=$(date +%Y%m%d_%H%M%S)
    dest="${dir}/tacquito.yaml.pre-store.${ts}"
    while [[ -e "$dest" || -L "$dest" ]]; do
        n=$((n + 1))
        dest="${dir}/tacquito.yaml.pre-store.${ts}.${n}"
    done
    cp "$src" "$dest" || return 1
    chmod 600 "$dest" || return 1
    echo "$dest"
}

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
    restart_service
    info "Rolled back: ${CONFIG} is the pre-store file again and the store is gone (legacy read-only mode)."
    info "To move to the store again: 'tacctl store import --check', then 'tacctl upgrade' (or 'tacctl store import' and 'tacctl config render --force')."
    echo ""
}

# --- CLI: tacctl store ... --------------------------------------------------

cmd_store_usage() {
    echo ""
    echo -e "${BOLD}tacctl store${NC} — canonical store (users, groups, scopes, filters)"
    echo ""
    echo "  show [--json]                          Print the model (YAML by default)."
    echo "                                         Includes shared secrets and password hashes."
    echo "  import [--check|--force] [--replace] [<file>]"
    echo "                                         Import a legacy tacquito.yaml (default: the live one)."
    echo "      --check     write nothing; report what an import would do"
    echo "      --force     drop content the store cannot represent (each item is listed)"
    echo "      --replace   overwrite an existing store"
    echo "  rollback                               Undo the import: restore the pre-store tacquito.yaml, remove"
    echo "                                         the store, restart (back to legacy read-only mode)."
    echo ""
}

cmd_store_show() {
    local fmt="yaml"
    case "${1:-}" in
        "")      ;;
        --json)  fmt="json" ;;
        *)
            error "Usage: tacctl store show [--json]"
            return 2
            ;;
    esac
    model_load || return 1
    if [[ "$(model_mode)" == "legacy" ]]; then
        warn "No store yet — showing the model derived from ${CONFIG} (legacy read-only mode)." >&2
    fi
    _store_python show "$fmt" < <(printf '%s' "$_TACCTL_MODEL_CACHE")
}

cmd_store() {
    local sub="${1:-}"
    shift || true
    case "$sub" in
        show)   cmd_store_show "$@" ;;
        import) store_import "$@" ;;
        rollback) cmd_store_rollback "$@" ;;
        ""|help|-h|--help) cmd_store_usage ;;
        *)
            error "Unknown store subcommand '${sub}'."
            cmd_store_usage
            return 1
            ;;
    esac
}
