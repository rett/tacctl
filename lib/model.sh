# shellcheck shell=bash
# tacctl lib/model.sh -- the read interface for users, groups, scopes and filters (store loader + legacy tacquito.yaml loader)
# Sourced by bin/tacctl.sh (see the load block there for ordering); not executable.
#
# One JSON document -- the model -- describes every user, group, scope and
# prefix filter, independent of any daemon's file format:
#
#   { "version": 1,
#     "groups":  { <name>: {priv_lvl, juniper_class, builtin} },
#     "users":   { <name>: {group, scopes[], hash|null, disabled,
#                           password_changed|null, accounting_sink} },
#     "scopes":  { <name>: {prefixes[], secret, protocols[]|null} },
#     "filters": { "allow": [], "deny": [] } }
#
# Two loaders produce it:
#   store loader   reads store.yaml (normal mode);
#   legacy loader  parses a tacquito.yaml with yaml.safe_load. It is the
#                  read-only fallback while no store exists, and the importer
#                  ('tacctl store import', lib/store.sh).
# Both yield the same document for the same data, so callers never need to
# know which one ran (model_mode tells them when they must, e.g. to refuse
# a mutation in legacy mode).
#
# The model holds shared secrets and password hashes. It is cached in a shell
# variable and handed to python on stdin, never on argv.

# --- Cache control ----------------------------------------------------------
# Same pattern as _TACCTL_CFG_CACHE in lib/conf.sh: empty = cold. A cache
# filled inside $(...) dies with that subshell, so a command that makes
# several model_* calls should call model_load once in its own shell first.
_TACCTL_MODEL_CACHE=""
_model_invalidate() { _TACCTL_MODEL_CACHE=""; }

# model_mode: prints 'store' when store.yaml exists, else 'legacy'.
model_mode() {
    if [[ -f "$STORE_FILE" ]]; then
        echo "store"
    else
        echo "legacy"
    fi
}

# model_load: fill the cache (no output). Returns non-zero, with a message on
# stderr, when neither a store nor a legacy config can be loaded.
model_load() {
    [[ -n "$_TACCTL_MODEL_CACHE" ]] && return 0
    local out
    if [[ -f "$STORE_FILE" ]]; then
        out=$(_store_python dump-store "$STORE_FILE") || return 1
    elif [[ -f "$CONFIG" ]]; then
        out=$(_store_python dump-legacy "$CONFIG" "$PASSWORD_DATES_DIR" "${BACKUP_DIR}/disabled") || return 1
    else
        error "No store at ${STORE_FILE} and no config at ${CONFIG}."
        return 1
    fi
    _TACCTL_MODEL_CACHE="$out"
}

# model_dump: print the whole model as one line of JSON.
model_dump() {
    model_load || return 1
    printf '%s\n' "$_TACCTL_MODEL_CACHE"
}

_model_query() {
    model_load || return 1
    _store_python get "$@" < <(printf '%s' "$_TACCTL_MODEL_CACHE")
}

# Accessors. Conventions shared by all of them:
#   - a list accessor prints names one per line, sorted;
#   - model_<kind> <name> prints that entry as JSON (with "name" added) and
#     returns 1, printing nothing, when it does not exist -- so it doubles as
#     the existence test;
#   - model_<kind> <name> <field> prints one field: a scalar as text (true /
#     false for booleans, empty for null), a list one item per line.

# model_users: every user name, including the 'root' accounting sink.
model_users()  { _model_query users; }
# model_user <name> [group|scopes|hash|disabled|password_changed|accounting_sink]
model_user()   { _model_query users "$@"; }
# model_groups: every group name.
model_groups() { _model_query groups; }
# model_group <name> [priv_lvl|juniper_class|builtin]
model_group()  { _model_query groups "$@"; }
# model_scopes: every scope name.
model_scopes() { _model_query scopes; }
# model_scope <name> [prefixes|secret|protocols]
model_scope()  { _model_query scopes "$@"; }
# model_filters [allow|deny]: JSON of both lists, or one list a CIDR per line.
model_filters() { _model_query filters "$@"; }

# --- Python: legacy loader, import, accessors, equivalence ------------------
# Appended to _store_py (lib/store.sh), whose names it uses.
_model_py() {
    cat <<'PY'

# ---- legacy tacquito.yaml loader ------------------------------------------
#
# Builds the model from the structure yaml.safe_load returns, so anchor
# layout, section comments and spacing are irrelevant. An alias resolves to
# the very same Python object as its anchor, which is how top-level anchor
# holders are told apart from content nothing refers to.
#
# The loader always returns the model a forced import would produce, plus a
# report with three lists:
#   dropped  content the store cannot represent (import fails unless --force)
#   errors   problems no flag can fix (import always fails)
#   notes    things the operator should know that lose nothing
# No message contains a secret or a hash.

LEGACY_CONSTANTS = ('authenticator_type_bcrypt', 'action_deny', 'action_permit',
                    'accounter_type_file', 'handler_type_start', 'provider_type_prefix')
LEGACY_TOP_KEYS = ('users', 'secrets', 'prefix_allow', 'prefix_deny')
T_BCRYPT, T_FILE_ACCOUNTER, T_HANDLER_START, T_PROVIDER_PREFIX = 1, 3, 1, 1


def _file_accounter_ok(a):
    return (isinstance(a, dict) and set(a) <= {'name', 'type', 'options'}
            and a.get('name') == 'tacquito_accounter'
            and a.get('type') == T_FILE_ACCOUNTER and not a.get('options'))


def _sidecar(dirpath, fname, rep):
    """First line of a sidecar file, or None when there is none."""
    if not dirpath:
        return None
    try:
        with open(os.path.join(dirpath, fname)) as f:
            return f.read().strip()
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError as e:
        rep['notes'].append(f"{fname}: sidecar file not readable ({e.strerror}); ignored")
        return None


def _legacy_group(g, rep, refs):
    """One inlined group dict -> {priv_lvl, juniper_class, builtin}."""
    name = g['name']
    label = f"group '{name}'"
    for k in g:
        if k not in ('name', 'services', 'commands', 'accounter', 'authenticator'):
            rep['dropped'].append(f"{label}: unsupported key '{k}'")
    if g.get('authenticator') is not None:
        refs.add(id(g['authenticator']))
        rep['dropped'].append(f"{label}: group-level authenticator (the store keeps one per user)")
    acc = g.get('accounter')
    if acc is not None:
        refs.add(id(acc))
        if not _file_accounter_ok(acc):
            rep['dropped'].append(f"{label}: accounter other than the file accounter")
    priv = cls = None
    services = g.get('services') or []
    if not isinstance(services, list):
        rep['errors'].append(f"{label}: services is not a list")
        services = []
    for svc in services:
        if not isinstance(svc, dict):
            rep['errors'].append(f"{label}: a service entry is not a mapping")
            continue
        refs.add(id(svc))
        sname = str(svc.get('name', '')).strip()
        if sname in ('shell', 'exec'):
            want, have = 'priv-lvl', priv
        elif sname == 'junos-exec':
            want, have = 'local-user-name', cls
        else:
            rep['dropped'].append(f"{label}: service '{sname}' (only shell and junos-exec are stored)")
            continue
        slabel = f"{label}: service '{sname}'"
        if have is not None:
            rep['dropped'].append(f"{slabel}: second definition of the same service")
            continue
        for k in svc:
            if k not in ('name', 'set_values', 'match', 'is_optional'):
                rep['dropped'].append(f"{slabel}: unsupported key '{k}'")
        if svc.get('match'):
            rep['dropped'].append(f"{slabel}: match conditions")
        if svc.get('is_optional'):
            rep['dropped'].append(f"{slabel}: is_optional")
        val = None
        set_values = svc.get('set_values') or []
        if not isinstance(set_values, list):
            rep['errors'].append(f"{slabel}: set_values is not a list")
            set_values = []
        for sv in set_values:
            if not isinstance(sv, dict):
                rep['errors'].append(f"{slabel}: a set_values entry is not a mapping")
                continue
            vname = str(sv.get('name', '')).strip()
            if vname != want:
                rep['dropped'].append(f"{slabel}: extra set_value '{vname}'")
                continue
            if val is not None:
                rep['dropped'].append(f"{slabel}: second '{vname}' set_value")
                continue
            for k in sv:
                if k not in ('name', 'values', 'is_optional'):
                    rep['dropped'].append(f"{slabel}: set_value '{vname}': unsupported key '{k}'")
            if sv.get('is_optional'):
                rep['dropped'].append(f"{slabel}: set_value '{vname}': is_optional")
            values = sv.get('values') or []
            if not isinstance(values, list):
                values = [values]
            if len(values) > 1:
                rep['dropped'].append(f"{slabel}: set_value '{vname}': more than one value (first kept)")
            if values:
                val = values[0]
        if val is None:
            continue
        if want == 'priv-lvl':
            if is_int(val) or (isinstance(val, str) and re.fullmatch(r'[0-9]+', val.strip())):
                priv = int(val)
                if sname == 'exec':
                    rep['notes'].append(
                        f"{label}: legacy service name 'exec' is stored as the Cisco shell service "
                        "(rendered as 'shell', what 'tacctl upgrade' already migrates to)")
            else:
                rep['errors'].append(f"{label}: priv-lvl is not a number")
        else:
            cls = str(val).strip()
    if priv is None and not any(e.startswith(label + ': priv-lvl') for e in rep['errors']):
        rep['errors'].append(f"{label}: no shell service with a priv-lvl value")
    if cls is None:
        rep['errors'].append(f"{label}: no junos-exec service with a local-user-name value")
    return {'priv_lvl': priv, 'juniper_class': cls, 'builtin': name in BUILTIN_GROUPS}


def _parse_prefix_block(block):
    """The `prefixes: |` JSON block -> list of strings, as read_scope_prefixes
    reads it (JSON first, quoted-string scrape as the fallback)."""
    if not block:
        return []
    try:
        arr = json.loads(block)
        if isinstance(arr, list):
            return [c for c in arr if isinstance(c, str)]
    except ValueError:
        pass
    return re.findall(r'"([^"]+)"', block)


def legacy_load(path, dates_dir='', disabled_dir=''):
    rep = {'dropped': [], 'errors': [], 'notes': []}
    try:
        with open(path) as f:
            doc = yaml.safe_load(f)
    except yaml.YAMLError as e:
        raise StoreError(yaml_problem(path, e))
    except OSError as e:
        raise StoreError(f'{path}: {e.strerror}')
    if doc is None:
        doc = {}
    if not isinstance(doc, dict):
        raise StoreError(f'{path}: top level is not a YAML mapping')

    model = {'version': STORE_VERSION, 'groups': {}, 'users': {}, 'scopes': {},
             'filters': {'allow': [], 'deny': []}}
    refs = set()          # id() of every dict reached through users/groups
    group_src = {}        # name -> source dict, to detect conflicting copies

    def register_group(g, where):
        if not isinstance(g, dict) or not isinstance(g.get('name'), str) or not g['name']:
            rep['errors'].append(f"{where}: group entry without a usable name (quote names that YAML reads as numbers or booleans)")
            return None
        name = g['name']
        refs.add(id(g))
        if name in group_src:
            if group_src[name] is not g and group_src[name] != g:
                rep['errors'].append(f"group '{name}' is defined more than once with different content")
            return name
        group_src[name] = g
        model['groups'][name] = _legacy_group(g, rep, refs)
        return name

    # ---- users ----
    users = doc.get('users') or []
    if not isinstance(users, list):
        rep['errors'].append("'users' is not a list")
        users = []
    for idx, u in enumerate(users):
        if not isinstance(u, dict):
            rep['errors'].append(f"users[{idx}]: not a mapping")
            continue
        name = u.get('name')
        if not isinstance(name, str) or not name:
            rep['errors'].append(f"users[{idx}]: no usable name (quote names that YAML reads as numbers or booleans)")
            continue
        label = f"user '{name}'"
        if name in model['users']:
            rep['errors'].append(f"{label}: defined more than once")
            continue
        for k in u:
            if k not in ('name', 'scopes', 'groups', 'services', 'commands', 'authenticator', 'accounter'):
                rep['dropped'].append(f"{label}: unsupported key '{k}'")
        if u.get('services'):
            rep['dropped'].append(f"{label}: user-level services override")
        if u.get('commands'):
            rep['dropped'].append(f"{label}: user-level commands override")

        groups = u.get('groups') or []
        if not isinstance(groups, list):
            groups = [groups]
        if len(groups) != 1:
            if not groups:
                rep['dropped'].append(f"{label}: no group, so the user itself cannot be stored (exactly one group is required)")
                continue
            rep['dropped'].append(f"{label}: {len(groups)} groups (only the first is kept)")
        gname = register_group(groups[0], label)
        for extra in groups[1:]:
            if isinstance(extra, dict):
                refs.add(id(extra))
        if gname is None:
            continue

        sink = name in SINK_USERS
        hash_val, disabled = None, True
        auth = u.get('authenticator')
        if isinstance(auth, dict):
            refs.add(id(auth))
        if auth is None:
            rep['dropped'].append(f"{label}: no authenticator of its own; stored as disabled with no password")
        elif not isinstance(auth, dict) or auth.get('type') != T_BCRYPT:
            rep['dropped'].append(f"{label}: non-bcrypt authenticator; stored as disabled with no password")
        else:
            opts = auth.get('options') or {}
            if not isinstance(opts, dict):
                opts = {}
            for k in list(auth) + list(opts):
                if k not in ('type', 'options', 'hash'):
                    rep['dropped'].append(f"{label}: authenticator: unsupported key '{k}'")
            h = opts.get('hash')
            if is_int(h):
                # An unquoted hash whose hex happens to be all digits loads
                # as a YAML integer. Every bcrypt hex starts with "2432", so
                # the decimal text is exactly what the file says.
                h = str(h)
            low =h.strip().lower() if isinstance(h, str) else None
            if low == DISABLED_MARKER_HEX or (isinstance(h, str) and h.strip() == 'DISABLED'):
                # Disabled account. 'user disable' parks the real hash in a
                # sidecar; seeded accounts never had one.
                if not sink and RE_USER.fullmatch(name):
                    saved = _sidecar(disabled_dir, f'{name}.hash', rep)
                    if saved is not None:
                        hash_val = normalize_hash(saved)
                        if hash_val is None or hash_val == DISABLED_MARKER_HEX:
                            hash_val = None
                            rep['dropped'].append(
                                f"{label}: saved hash of the disabled account is not a bcrypt hash "
                                "('user enable' would have nothing to restore)")
            elif low is not None and bcrypt_hex_ok(low):
                if sink:
                    rep['dropped'].append(
                        f"{label}: carries a real password hash; the accounting sink is stored without one and stays disabled")
                else:
                    hash_val, disabled = low, False
            else:
                rep['dropped'].append(f"{label}: password hash is not a bcrypt hash; stored as disabled with no password")

        acc = u.get('accounter')
        if acc is None:
            rep['notes'].append(f"{label}: has no accounter of its own; the rendered config always attaches the file accounter")
        else:
            refs.add(id(acc))
            if not _file_accounter_ok(acc):
                rep['dropped'].append(f"{label}: accounter other than the file accounter")

        scopes = u.get('scopes')
        if scopes is None:
            scopes = []
            rep['notes'].append(f"{label}: has no scopes and can authenticate from nowhere")
        if not isinstance(scopes, list) or any(not isinstance(s, str) for s in scopes):
            rep['errors'].append(f"{label}: scopes is not a list of names (quote names that YAML reads as numbers or booleans)")
            scopes = [s for s in scopes if isinstance(s, str)] if isinstance(scopes, list) else []

        changed = None
        if RE_USER.fullmatch(name):
            date = _sidecar(dates_dir, f'{name}.date', rep)
            if date:
                if _check_field({'type': 'date'}, date) is None:
                    changed = date
                else:
                    rep['notes'].append(f"{label}: password-date file does not hold a YYYY-MM-DD date; ignored")

        model['users'][name] = {'group': gname, 'scopes': list(scopes), 'hash': hash_val,
                                'disabled': disabled, 'password_changed': changed,
                                'accounting_sink': sink}

    # ---- top-level keys: groups no user references, anchors, strays ----
    for key, val in doc.items():
        if key in LEGACY_TOP_KEYS or not isinstance(val, dict):
            continue
        if id(val) not in refs and 'name' in val and isinstance(val.get('services'), list):
            register_group(val, f"top-level '{key}'")
    for key, val in doc.items():
        if key in LEGACY_TOP_KEYS:
            continue
        if isinstance(val, dict):
            if id(val) in refs:
                continue
            if 'name' in val and 'set_values' in val:
                rep['notes'].append(f"top-level '{key}': service anchor no group uses; ignored")
            elif 'type' in val and isinstance(val.get('options'), dict) and 'hash' in val['options']:
                rep['notes'].append(f"top-level '{key}': authenticator anchor no user uses; ignored")
            elif _file_accounter_ok(val):
                pass
            else:
                rep['dropped'].append(f"unknown top-level key '{key}'")
        elif key in LEGACY_CONSTANTS and is_int(val):
            pass
        else:
            rep['dropped'].append(f"unknown top-level key '{key}'")

    # ---- scopes: secrets[] entries grouped by name ----
    secrets = doc.get('secrets') or []
    if not isinstance(secrets, list):
        rep['errors'].append("'secrets' is not a list")
        secrets = []
    keys_by_scope = {}
    for idx, s in enumerate(secrets):
        if not isinstance(s, dict):
            rep['errors'].append(f"secrets[{idx}]: not a mapping")
            continue
        name = s.get('name')
        if name is None or name == '':
            rep['dropped'].append(f"secrets[{idx}]: entry without a name")
            continue
        if not isinstance(name, str):
            rep['errors'].append(f"secrets[{idx}]: name is not a string (quote names that YAML reads as numbers or booleans)")
            continue
        label = f"scope '{name}' (secrets[{idx}])"
        if s.get('type') != T_PROVIDER_PREFIX:
            rep['dropped'].append(f"{label}: non-prefix secret provider; entry skipped")
            continue
        for k in s:
            if k not in ('name', 'secret', 'handler', 'type', 'options'):
                rep['dropped'].append(f"{label}: unsupported key '{k}'")
        handler = s.get('handler')
        if not isinstance(handler, dict) or handler.get('type') != T_HANDLER_START:
            rep['dropped'].append(f"{label}: handler other than the standard start handler")
        elif handler.get('options') or set(handler) - {'type', 'options'}:
            rep['dropped'].append(f"{label}: handler options")
        sec = s.get('secret')
        if not isinstance(sec, dict):
            sec = {}
        for k in sec:
            if k not in ('group', 'key'):
                rep['dropped'].append(f"{label}: secret: unsupported key '{k}'")
        key = sec.get('key')
        if not isinstance(key, str):
            # A non-string scalar (unquoted digits, yes/no) is read
            # differently by PyYAML and by the daemon; guessing would
            # silently change the shared secret.
            rep['errors'].append(f"{label}: secret.key is missing or not a YAML string (quote it)")
            key = None
        opts = s.get('options') or {}
        if not isinstance(opts, dict):
            rep['errors'].append(f"{label}: options is not a mapping")
            opts = {}
        for k in opts:
            if k != 'prefixes':
                rep['dropped'].append(f"{label}: option '{k}'")
        block = opts.get('prefixes')
        if block is not None and not isinstance(block, str):
            rep['errors'].append(f"{label}: prefixes is not a text block")
            block = None
        scope = model['scopes'].setdefault(name, {'prefixes': [], 'secret': key, 'protocols': None})
        if scope['secret'] is None:
            scope['secret'] = key
        if key is not None:
            keys_by_scope.setdefault(name, []).append(key)
        for c in _parse_prefix_block(block):
            canon = canonical_cidr(c)
            if canon is None:
                rep['dropped'].append(f"{label}: invalid prefix {c!r}")
            elif canon not in scope['prefixes']:
                scope['prefixes'].append(canon)
    for name, keys in keys_by_scope.items():
        if len(set(keys)) > 1:
            rep['errors'].append(
                f"scope '{name}' has {len(keys)} entries but {len(set(keys))} distinct secret.key values "
                "— entries must share a key")

    # ---- prefix filters ----
    for src_key, dst in (('prefix_allow', 'allow'), ('prefix_deny', 'deny')):
        items = doc.get(src_key) or []
        if not isinstance(items, list):
            rep['errors'].append(f"'{src_key}' is not a list")
            continue
        for c in items:
            canon = canonical_cidr(c)
            if canon is None:
                rep['dropped'].append(f"{src_key}: invalid prefix {c!r}")
            elif canon not in model['filters'][dst]:
                model['filters'][dst].append(canon)

    return model, rep


# ---- import ---------------------------------------------------------------

def _carry_over(model, existing_path, rep):
    """Re-import over an existing store: keep what a tacquito.yaml cannot
    carry, so adopting hand edits never loses it."""
    try:
        old = store_normalize(store_load_raw(existing_path))
    except StoreError as e:
        rep['notes'].append(f"existing store could not be read ({e}); nothing carried over")
        return
    kept = {'protocols': 0, 'password_changed': 0, 'hash': 0}
    for name, s in model['scopes'].items():
        prev = old['scopes'].get(name)
        if isinstance(prev, dict) and prev.get('protocols'):
            s['protocols'] = prev['protocols']
            kept['protocols'] += 1
    for name, u in model['users'].items():
        prev = old['users'].get(name)
        if not isinstance(prev, dict):
            continue
        if u['password_changed'] is None and prev.get('password_changed'):
            u['password_changed'] = prev['password_changed']
            kept['password_changed'] += 1
        if (u['disabled'] and u['hash'] is None and not u['accounting_sink']
                and bcrypt_hex_ok(prev.get('hash'))):
            u['hash'] = prev['hash']
            kept['hash'] += 1
    if kept['protocols']:
        rep['notes'].append(f"kept the protocols filter of {kept['protocols']} scope(s) from the existing store")
    if kept['password_changed']:
        rep['notes'].append(f"kept the password date of {kept['password_changed']} user(s) from the existing store")
    if kept['hash']:
        rep['notes'].append(f"kept the saved password of {kept['hash']} disabled user(s) from the existing store")


def import_load(src, dates_dir, disabled_dir, existing, force):
    """Load, report, decide. Returns (ok, model). Prints the report."""
    model, rep = legacy_load(src, dates_dir, disabled_dir)
    if existing:
        _carry_over(model, existing, rep)
    model = store_canonicalize(model)
    # Validation problems are fatal, but only worth listing once the loader
    # itself has nothing fatal to say (its errors usually cause them).
    verrs = [] if rep['errors'] else store_validate(model)

    users = model['users']
    n_disabled = sum(1 for u in users.values() if u['disabled'] and not u['accounting_sink'])
    n_sink = sum(1 for u in users.values() if u['accounting_sink'])
    print(f"  Source:   {src}")
    print(f"  Groups:   {len(model['groups'])}")
    detail = f"{n_disabled} disabled"
    if n_sink:
        detail += f", {n_sink} accounting sink"
    print(f"  Users:    {len(users)} ({detail})")
    print(f"  Scopes:   {len(model['scopes'])}")
    print(f"  Filters:  allow {len(model['filters']['allow'])}, deny {len(model['filters']['deny'])}")
    if rep['notes']:
        print("\n  Notes:")
        for n in rep['notes']:
            print(f"    - {n}")
    if rep['dropped']:
        heading = 'Dropped (--force)' if force else 'Cannot be represented in the store'
        print(f"\n  {heading}:")
        for d in rep['dropped']:
            print(f"    - {d}")
    if rep['errors'] or verrs:
        print("\n  Errors:")
        for e in rep['errors'] + verrs:
            print(f"    - {e}")
    sys.stdout.flush()

    if rep['errors'] or verrs:
        print(f"\ntacctl store: {len(rep['errors']) + len(verrs)} error(s) must be fixed in {src} before it can be imported"
              + (" (--force does not override these)." if force else "."), file=sys.stderr)
        return False, model
    if rep['dropped'] and not force:
        print(f"\ntacctl store: {len(rep['dropped'])} item(s) cannot be represented in the store. "
              "Fix them, or re-run with --force to drop them.", file=sys.stderr)
        return False, model
    return True, model


# ---- accessors ------------------------------------------------------------

def _emit(value):
    if value is None:
        return
    if isinstance(value, bool):
        print('true' if value else 'false')
    elif isinstance(value, list):
        for item in value:
            print(item)
    else:
        print(value)


def model_get(model, argv):
    kind = argv[0]
    name = argv[1] if len(argv) > 1 else None
    field = argv[2] if len(argv) > 2 else None
    if kind == 'filters':
        if name is None:
            print(json.dumps(model['filters'], sort_keys=True))
        elif name in FILTER_KEYS:
            _emit(model['filters'].get(name) or [])
        else:
            raise StoreError(f"filters: unknown list '{name}'")
        return 0
    section = model[kind]
    if name is None:
        for n in sorted(section):
            print(n)
        return 0
    ent = section.get(name)
    if ent is None:
        return 1
    if field is None:
        print(json.dumps(dict(ent, name=name), sort_keys=True))
    elif field in STORE_SCHEMA[kind]['fields']:
        _emit(ent.get(field))
    else:
        raise StoreError(f"{STORE_SCHEMA[kind]['label']}: unknown field '{field}'")
    return 0


# ---- equivalence of two tacquito.yaml files (plan 4.3 step 3) --------------

def _equiv_normalize(doc, fingerprint):
    """Reduce a loaded tacquito.yaml to what the daemon acts on.

    users    dict by name; scopes sorted; group/authenticator/accounter dicts
             as loaded (aliases already inlined), with two legacy spellings
             folded: service name 'exec' -> 'shell', hash 'DISABLED' -> marker.
    secrets  tacquito walks secrets[] and takes the first entry with a prefix
             containing the client. Two CIDRs either nest or are disjoint, so
             an entry is dead exactly when an earlier one contains it, and
             among the live entries the most specific wins whatever the order.
             The routing is therefore fully described by the live
             (prefix, scope, key) set plus the list of dead entries -- which
             compares equal for harmless reorderings and for multi-prefix
             entries versus one entry per prefix, and unequal whenever a
             client would land in a different scope.
    filters  sets.
    """
    notes = []
    out = {'users': {}, 'secrets': {'routes': [], 'shadowed': []},
           'prefix_allow': [], 'prefix_deny': []}
    if not isinstance(doc, dict):
        return out, notes

    def clean(node):
        if isinstance(node, dict):
            res = {k: clean(v) for k, v in node.items()}
            if res.get('name') == 'exec' and 'set_values' in res:
                res['name'] = 'shell'
                notes.append("service name 'exec' compared as 'shell'")
            return res
        if isinstance(node, list):
            return [clean(v) for v in node]
        return node

    for u in doc.get('users') or []:
        if not isinstance(u, dict):
            continue
        ent = clean({k: v for k, v in u.items() if k != 'name'})
        if isinstance(ent.get('scopes'), list):
            ent['scopes'] = sorted(str(s) for s in ent['scopes'])
        auth = ent.get('authenticator')
        if isinstance(auth, dict) and isinstance(auth.get('options'), dict) and 'hash' in auth['options']:
            h = str(auth['options']['hash']).strip()
            if h == 'DISABLED' or h.lower() == DISABLED_MARKER_HEX:
                auth['options']['hash'] = '<disabled>'
            else:
                auth['options']['hash'] = fingerprint(h.lower())
        out['users'][str(u.get('name'))] = ent

    live = []   # (network, scope, key fingerprint)
    for s in doc.get('secrets') or []:
        if not isinstance(s, dict):
            continue
        name = str(s.get('name'))
        key = (s.get('secret') or {}).get('key') if isinstance(s.get('secret'), dict) else None
        fp = fingerprint(str(key))
        block = (s.get('options') or {}).get('prefixes') if isinstance(s.get('options'), dict) else None
        for c in _parse_prefix_block(block if isinstance(block, str) else ''):
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError:
                continue
            cover = next((n for n, _, _ in live
                          if n.version == net.version and net.subnet_of(n)), None)
            if cover is not None:
                out['secrets']['shadowed'].append(
                    {'prefix': str(net), 'scope': name, 'never_matches_because_of': str(cover)})
            else:
                live.append((net, name, fp))
    live.sort(key=lambda t: cidr_key(str(t[0])))
    out['secrets']['routes'] = [{'prefix': str(n), 'scope': nm, 'key': fp} for n, nm, fp in live]
    out['secrets']['shadowed'].sort(key=lambda d: cidr_key(d['prefix']))

    for k in ('prefix_allow', 'prefix_deny'):
        items = doc.get(k) or []
        if isinstance(items, list):
            out[k] = sorted({canonical_cidr(c) or str(c) for c in items})
    return out, sorted(set(notes))


def equiv_check(live_path, rendered_path):
    # Secrets and hashes are compared, not shown: both sides get the same
    # keyed fingerprint, and the key dies with this process.
    salt = os.urandom(16)

    def fingerprint(value):
        return '<redacted:' + hmac.new(salt, value.encode(), hashlib.sha256).hexdigest()[:10] + '>'

    sides = []
    for path in (live_path, rendered_path):
        try:
            with open(path) as f:
                doc = yaml.safe_load(f)
        except yaml.YAMLError as e:
            raise StoreError(yaml_problem(path, e))
        except OSError as e:
            raise StoreError(f'{path}: {e.strerror}')
        sides.append(_equiv_normalize(doc, fingerprint))
    (a, notes_a), (b, _notes_b) = sides
    for n in notes_a:
        print(f'note: {live_path}: {n}')
    if a == b:
        print('EQUIVALENT')
        return 0
    ta = json.dumps(a, indent=2, sort_keys=True).splitlines(keepends=True)
    tb = json.dumps(b, indent=2, sort_keys=True).splitlines(keepends=True)
    sys.stdout.writelines(difflib.unified_diff(ta, tb, fromfile='live (normalised)',
                                               tofile='rendered (normalised)'))
    print('NOT EQUIVALENT')
    return 1
PY
}
