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
#     "scopes":  { <name>: {prefixes[], secret, protocols[]|null,
#                           vendor_attrs[]?, devices{cidr: vendor}?} },
#     "filters": { "allow": [], "deny": [] } }
#
# vendor_attrs and devices are in a scope's entry only when it has any
# (RADIUS only; see 'tacctl scope vendor-attrs' and 'tacctl scope devices').
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

# Run the read program on the cached model: _model_python get|view <args...>.
# It is the schema base (lib/store.sh: _store_base_py) plus the accessors and
# views below -- no YAML, no file access; the model arrives on stdin.
_model_python() {
    python3 <(_store_base_py; _model_read_py; _model_read_main_py) "$@"
}

_model_query() {
    model_load || return 1
    _model_python get "$@" < <(printf '%s' "$_TACCTL_MODEL_CACHE")
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
# model_scope <name> [prefixes|secret|protocols|vendor_attrs|devices]
# (devices: one '<cidr> <vendor>' line per tagged address, in stored order)
model_scope()  { _model_query scopes "$@"; }
# model_filters [allow|deny]: JSON of both lists, or one list a CIDR per line.
model_filters() { _model_query filters "$@"; }

# --- Views ------------------------------------------------------------------
# Canned read-only reports over the model (python: model_view below). They
# exist so a command needs one interpreter run for a table, not one per cell.
# Every view works the same in store and legacy mode. Lines are '|'-separated
# or key=value; names cannot contain either character.
_model_view() {
    model_load || return 1
    _model_python view "$@" < <(printf '%s' "$_TACCTL_MODEL_CACHE")
}

# Existence tests: return 0/1, print nothing. An empty name is never found.
model_user_exists()  { [[ -n "${1:-}" ]] && _model_view has users "$1"; }
model_group_exists() { [[ -n "${1:-}" ]] && _model_view has groups "$1"; }
model_scope_exists() { [[ -n "${1:-}" ]] && _model_view has scopes "$1"; }

# model_user_info <name>: key=value lines -- group, status (active|disabled),
# password_changed (date or 'unknown'), priv_lvl, juniper_class, hash_type
# (the '$2b$12$' prefix, empty when disabled), has_hash (1|0) -- then one
# 'scope=<name>|<1 if the scope exists, else 0>' line per scope. Returns 1,
# printing nothing, when the user does not exist. Never prints the hash.
model_user_info() { _model_view user-info "$1"; }

# model_user_privlvl <name>: priv-lvl of the user's group, or nothing when the
# user is unknown, disabled, the accounting sink, or its group is missing.
model_user_privlvl() { _model_view user-privlvl "$1"; }

# model_user_rows: 'name|group|status|password_changed|scope,scope' per user,
# by name, without the accounting sink.
model_user_rows() { _model_view user-rows; }

# model_group_rows: 'name|priv_lvl|juniper_class|users' by priv-lvl, highest
# first (equal levels in reverse name order). The user count leaves out the
# accounting sink.
model_group_rows() { _model_view group-rows; }

# model_group_users <group>: names of every user in the group (the accounting
# sink included), by name.
model_group_users() { _model_view group-users "$1"; }

# model_group_info: 'name|priv_lvl|juniper_class' per group, built-ins first
# (readonly, operator, superuser), then the rest by name.
model_group_info() { _model_view group-info; }

# model_scopes_by_routing: every scope name in the order listings use: by
# where the scope's most specific prefix sits in the daemon's first-match
# walk (the order of first appearance in the rendered secrets list).
model_scopes_by_routing() { _model_view scope-names; }

# model_scope_prefixes <scope>: its prefixes in display order -- longest
# prefix first, the order every listing has always used. ('model_scope <s>
# prefixes' prints them in stored order.) Unknown scope: no output.
model_scope_prefixes() { _model_view scope-prefixes "$1"; }

# model_scope_users <scope>: names of the users granted the scope, by name.
model_scope_users() { _model_view scope-users "$1"; }

# model_prefix_owner <cidr>: the scope holding exactly this network (after
# canonicalisation), or nothing.
model_prefix_owner() { [[ -n "${1:-}" ]] || return 0; _model_view prefix-owner "$1"; }

# model_scope_devices <scope>: its tagged addresses as '<cidr>|<vendor>'
# lines in display order (longest prefix first). Unknown scope: no output.
model_scope_devices() { _model_view scope-devices "$1"; }

# model_vendor_gaps: the scopes RADIUS serves that send no vendor attribute
# and are not Linux-host scopes (see the view), one per line. Reads the host
# registry (lib/linux_hosts.sh).
model_vendor_gaps() {
    local -a counts=()
    if [[ -s "${LINUX_HOSTS_FILE:-}" ]]; then
        mapfile -t counts < <(cut -d'|' -f4 "$LINUX_HOSTS_FILE" | awk 'NF { n[$0]++ } END { for (s in n) print s "=" n[s] }')
    fi
    _model_view vendor-gaps ${counts[@]+"${counts[@]}"}
}

# model_vendor_rows: '<scope>|<1 when its protocols let RADIUS serve it, else
# 0>|<enabled vendors, comma-separated>|<tagged vendors, comma-separated>|
# <number of tagged addresses>' per scope, by name.
model_vendor_rows() { _model_view vendor-rows; }

# --- Python: accessors and views --------------------------------------------
# The read side: needs only _store_base_py. Part of the full program too
# (_model_py includes it), so 'store show' and the importer see the same code.
_model_read_py() {
    cat <<'PY'

# ---- accessors ------------------------------------------------------------

def _emit(value):
    if value is None:
        return
    if isinstance(value, bool):
        print('true' if value else 'false')
    elif isinstance(value, list):
        for item in value:
            print(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            print(key, item)
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


# ---- views ----------------------------------------------------------------
#
# Each prints lines for a bash caller to read; none prints a secret or a
# hash. They take the model as either loader built it, so a legacy model with
# dangling references (a user pointing at a scope that is gone) still works.

BUILTIN_DISPLAY_ORDER = ('readonly', 'operator', 'superuser')
RFC1918 = {'10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'}


def user_is_disabled(u):
    """True when the user cannot authenticate: flagged, the accounting sink,
    or without a password. The renderer emits the marker in the same cases."""
    return bool(u.get('disabled') or u.get('accounting_sink') or not u.get('hash'))


def display_key(cidr):
    """Listing order: longest prefix first, IPv4 before IPv6, then address."""
    try:
        n = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return (1, 0, 0)
    return (-n.prefixlen, n.version, int(n.network_address))


def routing_pairs(scopes):
    """[(cidr, scope)] in the order the daemon tries them (as rendered)."""
    pairs = [(c, name) for name, s in scopes.items()
             for c in (s.get('prefixes') or []) if canonical_cidr(c) is not None]
    return sorted(pairs, key=lambda t: (cidr_key(t[0]), t[1]))


def scope_display_order(scopes):
    """Scope names by where their first prefix sits in the routing order;
    a scope without prefixes goes last."""
    order = []
    for _c, name in routing_pairs(scopes):
        if name not in order:
            order.append(name)
    return order + sorted(n for n in scopes if n not in order)


def vendor_summary(scope):
    """What 'scope list' shows of a scope's vendor attributes: the enabled
    vendors and how many addresses are tagged; '' when there is neither."""
    parts = []
    if scope.get('vendor_attrs'):
        parts.append(','.join(scope['vendor_attrs']))
    if scope.get('devices'):
        parts.append(f"{len(scope['devices'])} tagged")
    return ' + '.join(parts)


def model_view(model, argv):
    view, args = argv[0], argv[1:]
    users, groups, scopes = model['users'], model['groups'], model['scopes']
    filters = model.get('filters') or {}

    def members(scope):
        return sorted(n for n, u in users.items() if scope in (u.get('scopes') or []))

    def priv_of(user):
        g = groups.get(user.get('group')) or {}
        return g.get('priv_lvl')

    if view == 'has':
        return 0 if args[1] in model[args[0]] else 1

    if view == 'user-rows':
        for name in sorted(users):
            u = users[name]
            if u.get('accounting_sink'):
                continue
            status = 'disabled' if user_is_disabled(u) else 'active'
            print('|'.join([name, str(u.get('group') or ''), status,
                            u.get('password_changed') or 'unknown',
                            ','.join(u.get('scopes') or [])]))
        return 0

    if view == 'user-info':
        u = users.get(args[0])
        if u is None:
            return 1
        g = groups.get(u.get('group')) or {}
        disabled = user_is_disabled(u)
        hash_type = ''
        if not disabled:
            try:
                hash_type = binascii.unhexlify(u['hash'][:14]).decode('ascii')
            except (binascii.Error, ValueError, UnicodeDecodeError):
                hash_type = ''
        print(f"group={u.get('group') or ''}")
        print('status=' + ('disabled' if disabled else 'active'))
        print(f"password_changed={u.get('password_changed') or 'unknown'}")
        print(f"priv_lvl={'' if g.get('priv_lvl') is None else g['priv_lvl']}")
        print(f"juniper_class={g.get('juniper_class') or ''}")
        print(f'hash_type={hash_type}')
        print(f"has_hash={'1' if u.get('hash') else '0'}")
        for s in u.get('scopes') or []:
            print(f"scope={s}|{'1' if s in scopes else '0'}")
        return 0

    if view == 'user-privlvl':
        u = users.get(args[0])
        if u is not None and not user_is_disabled(u) and priv_of(u) is not None:
            print(priv_of(u))
        return 0

    if view == 'group-rows':
        counts = {}
        for u in users.values():
            if not u.get('accounting_sink'):
                counts[u.get('group')] = counts.get(u.get('group'), 0) + 1
        # Highest priv-lvl first; equal levels in reverse name order, the
        # order 'group list' has always printed (it used 'sort -nr').
        def by_priv(name):
            p = groups[name].get('priv_lvl')
            return (p if is_int(p) else -1, name)
        for name in sorted(groups, key=by_priv, reverse=True):
            g = groups[name]
            priv = 'n/a' if g.get('priv_lvl') is None else g['priv_lvl']
            print(f"{name}|{priv}|{g.get('juniper_class') or 'n/a'}|{counts.get(name, 0)}")
        return 0

    if view == 'group-users':
        for n in sorted(n for n, u in users.items() if u.get('group') == args[0]):
            print(n)
        return 0

    if view == 'group-info':
        first = [g for g in BUILTIN_DISPLAY_ORDER if g in groups]
        for name in first + sorted(g for g in groups if g not in first):
            g = groups[name]
            print(f"{name}|{'' if g.get('priv_lvl') is None else g['priv_lvl']}|{g.get('juniper_class') or ''}")
        return 0

    if view == 'scope-names':
        for name in scope_display_order(scopes):
            print(name)
        return 0

    if view == 'scope-prefixes':
        s = scopes.get(args[0]) or {}
        for c in sorted(s.get('prefixes') or [], key=display_key):
            print(c)
        return 0

    if view == 'scope-users':
        for n in members(args[0]):
            print(n)
        return 0

    if view == 'prefix-owner':
        target = canonical_cidr(args[0])
        if target is None:
            return 0
        for name in sorted(scopes):
            if target in [canonical_cidr(c) for c in (scopes[name].get('prefixes') or [])]:
                print(name)
                break
        return 0

    if view == 'scope-rows':
        # One line per (scope, prefix): the first carries the user count, the
        # default marker and the vendor attributes (see vendor_summary), the
        # rest leave those columns empty.
        default = args[0] if args else ''
        for name in scope_display_order(scopes):
            pfx = sorted(scopes[name].get('prefixes') or [], key=display_key) or ['(no prefix)']
            for idx, c in enumerate(pfx):
                if idx == 0:
                    print(f"{name}|{c}|{len(members(name))}|{'yes' if name == default else ''}"
                          f"|{vendor_summary(scopes[name])}")
                else:
                    print(f'|{c}|||')
        return 0

    if view == 'scope-devices':
        devices = (scopes.get(args[0]) or {}).get('devices') or {}
        for c in sorted(devices, key=display_key):
            print(f'{c}|{devices[c]}')
        return 0

    if view == 'device-problems':
        # device-problems <scope> <prefix csv> [<cidr> <vendor>]: what
        # device_problems (lib/store.sh) would say with that scope's prefixes
        # replaced (the scope may be new) and, optionally, one address tagged.
        # One message per line; returns 1 when there is any.
        trial = {n: dict(s) for n, s in scopes.items()}
        mine = trial.setdefault(args[0], {})
        mine['prefixes'] = [c for c in args[1].split(',') if c]
        if len(args) > 3:
            mine['devices'] = dict(mine.get('devices') or {}, **{args[2]: args[3]})
        problems = device_problems(trial)
        for name, c, msg in problems:
            print(f'{name}|{c}|{msg}')
        return 1 if problems else 0

    if view == 'vendor-gaps':
        # vendor-gaps [<scope>=<enrolled hosts>...]: scopes RADIUS serves that
        # send no vendor attribute (none enabled, nothing tagged) and are not
        # Linux-host scopes. A Linux-host scope: enrolled hosts use it, every
        # prefix is a single address, and there are no more of them than
        # hosts (what 'host enroll' creates, or a scope shared by hosts
        # only). pam_radius_auth reads no vendor attribute.
        hosts = {}
        for a in args:
            name, _sep, count = a.rpartition('=')
            hosts[name] = int(count)
        for name in sorted(scopes):
            s = scopes[name]
            if s.get('protocols') and 'radius' not in s['protocols']:
                continue
            if s.get('vendor_attrs') or s.get('devices'):
                continue
            pfx = [ipaddress.ip_network(c, strict=False) for c in (s.get('prefixes') or [])
                   if canonical_cidr(c) is not None]
            if (hosts.get(name, 0) > 0 and all(n.prefixlen == n.max_prefixlen for n in pfx)
                    and len(pfx) <= hosts[name]):
                continue
            print(name)
        return 0

    if view == 'vendor-rows':
        for name in sorted(scopes):
            s = scopes[name]
            devices = s.get('devices') or {}
            served = not s.get('protocols') or 'radius' in s['protocols']
            print('|'.join([name, '1' if served else '0', ','.join(s.get('vendor_attrs') or []),
                            ','.join(v for v in KNOWN_VENDORS if v in devices.values()),
                            str(len(devices))]))
        return 0

    if view == 'scope-routing':
        default = args[0] if args else ''
        rows = [(display_key(c), name, c) for name, s in scopes.items()
                for c in (s.get('prefixes') or ['(no prefix)'])]
        for _k, name, c in sorted(rows):
            print(f"{name}|{c}|{len(members(name))}|{'yes' if name == default else ''}")
        return 0

    if view == 'scope-lookup':
        query = args[0]
        q_net = q_host = None
        try:
            if '/' in query:
                q_net = ipaddress.ip_network(query, strict=False)
            else:
                q_host = ipaddress.ip_address(query)
        except ValueError as e:
            print(f'ERROR: invalid address or CIDR: {e}')
            return 2
        what = q_host if q_host is not None else q_net
        matches = []
        for c, name in routing_pairs(scopes):
            pnet = ipaddress.ip_network(c, strict=False)
            if pnet.version != what.version:
                continue
            if q_host is not None and q_host in pnet:
                matches.append((name, pnet))
            elif q_net is not None and (pnet == q_net or q_net.subnet_of(pnet)):
                matches.append((name, pnet))
        if not matches:
            if q_host is not None:
                print(f'No scope owns {q_host} — no prefix in any scope contains it.')
            else:
                print(f'No scope owns {q_net} — no prefix covers the full range.')
            return 1
        print(f"  {what} -> scope '{matches[0][0]}' (via prefix {matches[0][1]})")
        # The vendor tag, if the scope has one for it: the most specific
        # tagged range that holds the whole query (what its RADIUS client is).
        tags = []
        for c, vendor in ((scopes[matches[0][0]].get('devices')) or {}).items():
            tnet = ipaddress.ip_network(c, strict=False)
            if tnet.version != what.version:
                continue
            if (q_host is not None and q_host in tnet) or (q_net is not None and q_net.subnet_of(tnet)):
                tags.append((tnet, vendor))
        if tags:
            tnet, vendor = max(tags, key=lambda t: t[0].prefixlen)
            print(f"  Tagged {vendor} (scope devices entry {tnet}): over RADIUS it gets that vendor's attribute only")
        if len(matches) > 1:
            print('')
            print("  Also covered by (shadowed — the more specific prefix above wins):")
            for name, pnet in matches[1:]:
                print(f"    - scope '{name}' via prefix {pnet}")
        return 0

    if view == 'config-show':
        for name in scope_display_order(scopes):
            s = scopes[name]
            print(f"scope={name}|{len(s.get('secret') or '')}|{len(members(name))}")
            for c in sorted(s.get('prefixes') or [], key=display_key):
                print(f'prefix={c}')
        for key, grp, field in (('cisco_ro', 'readonly', 'priv_lvl'), ('cisco_op', 'operator', 'priv_lvl'),
                                ('cisco_rw', 'superuser', 'priv_lvl'), ('juniper_ro', 'readonly', 'juniper_class'),
                                ('juniper_op', 'operator', 'juniper_class'), ('juniper_rw', 'superuser', 'juniper_class')):
            val = (groups.get(grp) or {}).get(field)
            print(f"{key}={'NOT FOUND' if val is None else val}")
        print('allow=' + ', '.join(filters.get('allow') or []))
        print('deny=' + ', '.join(filters.get('deny') or []))
        return 0

    if view == 'linux-users':
        for n in members(args[0]):
            u = users[n]
            if u.get('accounting_sink') or user_is_disabled(u):
                continue
            p = priv_of(u)
            print(f"{n}|{'' if p is None else p}")
        return 0

    if view == 'status':
        min_secret = int(args[0])
        all_cidrs, weak, placeholder, no_prefix = [], [], [], []
        for name in sorted(scopes):
            s = scopes[name]
            key = s.get('secret') or ''
            if not s.get('prefixes'):
                no_prefix.append(name)
            all_cidrs.extend(s.get('prefixes') or [])
            if 'REPLACE' in key:
                placeholder.append(name)
            elif len(key) < min_secret:
                weak.append(f'{name}:{len(key)}')
        refs, unused = 0, set(scopes)
        orphans = []
        for n in sorted(users):
            for s in users[n].get('scopes') or []:
                refs += 1
                if s in scopes:
                    unused.discard(s)
                else:
                    orphans.append(f'{n}:{s}')
        print(f'user_count={len(users)}')
        print(f'scope_count={len(scopes)}')
        print(f'prefix_count={len(all_cidrs)}')
        print(f"prefix_unrestricted={'1' if set(all_cidrs) == RFC1918 else '0'}")
        print(f"prefix_has_v6={'1' if any(':' in c for c in all_cidrs) else '0'}")
        print(f"allow_has_v6={'1' if any(':' in c for c in (filters.get('allow') or [])) else '0'}")
        print('placeholder_scopes=' + ','.join(placeholder))
        print('weak_scopes=' + ','.join(weak))
        print('empty_prefix_scopes=' + ','.join(no_prefix))
        print(f'total_refs={refs}')
        print('empty_scopes=' + ','.join(sorted(unused)))
        for o in orphans:
            print(f'orphan={o}')
        for n in sorted(users):
            if users[n].get('password_changed'):
                print(f"pwdate={n}|{users[n]['password_changed']}")
        return 0

    if view == 'validate':
        # Checks 'config validate' makes on the model. 'full' adds the
        # reference checks store_validate already makes on a store, for a
        # legacy model nothing has validated.
        full = bool(args) and args[0] == 'full'
        errs = []
        if not users:
            errs.append('No users defined (tacquito refuses to serve such a config)')
        if not scopes:
            errs.append('No scopes defined (tacquito refuses to serve such a config)')
        for name in sorted(scopes):
            s = scopes[name]
            if 'REPLACE' in (s.get('secret') or ''):
                errs.append(f"Shared secret contains placeholder value (scope '{name}')")
            if full and not s.get('secret'):
                errs.append(f"Scope '{name}' has no shared secret")
            if full and not s.get('prefixes'):
                errs.append(f"Scope '{name}' has no prefixes")
        if full:
            for n in sorted(users):
                u = users[n]
                if n in RESERVED_USERS:
                    errs.append(f'User "{n}" uses a reserved name (remove with: tacctl user remove {n})')
                if u.get('group') not in groups:
                    errs.append(f"User '{n}' is in nonexistent group '{u.get('group')}'")
                for s in u.get('scopes') or []:
                    if s not in scopes:
                        errs.append(f"User '{n}' references nonexistent scope '{s}'")
        print(f'COUNT:users={len(users)}')
        print(f'COUNT:groups={len(groups)}')
        print(f'COUNT:scopes={len(scopes)}')
        for e in errs:
            print(f'ERROR:{e}')
        return 0

    raise StoreError(f'internal: unknown view {view!r}')
PY
}

# Entry point of the read program (see _model_python).
_model_read_main_py() {
    cat <<'PY'


if __name__ == '__main__':
    try:
        _model = json.load(sys.stdin)
        if sys.argv[1] == 'get':
            sys.exit(model_get(_model, sys.argv[2:]))
        elif sys.argv[1] == 'view':
            sys.exit(model_view(_model, sys.argv[2:]))
        raise StoreError(f'internal: unknown command {sys.argv[1]!r}')
    except StoreError as e:
        print(f'tacctl store: {e}', file=sys.stderr)
        sys.exit(1)
PY
}

# --- Python: legacy loader, import, equivalence -----------------------------
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
    """The `prefixes: |` JSON block -> list of strings, the way tacctl always
    read it (JSON first, quoted-string scrape as the fallback)."""
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
    kept = {'protocols': 0, 'password_changed': 0, 'hash': 0, 'vendor': 0}
    for name, s in model['scopes'].items():
        prev = old['scopes'].get(name)
        if isinstance(prev, dict) and prev.get('protocols'):
            s['protocols'] = prev['protocols']
            kept['protocols'] += 1
        if isinstance(prev, dict) and (prev.get('vendor_attrs') or prev.get('devices')):
            if prev.get('vendor_attrs'):
                s['vendor_attrs'] = list(prev['vendor_attrs'])
            if isinstance(prev.get('devices'), dict) and prev['devices']:
                s['devices'] = dict(prev['devices'])
            kept['vendor'] += 1
    # A tagged address whose prefix the imported file no longer has (or has
    # given to another scope) cannot be kept: the store refuses it.
    for name, c, _msg in device_problems(model['scopes']):
        del model['scopes'][name]['devices'][c]
        rep['dropped'].append(f"scope '{name}': the vendor tag of {c} (no prefix of the scope in this file contains it any more)")
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
    if kept['vendor']:
        rep['notes'].append(f"kept the RADIUS vendor attributes and tagged addresses of {kept['vendor']} scope(s) from the existing store")
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


PY
    _model_read_py
    cat <<'PY'

# ---- equivalence of two tacquito.yaml files (plan 4.3 step 3) --------------
#
# "Equivalent" means: tacquito, given either file, answers every client the
# same way. The comparison therefore models what the daemon does with a
# config rather than how the file is spelled. Each rule below is read off
# the tacquito source (cmds/server/loader/loader.go, config/secret/prefix,
# config/authorizers/stringy, config/authenticators/bcrypt):
#
#   scalars  The daemon decodes YAML into string fields, so `15` and "15"
#            are the same value to it while `01` and `1` are not. Both files
#            are loaded with yaml.BaseLoader, which keeps every scalar as
#            the text that was written.
#   users    Keyed by name. Scope order is irrelevant (membership test). A
#            user without its own authenticator/accounter gets the first one
#            its groups define, so the EFFECTIVE authenticator and accounter
#            are compared. Groups stay as written, in order: their services
#            and commands are appended to the user's in that order. A hash
#            is compared case-insensitively (hex); 'DISABLED' and the
#            disabled marker are one value (both can never authenticate and
#            draw the same reply).
#   secrets  The daemon builds one provider per secrets[] entry, in file
#            order, and answers a client with the first provider holding a
#            prefix that contains it. It builds NO provider for an entry
#            whose scope has no users, whose type/handler is not the
#            standard one, or whose prefixes option is not a non-empty JSON
#            list of strings; a prefix Go's net.ParseCIDR rejects (a bare
#            address, a dotted netmask) is skipped. Two CIDRs nest or are
#            disjoint, so a prefix is dead when an earlier provider holds
#            one containing it, and among the live prefixes the most
#            specific wins whatever the order: the routing is exactly the
#            set of live (prefix, scope, key). That set compares equal for
#            harmless reorderings and for one multi-prefix entry versus one
#            entry per prefix, and unequal whenever some client would get a
#            different scope or key.
#   filters  prefix_allow / prefix_deny as sets of parseable CIDRs.
#
# A scope's RADIUS-only fields (vendor_attrs, devices) never reach
# tacquito.yaml, so they have no part here; re-importing over an existing
# store keeps them (_carry_over above).
#
# Two further parts are compared although the daemon ignores them today,
# because they decide what happens on the next change: groups no user is in,
# and the routing as it would be if every scope had a user. A difference
# confined to those is reported as latent, and still fails the check.

def _go_cidr(text):
    """A prefix as Go's net.ParseCIDR accepts it (address/bits), else None."""
    if not isinstance(text, str) or not re.fullmatch(r'[0-9A-Fa-f:.]+/[0-9]+', text):
        return None
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        return None


def _go_prefix_list(raw):
    """options.prefixes as the prefix provider reads it (json.Unmarshal into
    []string). None when the provider would refuse the entry."""
    if not isinstance(raw, str):
        return None
    try:
        arr = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(arr, list) or not arr:
        return None
    if any(c is not None and not isinstance(c, str) for c in arr):
        return None
    return [c for c in arr if isinstance(c, str)]


def _yaml_null(v):
    return v is None or (isinstance(v, str) and v in ('', '~', 'null', 'Null', 'NULL'))


def _as_list(v):
    return v if isinstance(v, list) else []


def _is_one(v):
    """True for a type field that decodes to the integer 1."""
    try:
        return int(str(v)) == 1
    except ValueError:
        return False


def _equiv_redact(node, fingerprint, sensitive=False):
    """Copy of node with every scalar under an authenticator or secret
    mapping (bar its type/group) replaced by a fingerprint."""
    if isinstance(node, dict):
        out = {}
        for k, v in node.items():
            inner = sensitive or k in ('authenticator', 'secret')
            if inner and k in ('type', 'group') and not isinstance(v, (dict, list)):
                out[k] = v
            else:
                out[k] = _equiv_redact(v, fingerprint, inner)
        return out
    if isinstance(node, list):
        return [_equiv_redact(v, fingerprint, sensitive) for v in node]
    if sensitive and node is not None:
        return fingerprint(str(node))
    return node


def _equiv_hash(auth):
    """Authenticator mapping with options.hash in its comparison form."""
    if not isinstance(auth, dict) or not isinstance(auth.get('options'), dict):
        return auth
    h = auth['options'].get('hash')
    if not isinstance(h, str):
        return auth
    if h == 'DISABLED' or h.lower() == DISABLED_MARKER_HEX:
        folded = '<disabled>'
    else:
        folded = h.lower()
    return dict(auth, options=dict(auth['options'], hash=folded))


def _equiv_routes(providers):
    """Ordered providers [(index, scope, key, extra, [network...])] ->
    (live routes sorted by prefix, notes about prefixes that never match)."""
    live, earlier, notes = [], [], []
    for idx, scope, key, extra, nets in providers:
        for net in nets:
            cover = next((n for n in earlier if n.version == net.version and net.subnet_of(n)), None)
            if cover is not None:
                notes.append(f"secrets[{idx}] '{scope}': {net} never matches a client "
                             f"(an earlier entry already covers it with {cover})")
                continue
            route = {'prefix': str(net), 'scope': scope, 'key': key}
            if extra:
                route['nonstandard'] = extra
            live.append((net, route))
        # The prefixes of one provider share one answer, so only earlier
        # providers can shadow.
        earlier.extend(nets)
    live.sort(key=lambda t: cidr_key(str(t[0])))
    return [r for _, r in live], notes


def _equiv_normalize(doc, fingerprint):
    """Reduce a loaded tacquito.yaml to the comparison form described above.
    Returns (form, notes)."""
    notes = []
    form = {'users': {}, 'groups_without_users': {},
            'secrets': {'routes': [], 'routes_if_every_scope_had_users': []},
            'prefix_allow': [], 'prefix_deny': []}
    if not isinstance(doc, dict):
        return form, notes

    # ---- users ----
    used_groups, scoped = set(), set()
    for u in _as_list(doc.get('users')):
        if not isinstance(u, dict):
            continue
        name = str(u.get('name'))
        ent = {k: v for k, v in u.items() if k != 'name'}
        groups = [g for g in _as_list(u.get('groups')) if isinstance(g, dict)]
        used_groups.update(str(g.get('name')) for g in groups)
        for field in ('authenticator', 'accounter'):
            eff = u.get(field)
            if _yaml_null(eff):
                eff = next((g[field] for g in groups if not _yaml_null(g.get(field))), None)
            ent[field] = eff
        ent['authenticator'] = _equiv_hash(ent['authenticator'])
        ent['groups'] = [dict(g, authenticator=_equiv_hash(g['authenticator']))
                         if isinstance(g, dict) and 'authenticator' in g else g
                         for g in _as_list(u.get('groups'))]
        if isinstance(u.get('scopes'), list):
            ent['scopes'] = sorted({str(s) for s in u['scopes']})
            scoped.update(ent['scopes'])
        key, n = name, 1
        while key in form['users']:
            # tacquito lets a later entry override an earlier one per scope;
            # nothing tacctl renders does that, so keep both visible.
            n += 1
            key = f'{name} (entry {n})'
        form['users'][key] = _equiv_redact(ent, fingerprint)

    # ---- groups nobody is in (latent) ----
    for val in doc.values():
        if (isinstance(val, dict) and 'name' in val and isinstance(val.get('services'), list)
                and str(val['name']) not in used_groups):
            g = dict(val, authenticator=_equiv_hash(val['authenticator'])) if 'authenticator' in val else val
            form['groups_without_users'][str(val['name'])] = _equiv_redact(g, fingerprint)

    # ---- secrets ----
    providers = []
    for idx, s in enumerate(_as_list(doc.get('secrets'))):
        if not isinstance(s, dict):
            continue
        name = str(s.get('name'))
        sec = s.get('secret') if isinstance(s.get('secret'), dict) else {}
        key = sec.get('key')
        fp = fingerprint('' if _yaml_null(key) else str(key))
        handler = s.get('handler') if isinstance(s.get('handler'), dict) else {}
        opts = s.get('options') if isinstance(s.get('options'), dict) else {}
        # Anything beyond the skeleton tacctl writes rides along, so it shows.
        extra = {k: v for k, v in s.items() if k not in ('name', 'secret', 'handler', 'type', 'options')}
        if {k: v for k, v in sec.items() if k != 'key'} != {'group': 'tacquito'}:
            extra['secret'] = {k: v for k, v in sec.items() if k != 'key'}
        if {k: v for k, v in handler.items() if k != 'type'}:
            extra['handler'] = {k: v for k, v in handler.items() if k != 'type'}
        if {k: v for k, v in opts.items() if k != 'prefixes'}:
            extra['options'] = {k: v for k, v in opts.items() if k != 'prefixes'}
        extra = _equiv_redact(extra, fingerprint)
        label = f"secrets[{idx}] '{name}'"
        if not _is_one(s.get('type')):
            notes.append(f"{label}: not a prefix provider; tacquito builds nothing for it")
            continue
        if not _is_one(handler.get('type')):
            notes.append(f"{label}: no standard handler; tacquito builds nothing for it")
            continue
        prefixes = _go_prefix_list(opts.get('prefixes'))
        if prefixes is None:
            notes.append(f"{label}: prefixes is not a non-empty JSON list of strings; tacquito builds nothing for it")
            continue
        nets = []
        for c in prefixes:
            net = _go_cidr(c)
            if net is None:
                notes.append(f"{label}: prefix {c!r} is not a CIDR tacquito can parse; it is skipped")
            elif net not in nets:
                nets.append(net)
        providers.append((idx, name, fp, extra, nets))

    active = [p for p in providers if p[1] in scoped]
    for name in sorted({p[1] for p in providers if p[1] not in scoped}):
        notes.append(f"scope '{name}' has no users; tacquito does not load it")
    form['secrets']['routes'], shadow_notes = _equiv_routes(active)
    form['secrets']['routes_if_every_scope_had_users'], latent_notes = _equiv_routes(providers)
    notes.extend(shadow_notes)
    notes.extend(n + ' once every scope has a user' for n in latent_notes if n not in shadow_notes)

    # ---- prefix filters ----
    for k in ('prefix_allow', 'prefix_deny'):
        kept = set()
        for c in _as_list(doc.get(k)):
            net = _go_cidr(c)
            if net is None:
                notes.append(f"{k}: {c!r} is not a CIDR tacquito can parse; it is ignored")
            else:
                kept.add(str(net))
        form[k] = sorted(kept, key=cidr_key)
    return form, notes


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
                doc = yaml.load(f, Loader=yaml.BaseLoader)
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

    def serving(form):
        return (form['users'], form['secrets']['routes'], form['prefix_allow'], form['prefix_deny'])

    if serving(a) == serving(b):
        print('note: the two differ only in groups without users or scopes without users. '
              'tacquito answers today\'s clients identically, but the difference takes '
              'effect as soon as such a group or scope gets a user.')
    print('NOT EQUIVALENT')
    return 1
PY
}
