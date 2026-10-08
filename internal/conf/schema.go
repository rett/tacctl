package conf

import (
	"fmt"
	"math/big"
	"regexp"
	"slices"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/rett/tacctl/internal/cidr"
	"github.com/rett/tacctl/internal/names"
	"github.com/rett/tacctl/internal/py"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The schema types (lib/conf.sh _conf_schema_py).
const (
	TypeInt            = "int"
	TypeNullableString = "nullable_string"
	TypeEnum           = "enum"
	TypeACLName        = "acl_name"
	TypeCIDRList       = "cidr_list"
	TypeHostPort       = "host_port"
	TypeListener       = "listener"
	TypeBackendList    = "backend_list"
	TypeCiscoCmdList   = "cisco_cmd_list"
	TypeCommandRules   = "command_rules"
	// TypeJunosRegexList is junos.<group>.<attr> (junos.go).
	TypeJunosRegexList = "junos_regex_list"
	// TypeSudoCommandList is linux.engineer_sudo: absolute command paths.
	TypeSudoCommandList = "sudo_command_list"
)

// listTypes take list input (conf_set_list / a JSON list).
var listTypes = []string{TypeCIDRList, TypeCiscoCmdList, TypeCommandRules, TypeBackendList, TypeJunosRegexList, TypeSudoCommandList}

// Rule is one schema entry.
type Rule struct {
	Type     string
	Min, Max *int
	// Pattern is the Python regex of a nullable_string, as the message
	// prints it.
	Pattern string
	// Values are an enum's choices; a backend_list's are the registry,
	// filled in by Schema.
	Values []string
	// Default is the implicit per-instance default (a value as tacctl.yaml
	// holds it); HasDefault says there is one.
	Default    any
	HasDefault bool
	// Depth is how many trailing segments a wildcard takes (1 unless set).
	Depth int
}

func intp(v int) *int { return &v }

// scopePattern is scope.default's pattern.
const scopePattern = `^[a-zA-Z][a-zA-Z0-9_-]{0,31}$`

// Schema is SCHEMA and WILDCARDS for a registry of backends (BACKEND_IDS,
// in registration order: backends.enabled accepts these).
type Schema struct {
	exact     map[string]Rule
	wildcards []wildcard
}

type wildcard struct {
	prefix string
	rule   Rule
}

// NewSchema builds the schema; backends is the registry (tacctl 0.1.16:
// tacacs, radius).
func NewSchema(backends []string) *Schema {
	return &Schema{
		exact: map[string]Rule{
			"password.max_age_days": {Type: TypeInt, Min: intp(1)},
			"password.min_length":   {Type: TypeInt, Min: intp(8), Max: intp(64)},
			"secret.min_length":     {Type: TypeInt, Min: intp(16), Max: intp(128)},
			"bcrypt.cost":           {Type: TypeInt, Min: intp(10), Max: intp(14)},
			"scope.default":         {Type: TypeNullableString, Pattern: scopePattern},
			"host.default_method":   {Type: TypeEnum, Values: []string{"tacplus", "radius"}},
			// The Linux UID range ('tacctl config linux uid-range'); the pair
			// is checked as a whole where it is used (hosts.RangeProblem).
			"linux.uid_min":          {Type: TypeInt, Min: intp(1000), Max: intp(4294967293)},
			"linux.uid_max":          {Type: TypeInt, Min: intp(1000), Max: intp(4294967293)},
			"mgmt_acl.names.cisco":   {Type: TypeACLName},
			"mgmt_acl.names.juniper": {Type: TypeACLName},
			"mgmt_acl.permits":       {Type: TypeCIDRList},
			// What tac-engineer may run through sudo on enrolled hosts other
			// than the tacctl server ('tacctl config linux engineer-sudo');
			// unset is every command.
			"linux.engineer_sudo": {Type: TypeSudoCommandList},
			// Backends that serve the model, in render and restart order.
			"backends.enabled": {Type: TypeBackendList, Values: slices.Clone(backends),
				Default: []any{"tacacs"}, HasDefault: true},
			// Per-backend daemon settings ('tacctl config loglevel|metrics').
			"backends.tacacs.level": {Type: TypeInt, Min: intp(0), Max: intp(100),
				Default: 20, HasDefault: true},
			"backends.tacacs.metrics_address": {Type: TypeHostPort,
				Default: "127.0.0.1:8080", HasDefault: true},
			// The SNMP name hint of 'device add' (0.2.2; the credentials are in
			// StateDir/snmp.yaml, never here). No version: no lookup.
			"snmp.version": {Type: TypeEnum, Values: []string{"v2c", "v3"}},
			"snmp.port":    {Type: TypeInt, Min: intp(1), Max: intp(65535), Default: 161, HasDefault: true},
			"snmp.timeout": {Type: TypeInt, Min: intp(1), Max: intp(10), Default: 2, HasDefault: true},
			"snmp.v3.auth": {Type: TypeEnum, Values: []string{"sha", "sha256"}},
			"snmp.v3.priv": {Type: TypeEnum, Values: []string{"aes128"}},
		},
		wildcards: []wildcard{
			{"privileges.", Rule{Type: TypeCiscoCmdList}},
			{"commands.", Rule{Type: TypeCommandRules}},
			{"aaa.order.", Rule{Type: TypeEnum, Values: []string{"tacacs-first", "local-first"},
				Default: "tacacs-first", HasDefault: true}},
			// 0 = never expire; Junos idle-timeout tops out at 60.
			{"exec_timeout.", Rule{Type: TypeInt, Min: intp(0), Max: intp(60), Default: 60, HasDefault: true}},
			{"tacacs_group.", Rule{Type: TypeACLName, Default: "TACACS-GROUP", HasDefault: true}},
			{"radius_group.", Rule{Type: TypeACLName, Default: "RADIUS-GROUP", HasDefault: true}},
			// No default on purpose: unset means "not decided for this scope".
			{"scope_auth_method.", Rule{Type: TypeEnum, Values: []string{"tacacs", "radius"}}},
			{"scope_mgmt_acl.names.cisco.", Rule{Type: TypeACLName, Default: "VTY-ACL", HasDefault: true}},
			{"scope_mgmt_acl.names.juniper.", Rule{Type: TypeACLName, Default: "MGMT-ACL", HasDefault: true}},
			{"scope_mgmt_acl.permits.", Rule{Type: TypeCIDRList, Default: []any{}, HasDefault: true}},
			// listeners.<backend>.<name>: its default is per name.
			{"listeners.", Rule{Type: TypeListener, Depth: 2}},
			// The per-group device settings of 0.2.2 (junos.go); no default:
			// absent is "not set" (the priv-lvl band decides).
			{"junos.", Rule{Type: TypeJunosRegexList, Depth: 2}},
			{"wti_level.", Rule{Type: TypeEnum, Values: WTILevels}},
			{"tier.", Rule{Type: TypeEnum, Values: Tiers}},
		},
	}
}

// Keys returns the exact (non-wildcard) schema paths, sorted.
func (s *Schema) Keys() []string {
	keys := make([]string, 0, len(s.exact))
	for k := range s.exact {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// Wildcards returns the wildcard prefixes in order.
func (s *Schema) Wildcards() []string {
	out := make([]string, len(s.wildcards))
	for i, w := range s.wildcards {
		out[i] = w.prefix
	}
	return out
}

// RuleFor is schema_for: the rule of a dotted path, or false.
func (s *Schema) RuleFor(path string) (Rule, bool) {
	if r, ok := s.exact[path]; ok {
		return r, true
	}
	for _, w := range s.wildcards {
		if !strings.HasPrefix(path, w.prefix) {
			continue
		}
		parts := strings.Split(path[len(w.prefix):], ".")
		depth := w.rule.Depth
		if depth == 0 {
			depth = 1
		}
		if len(parts) == depth && !slices.Contains(parts, "") {
			return w.rule, true
		}
	}
	return Rule{}, false
}

// ImplicitDefault is implicit_default: the per-instance default of a
// path (a wildcard's, or a built-in listener's), or false.
func (s *Schema) ImplicitDefault(path string) (any, bool) {
	r, ok := s.RuleFor(path)
	if !ok {
		return nil, false
	}
	if r.Type == TypeListener {
		parts := strings.Split(path, ".")
		b, ok := ListenerBackendByID(parts[1])
		if !ok {
			return nil, false
		}
		v, ok := b.defaultValue(parts[2])
		if !ok {
			return nil, false
		}
		return v, true
	}
	return r.Default, r.HasDefault
}

// pyMatch is re.match(pattern, s) for the schema's anchored patterns,
// whose '$' also matches before a final newline.
func pyMatch(re *regexp.Regexp, s string) bool { return re.MatchString(s) }

var (
	reScopeDefault = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_-]{0,31}\n?$`)
	reACLName      = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]*\n?$`)
	reCmd          = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9 _-]+\n?$`)
	reRuleName     = regexp.MustCompile(`^(?:[A-Za-z][A-Za-z0-9_-]{0,31}|\*)\n?$`)
)

// pyLen is len(s): characters, not bytes.
func pyLen(s string) int { return utf8.RuneCountInString(s) }

// Validate is validate(path, value, is_list): "" when the schema accepts
// value at path, else the reason (lib/conf.sh's message).
func (s *Schema) Validate(path string, value any, isList bool) string {
	rule, ok := s.RuleFor(path)
	if !ok {
		return "unknown config key (typo? path must be one of the known tunables)"
	}
	t := rule.Type
	if isList && !slices.Contains(listTypes, t) {
		return fmt.Sprintf("%s does not accept list input; drop 'set-list'", t)
	}
	if !isList && slices.Contains(listTypes, t) {
		return fmt.Sprintf("%s requires list input (use conf_set_list)", t)
	}
	switch t {
	case TypeInt:
		n := py.BigInt(value)
		if n == nil {
			return "must be an integer"
		}
		if rule.Min != nil && n.Cmp(big.NewInt(int64(*rule.Min))) < 0 {
			return fmt.Sprintf("must be >= %d; got %s", *rule.Min, n)
		}
		if rule.Max != nil && n.Cmp(big.NewInt(int64(*rule.Max))) > 0 {
			return fmt.Sprintf("must be <= %d; got %s", *rule.Max, n)
		}
		return ""
	case TypeNullableString:
		if value == nil {
			return ""
		}
		str, isStr := value.(string)
		if !isStr {
			return "must be a string or null"
		}
		if !pyMatch(reScopeDefault, str) {
			return fmt.Sprintf("does not match required pattern %s", py.ReprString(rule.Pattern))
		}
		return ""
	case TypeEnum:
		str, isStr := value.(string)
		if !isStr {
			return fmt.Sprintf("must be a string (one of: %s)", strings.Join(rule.Values, ", "))
		}
		if !slices.Contains(rule.Values, str) {
			return fmt.Sprintf("must be one of: %s (got %s)", strings.Join(rule.Values, ", "), py.ReprString(str))
		}
		return ""
	case TypeACLName:
		str, isStr := value.(string)
		if !isStr {
			return "must be a string"
		}
		if n := pyLen(str); n < 1 || n > 63 {
			return fmt.Sprintf("must be 1..63 chars; got %d", n)
		}
		if !pyMatch(reACLName, str) {
			return "must start with a letter and contain only [A-Za-z0-9_-]"
		}
		return ""
	case TypeCIDRList:
		items, isList := py.List(value)
		if !isList {
			return "must be a list of CIDRs"
		}
		for i, item := range items {
			str, isStr := item.(string)
			if !isStr {
				return fmt.Sprintf("element %d: must be a string", i)
			}
			if cidr.Validate(str) != nil {
				return fmt.Sprintf("element %d: %s is not a valid CIDR", i, py.ReprString(str))
			}
		}
		return ""
	case TypeHostPort:
		return HostPortProblem(value)
	case TypeListener:
		parts := strings.Split(path, ".")
		return ListenerProblem(parts[1], parts[2], value)
	case TypeBackendList:
		known := strings.Join(rule.Values, ", ")
		items, isList := py.List(value)
		if !isList || len(items) == 0 {
			return fmt.Sprintf("must be a non-empty list of backends (known: %s)", known)
		}
		for i, item := range items {
			if !inStrings(item, rule.Values) {
				return fmt.Sprintf("element %d: %s is not a backend (known: %s)", i, py.Repr(item), known)
			}
			for _, prev := range items[:i] {
				if py.Equal(prev, item) {
					return fmt.Sprintf("element %d: %s is listed twice", i, py.Repr(item))
				}
			}
		}
		return ""
	case TypeCiscoCmdList:
		items, isList := py.List(value)
		if !isList {
			return "must be a list of Cisco priv-exec command strings"
		}
		for i, item := range items {
			str, isStr := item.(string)
			if !isStr {
				return fmt.Sprintf("element %d: must be a string", i)
			}
			// 0.2.2: an entry may start with a mode (exec:, exec all:,
			// configure:, configure all:); the command after it is checked.
			// Any other ':' is an invalid character, as before.
			if _, cmd, ok := names.SplitPrivEntry(str); ok {
				str = cmd
			}
			if !pyMatch(reCmd, str) {
				return fmt.Sprintf("element %d: %s has invalid characters (letters/digits/spaces/_/- only)", i, py.ReprString(str))
			}
			if n := pyLen(str); n > 64 {
				return fmt.Sprintf("element %d: too long (%d chars; max 64)", i, n)
			}
		}
		return ""
	case TypeCommandRules:
		return validateCommandRules(value)
	case TypeJunosRegexList:
		return junosListProblem(path, value)
	case TypeSudoCommandList:
		items, isList := py.List(value)
		if !isList || len(items) == 0 {
			return "must be a non-empty list of absolute command paths"
		}
		for i, item := range items {
			str, isStr := item.(string)
			if !isStr {
				return fmt.Sprintf("element %d: must be a string", i)
			}
			if p := SudoCommandProblem(str); p != "" {
				return fmt.Sprintf("element %d: %s %s", i, py.ReprString(str), p)
			}
			for _, prev := range items[:i] {
				if py.Equal(prev, item) {
					return fmt.Sprintf("element %d: %s is listed twice", i, py.ReprString(str))
				}
			}
		}
		return ""
	}
	return fmt.Sprintf("unknown schema type %s", py.ReprString(t))
}

// reSudoCommand is a command a sudoers line may name for linux.engineer_sudo:
// an absolute path of letters, digits and . _ + - /, without arguments (no
// space, comma, colon, backslash, wildcard or anything else sudoers reads
// as syntax).
var reSudoCommand = regexp.MustCompile(`^/[A-Za-z0-9._+/-]+$`)

// SudoCommandProblem is "" when cmd can be one command of
// linux.engineer_sudo, else why not (after the quoted command).
func SudoCommandProblem(cmd string) string {
	switch {
	case !reSudoCommand.MatchString(cmd):
		return "is not an absolute command path (letters, digits and . _ + - / only, no arguments)"
	case len(cmd) > 255:
		return "is longer than 255 characters"
	case strings.Contains("/"+cmd+"/", "/../") || strings.Contains("/"+cmd+"/", "/./") || strings.Contains(cmd, "//") || strings.HasSuffix(cmd, "/"):
		return "is not a clean path"
	}
	return ""
}

// validateCommandRules is the command_rules branch of validate.
func validateCommandRules(value any) string {
	items, isList := py.List(value)
	if !isList {
		return "must be a list of rule dicts"
	}
	if len(items) == 0 {
		return "must not be empty (need at least a catch-all '*' rule)"
	}
	catchall := 0
	for i, item := range items {
		m, isMap := item.(*yamlpy.Map)
		if !isMap {
			return fmt.Sprintf("element %d: must be a dict {name, action, match?}", i)
		}
		name, _ := m.Get("name")
		action, _ := m.Get("action")
		match, ok := m.Get("match")
		if !ok {
			match = []any{}
		}
		nameStr, isStr := name.(string)
		if !isStr || !pyMatch(reRuleName, nameStr) {
			return fmt.Sprintf("element %d: name must be '*' or a letter-start token (got %s)", i, py.Repr(name))
		}
		if nameStr == "*" {
			catchall++
			if i != len(items)-1 {
				return fmt.Sprintf("element %d: '*' catch-all must be the LAST rule", i)
			}
		}
		if !inStrings(action, []string{"permit", "deny"}) {
			return fmt.Sprintf("element %d: action must be 'permit' or 'deny' (got %s)", i, py.Repr(action))
		}
		if match == nil {
			match = []any{}
		}
		matches, isList := py.List(match)
		if !isList {
			return fmt.Sprintf("element %d: match must be a list of regex strings", i)
		}
		for j, mv := range matches {
			rx, isStr := mv.(string)
			if !isStr {
				return fmt.Sprintf("element %d: match[%d]: must be a string", i, j)
			}
			if _, err := regexp.Compile(rx); err != nil {
				return fmt.Sprintf("element %d: match[%d]: invalid regex (%s)", i, j, regexError(err))
			}
			if names.CommandMatchIsDead(nameStr, rx) {
				return fmt.Sprintf("element %d: match[%d]: %s repeats the command word; "+
					"tacquito tests match regexes against the ARGUMENTS only "+
					"(e.g. 'running-config' for 'show running-config'), so this "+
					"rule can never match. Drop the '%s ' prefix or omit match.", i, j, py.ReprString(rx), nameStr)
			}
		}
		if extra := sortedExtra(m, []string{"name", "action", "match"}); len(extra) > 0 {
			return fmt.Sprintf("element %d: unknown keys %s", i, py.Repr(extra))
		}
	}
	if catchall != 1 {
		return fmt.Sprintf("must contain exactly one '*' catch-all rule (found %d)", catchall)
	}
	return ""
}

// regexError is the reason of a regexp.Compile error without Go's
// "error parsing regexp: " prefix.
func regexError(err error) string {
	return strings.TrimPrefix(err.Error(), "error parsing regexp: ")
}

// CoerceScalar is coerce_scalar: a command-line value as conf_set stores
// it. An empty value stays empty; what int() reads is an integer (int, or
// *big.Int past int64); with a '.', what float() reads is a float;
// true/false/null in any case are a bool or nil; anything else stays a
// string.
func CoerceScalar(s string) any {
	if s == "" {
		return ""
	}
	if n, ok := py.Int(s); ok {
		if n.IsInt64() {
			return int(n.Int64())
		}
		return n
	}
	if strings.Contains(s, ".") {
		if f, ok := py.Float(s); ok {
			return f
		}
	}
	switch strings.ToLower(s) {
	case "true":
		return true
	case "false":
		return false
	case "null":
		return nil
	}
	return s
}
