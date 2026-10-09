package conf

import (
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/ui"
)

// The tests of tests/unit/conf.bats (tacctl 0.1.16), one Go test per bats
// test, named after it.

func get(t *testing.T, c *Config, path string) string {
	t.Helper()
	s, _ := c.Get(path, "")
	return s
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// refused asserts a ValidationError whose printed line holds want.
func refused(t *testing.T, err error, want string) {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want a validation error holding %q, got %v", want, err)
	}
	if !strings.Contains(ve.Error(), want) {
		t.Fatalf("%q does not hold %q", ve.Error(), want)
	}
}

func noFile(t *testing.T, c *Config) {
	t.Helper()
	if exists(c.Path) {
		t.Fatalf("%s exists:\n%s", c.Path, readFile(t, c.Path))
	}
}

func hasFile(t *testing.T, c *Config) {
	t.Helper()
	if !exists(c.Path) {
		t.Fatalf("%s does not exist", c.Path)
	}
}

func assertLines(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// --- conf_get ---

func TestConfGetReturnsDefaultWhenNoOverride(t *testing.T) {
	if got := get(t, tempConf(t), "bcrypt.cost"); got != "12" {
		t.Fatalf("got %q", got)
	}
}

func TestConfGetEmptyWhenPathMissingAndNoFallback(t *testing.T) {
	got, printed := tempConf(t).Get("nonexistent.key", "")
	if got != "" || !printed {
		t.Fatalf("got %q %v", got, printed)
	}
}

func TestConfGetReturnsFallbackWhenPathMissing(t *testing.T) {
	if got, _ := tempConf(t).Get("nonexistent.key", "my-fallback"); got != "my-fallback" {
		t.Fatalf("got %q", got)
	}
}

func TestConfGetOverridesWinOverDefaults(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("bcrypt.cost", "14"))
	if got := get(t, c, "bcrypt.cost"); got != "14" {
		t.Fatalf("got %q", got)
	}
}

func TestConfGetDeepMergeKeepsSiblingDefaults(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("password.max_age_days", "180"))
	if got := get(t, c, "password.max_age_days"); got != "180" {
		t.Fatalf("got %q", got)
	}
	if got := get(t, c, "password.min_length"); got != "12" {
		t.Fatalf("min_length %q", got)
	}
}

func TestConfGetCanonicalDefaultsComeFromConfEmitDefaults(t *testing.T) {
	c := tempConf(t)
	noFile(t, c)
	if get(t, c, "bcrypt.cost") != "12" || get(t, c, "mgmt_acl.names.cisco") != "VTY-ACL" {
		t.Fatal("defaults not answered")
	}
	if got, _ := c.Get("nonexistent.key", "99"); got != "99" {
		t.Fatalf("fallback %q", got)
	}
}

// --- conf_set ---

func TestConfSetCreatesTacctlYamlWith0640Perms(t *testing.T) {
	c := tempConf(t)
	noFile(t, c)
	must(t, c.Set("bcrypt.cost", "14"))
	fi, err := os.Stat(c.Path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o640 {
		t.Fatalf("mode %o", fi.Mode().Perm())
	}
}

func TestConfSetRevertToDefaultDeletesTheKey(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("bcrypt.cost", "14"))
	hasFile(t, c)
	must(t, c.Set("bcrypt.cost", "12"))
	noFile(t, c)
}

func TestConfSetCoercesIntegersAndBooleans(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("bcrypt.cost", "14"))
	must(t, c.Set("scope.default", "prod"))
	text := readFile(t, c.Path)
	if !strings.Contains(text, "cost: 14") || !strings.Contains(text, "default: prod") {
		t.Fatalf("file:\n%s", text)
	}
}

// --- conf_unset ---

func TestConfUnsetDropsTheKeyAndPrunesEmptyParentMaps(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("mgmt_acl.names.cisco", "CUSTOM"))
	if !strings.Contains(readFile(t, c.Path), "cisco: CUSTOM") {
		t.Fatal("not written")
	}
	must(t, c.Unset("mgmt_acl.names.cisco"))
	noFile(t, c)
}

func TestConfUnsetMissingKeyIsANoOp(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("bcrypt.cost", "14"))
	must(t, c.Unset("nonexistent.key"))
	if got := get(t, c, "bcrypt.cost"); got != "14" {
		t.Fatalf("got %q", got)
	}
}

// --- list helpers ---

func TestConfSetListAndGetListRoundTrip(t *testing.T) {
	c := tempConf(t)
	must(t, c.SetList("mgmt_acl.permits", ListItems("10.0.0.0/8\n192.168.1.0/24\n")))
	assertLines(t, c.GetList("mgmt_acl.permits"), "10.0.0.0/8", "192.168.1.0/24")
}

// The bats test shadows conf_emit_defaults to get a non-empty default
// list; privileges.operator is one in the shipped defaults.
func TestConfSetListListsReplaceWholesaleOnOverride(t *testing.T) {
	c := tempConf(t)
	assertLines(t, c.GetList("privileges.operator"), "exec all: ping", "exec all: traceroute",
		"exec all: monitor capture", "clear counters", "clear line", "clear ip arp", "clear arp-cache",
		"clear mac address-table dynamic", "undebug all")
	must(t, c.SetList("privileges.operator", ListItems("show version\n")))
	assertLines(t, c.GetList("privileges.operator"), "show version")
}

func TestConfSetListEmptyInputUnsets(t *testing.T) {
	c := tempConf(t)
	must(t, c.SetList("mgmt_acl.permits", ListItems("10.0.0.0/8\n")))
	assertLines(t, c.GetList("mgmt_acl.permits"), "10.0.0.0/8")
	must(t, c.SetList("mgmt_acl.permits", ListItems("")))
	noFile(t, c)
}

// --- conf_get_keys ---

func TestConfGetKeysEnumeratesTheKeysOfAMap(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("mgmt_acl.names.cisco", "A"))
	must(t, c.Set("mgmt_acl.names.juniper", "B"))
	assertLines(t, c.GetKeys("mgmt_acl.names"), "cisco", "juniper")
}

func TestConfGetKeysEmptyWhenPathIsAScalarOrAbsent(t *testing.T) {
	c := tempConf(t)
	if len(c.GetKeys("bcrypt.cost")) != 0 || len(c.GetKeys("nonexistent")) != 0 {
		t.Fatal("keys of a scalar or absent path")
	}
}

// --- Schema validation ---

func TestConfSetRejectsOutOfRangeIntWithClearDiagnostic(t *testing.T) {
	c := tempConf(t)
	refused(t, c.Set("bcrypt.cost", "99"), "bcrypt.cost: must be <= 14; got 99")
	noFile(t, c)
}

func TestConfSetRejectsNonNumericWhereIntRequired(t *testing.T) {
	refused(t, tempConf(t).Set("bcrypt.cost", "abc"), "must be an integer")
}

func TestConfSetRejectsUnknownKeyAsTypo(t *testing.T) {
	refused(t, tempConf(t).Set("bcrypt.cst", "14"), "unknown config key")
}

func TestConfSetRejectsACLNameNotMatchingPattern(t *testing.T) {
	refused(t, tempConf(t).Set("mgmt_acl.names.cisco", "1bad-start"), "must start with a letter")
}

func TestAAAOrderUnsetReadsEmpty(t *testing.T) {
	if got := get(t, tempConf(t), "aaa.order.lab"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestAAAOrderRoundTripLocalFirstPerScope(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("aaa.order.lab", "local-first"))
	if got := get(t, c, "aaa.order.lab"); got != "local-first" {
		t.Fatalf("got %q", got)
	}
}

func TestAAAOrderPerScopeOverridesAreIndependent(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("aaa.order.lab", "local-first"))
	must(t, c.Set("aaa.order.prod", "local-first"))
	if get(t, c, "aaa.order.lab") != "local-first" || get(t, c, "aaa.order.prod") != "local-first" {
		t.Fatal("not independent")
	}
	must(t, c.Set("aaa.order.lab", "tacacs-first"))
	if get(t, c, "aaa.order.lab") != "" || get(t, c, "aaa.order.prod") != "local-first" {
		t.Fatal("revert of lab disturbed prod")
	}
}

func TestAAAOrderRejectsUnknownEnumValue(t *testing.T) {
	c := tempConf(t)
	refused(t, c.Set("aaa.order.lab", "garbage"), "must be one of: tacacs-first, local-first")
	noFile(t, c)
}

func TestAAAOrderRejectsNonScopePath(t *testing.T) {
	refused(t, tempConf(t).Set("aaa.order", "tacacs-first"), "unknown config key")
}

func TestAAAOrderSettingTheImplicitDefaultPrunesOverride(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("aaa.order.lab", "local-first"))
	hasFile(t, c)
	must(t, c.Set("aaa.order.lab", "tacacs-first"))
	noFile(t, c)
}

func TestConfSetListRejectsMalformedCIDRs(t *testing.T) {
	c := tempConf(t)
	refused(t, c.SetList("mgmt_acl.permits", ListItems("10.0.0.0/8\ngarbage\n")), "element 1: 'garbage' is not a valid CIDR")
	noFile(t, c)
}

func TestConfSetListRejectsMalformedCiscoPrivExecStrings(t *testing.T) {
	err := tempConf(t).SetList("privileges.operator", ListItems("show version\nshow; rm\n"))
	refused(t, err, "element 1:")
	refused(t, err, "invalid characters")
}

// 0.2.2: an entry may start with a privilege mode; the command after it is
// checked as before, and an unknown prefix is an invalid character.
func TestConfSetListCiscoPrivModes(t *testing.T) {
	c := tempConf(t)
	must(t, c.SetList("privileges.operator", ListItems("configure: router bgp\nexec all: show ip\nconfigure all:interface\nshow version\n")))
	assertLines(t, c.GetList("privileges.operator"), "configure: router bgp", "exec all: show ip", "configure all:interface", "show version")
	refused(t, tempConf(t).SetList("privileges.operator", ListItems("config: router bgp\n")), "element 0: 'config: router bgp' has invalid characters")
	refused(t, tempConf(t).SetList("privileges.operator", ListItems("exec: show; rm\n")), "element 0: 'show; rm' has invalid characters")
	refused(t, tempConf(t).SetList("privileges.operator", ListItems("configure: "+strings.Repeat("a", 65)+"\n")), "element 0: too long (65 chars; max 64)")
}

func TestConfSetListRejectsScalarMisCallOnListPath(t *testing.T) {
	refused(t, tempConf(t).Set("mgmt_acl.permits", "10.0.0.0/8"), "requires list input")
}

func TestConfSetRejectsListMisCallOnScalarPath(t *testing.T) {
	refused(t, tempConf(t).SetList("bcrypt.cost", ListItems("12\n")), "does not accept list input")
}

// --- Overrides-file schema scan (tacctl config validate) ---

func TestValidateOverridesFileNoOutputOnACleanFile(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("bcrypt.cost", "14"))
	assertLines(t, c.Schema.ValidateFile(c.Path))
}

func validateText(t *testing.T, content string) string {
	t.Helper()
	c := tempConf(t)
	writeFile(t, c.Path, content)
	return strings.Join(c.Schema.ValidateFile(c.Path), "\n")
}

func TestValidateOverridesFileCatchesHandEditedOutOfRange(t *testing.T) {
	if got := validateText(t, "bcrypt:\n  cost: 99\n"); !strings.Contains(got, "bcrypt.cost: must be <= 14") {
		t.Fatalf("got %q", got)
	}
}

func TestValidateOverridesFileCatchesHandEditedUnknownKey(t *testing.T) {
	if got := validateText(t, "bcrypt:\n  cst: 14\n"); !strings.Contains(got, "bcrypt.cst: unknown config key") {
		t.Fatalf("got %q", got)
	}
}

func TestValidateOverridesFileCatchesMalformedListElements(t *testing.T) {
	got := validateText(t, "mgmt_acl:\n  permits:\n    - 10.0.0.0/8\n    - garbage\n")
	if !strings.Contains(got, "mgmt_acl.permits:") || !strings.Contains(got, "not a valid CIDR") {
		t.Fatalf("got %q", got)
	}
}

func TestValidateOverridesFileAFileThatDoesNotParseIsOneLineNamingWhere(t *testing.T) {
	c := tempConf(t)
	writeFile(t, c.Path, "commands: [unterminated\n")
	assertLines(t, c.Schema.ValidateFile(c.Path),
		"could not parse "+c.Path+": line 2, column 1: expected ',' or ']', but got '<stream end>'")
}

// --- An overrides file that does not parse ---

const brokenOverrides = "bcrypt:\n  cost: 14\ncommands: [unterminated\n"

func brokenConf(t *testing.T) *Config {
	t.Helper()
	c := tempConf(t)
	writeFile(t, c.Path, brokenOverrides)
	c.Reload()
	return c
}

// printed renders a write error as the bash prints it on stderr.
func printed(err error) string {
	var b bytes.Buffer
	var pe *ParseError
	if errors.As(err, &pe) {
		ui.Output{Stdout: &b, Stderr: &b}.ErrorLines(pe)
		return b.String()
	}
	if err != nil {
		return err.Error() + "\n"
	}
	return ""
}

func refusedUnparsable(t *testing.T, c *Config, err error, partial string) {
	t.Helper()
	var pe *ParseError
	if !errors.As(err, &pe) {
		t.Fatalf("want a parse refusal, got %v", err)
	}
	out := printed(err)
	for _, want := range []string{partial, "Fix or remove the file", "nothing was written"} {
		if !strings.Contains(out, want) {
			t.Fatalf("%q does not hold %q", out, want)
		}
	}
	if readFile(t, c.Path) != brokenOverrides {
		t.Fatal("the file was changed")
	}
}

func TestConfSetAnOverridesFileThatDoesNotParseIsRefusedNamedAndLeftAsItWas(t *testing.T) {
	c := brokenConf(t)
	refusedUnparsable(t, c, c.Set("password.max_age_days", "30"),
		"tacctl.yaml: could not parse "+c.Path+": line 4, column 1: expected ',' or ']'")
	want := "\033[0;31m[ERROR]\033[0m tacctl.yaml: could not parse " + c.Path +
		": line 4, column 1: expected ',' or ']', but got '<stream end>'\n" +
		"\033[0;31m[ERROR]\033[0m Fix or remove the file ('tacctl config validate' checks it); nothing was written.\n"
	if got := printed(c.Set("password.max_age_days", "30")); got != want {
		t.Fatalf("got %q\nwant %q", got, want)
	}
}

func TestConfUnsetSetListSetJSONRefusedTheSameWayFileUntouched(t *testing.T) {
	c := brokenConf(t)
	refusedUnparsable(t, c, c.Unset("bcrypt.cost"), "could not parse "+c.Path)
	refusedUnparsable(t, c, c.SetList("mgmt_acl.permits", ListItems("10.0.0.0/8\n")), "could not parse "+c.Path)
	refusedUnparsable(t, c, c.SetJSON("commands.operator", `[{"name": "*", "action": "deny"}]`), "could not parse "+c.Path)
}

func TestConfSetAnOverridesFileWhoseTopLevelIsNotAMappingIsRefused(t *testing.T) {
	c := tempConf(t)
	writeFile(t, c.Path, "- bcrypt\n")
	err := c.Set("bcrypt.cost", "13")
	if !strings.Contains(printed(err), "could not parse "+c.Path+": the top level is a list, not a mapping") {
		t.Fatalf("got %q", printed(err))
	}
	if readFile(t, c.Path) != "- bcrypt\n" {
		t.Fatal("changed")
	}
}

func TestConfSetAnEmptyOverridesFileIsNoOverridesAndIsWritten(t *testing.T) {
	c := tempConf(t)
	writeFile(t, c.Path, "")
	must(t, c.Set("bcrypt.cost", "13"))
	if got := get(t, c, "bcrypt.cost"); got != "13" {
		t.Fatalf("got %q", got)
	}
}

func TestConfGetAnOverridesFileThatDoesNotParseReadsAsTheDefaultsWithOneWarning(t *testing.T) {
	c := brokenConf(t)
	if got := get(t, c, "bcrypt.cost"); got != "12" {
		t.Fatalf("got %q", got)
	}
	var stderr bytes.Buffer
	c.WarnOnce(&stderr)
	if !strings.Contains(stderr.String(), "tacctl.yaml: could not parse "+c.Path+": line 4, column 1:") ||
		!strings.Contains(stderr.String(), "using the defaults") {
		t.Fatalf("warning %q", stderr.String())
	}
	stderr.Reset()
	c.WarnOnce(&stderr)
	if get(t, c, "bcrypt.cost") != "12" || stderr.Len() != 0 {
		t.Fatalf("second warning %q", stderr.String())
	}
}

func TestConfHasOverrideAnOverridesFileThatDoesNotParseHasNoOverrides(t *testing.T) {
	if brokenConf(t).HasOverride("bcrypt.cost") {
		t.Fatal("has override")
	}
}

// --- exec_timeout.<scope> ---

func TestExecTimeoutUnsetReadsEmpty(t *testing.T) {
	if got := get(t, tempConf(t), "exec_timeout.lab"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestExecTimeoutRoundTripAnExplicitOverride(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("exec_timeout.lab", "15"))
	if got := get(t, c, "exec_timeout.lab"); got != "15" {
		t.Fatalf("got %q", got)
	}
}

func TestExecTimeoutSettingTheImplicitDefaultPrunesOverride(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("exec_timeout.lab", "15"))
	hasFile(t, c)
	must(t, c.Set("exec_timeout.lab", "60"))
	noFile(t, c)
}

func TestExecTimeoutRejectsBelow0AndAbove60(t *testing.T) {
	c := tempConf(t)
	refused(t, c.Set("exec_timeout.lab", "-1"), "must be >= 0")
	refused(t, c.Set("exec_timeout.lab", "61"), "must be <= 60")
}

func TestExecTimeoutRejectsNonNumeric(t *testing.T) {
	refused(t, tempConf(t).Set("exec_timeout.lab", "forever"), "must be an integer")
}

// --- tacacs_group.<scope> ---

func TestTacacsGroupUnsetReadsEmpty(t *testing.T) {
	if got := get(t, tempConf(t), "tacacs_group.lab"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestTacacsGroupRoundTripAnExplicitOverride(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("tacacs_group.lab", "TACACS_PROD"))
	if got := get(t, c, "tacacs_group.lab"); got != "TACACS_PROD" {
		t.Fatalf("got %q", got)
	}
}

func TestTacacsGroupSettingTheImplicitDefaultPrunesOverride(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("tacacs_group.lab", "TACACS_PROD"))
	hasFile(t, c)
	must(t, c.Set("tacacs_group.lab", "TACACS-GROUP"))
	noFile(t, c)
}

func TestTacacsGroupRejectsInvalidCharacters(t *testing.T) {
	refused(t, tempConf(t).Set("tacacs_group.lab", "bad name with spaces"), "must start with a letter")
}

func TestTacacsGroupRejectsEmptyAndTooLong(t *testing.T) {
	c := tempConf(t)
	refused(t, c.Set("tacacs_group.lab", ""), "tacacs_group.lab:")
	refused(t, c.Set("tacacs_group.lab", strings.Repeat("A", 64)), "1..63 chars")
}

// --- radius_group.<scope> ---

func TestRadiusGroupUnsetReadsEmpty(t *testing.T) {
	if got := get(t, tempConf(t), "radius_group.lab"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestRadiusGroupRoundTripIndependentOfTacacsGroup(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("radius_group.lab", "RADIUS_PROD"))
	if get(t, c, "radius_group.lab") != "RADIUS_PROD" || get(t, c, "tacacs_group.lab") != "" {
		t.Fatal("not independent")
	}
}

func TestRadiusGroupSettingTheImplicitDefaultPrunesOverride(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("radius_group.lab", "RADIUS_PROD"))
	hasFile(t, c)
	must(t, c.Set("radius_group.lab", "RADIUS-GROUP"))
	noFile(t, c)
}

func TestRadiusGroupRejectsInvalidCharactersEmptyAndTooLong(t *testing.T) {
	c := tempConf(t)
	refused(t, c.Set("radius_group.lab", "bad name with spaces"), "must start with a letter")
	refused(t, c.Set("radius_group.lab", ""), "radius_group.lab:")
	refused(t, c.Set("radius_group.lab", strings.Repeat("A", 64)), "1..63 chars")
}

// --- scope_mgmt_acl.names.<vendor>.<scope> ---

func TestScopeMgmtACLNamesCiscoUnsetReadsEmpty(t *testing.T) {
	if got := get(t, tempConf(t), "scope_mgmt_acl.names.cisco.lab"); got != "" {
		t.Fatalf("got %q", got)
	}
}

func TestScopeMgmtACLNamesRoundTripOverridePerVendor(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("scope_mgmt_acl.names.cisco.lab", "LAB-VTY"))
	must(t, c.Set("scope_mgmt_acl.names.juniper.lab", "LAB-MGMT"))
	if get(t, c, "scope_mgmt_acl.names.cisco.lab") != "LAB-VTY" || get(t, c, "scope_mgmt_acl.names.juniper.lab") != "LAB-MGMT" {
		t.Fatal("round trip")
	}
}

func TestScopeMgmtACLNamesSettingTheShippedDefaultPrunesOverride(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set("scope_mgmt_acl.names.cisco.lab", "CUSTOM-ACL"))
	hasFile(t, c)
	must(t, c.Set("scope_mgmt_acl.names.cisco.lab", "VTY-ACL"))
	noFile(t, c)
}

func TestScopeMgmtACLNamesRejectsBadACLName(t *testing.T) {
	refused(t, tempConf(t).Set("scope_mgmt_acl.names.cisco.lab", "1bad-start"), "must start with a letter")
}

func TestScopeMgmtACLPerScopeWriteDoesNotWipeTheGlobalList(t *testing.T) {
	c := tempConf(t)
	must(t, c.SetList("mgmt_acl.permits", ListItems("10.0.0.0/8\n")))
	must(t, c.SetList("scope_mgmt_acl.permits.lab", ListItems("10.99.0.0/16\n")))
	assertLines(t, c.GetList("mgmt_acl.permits"), "10.0.0.0/8")
	assertLines(t, c.GetList("scope_mgmt_acl.permits.lab"), "10.99.0.0/16")
}

// --- scope_auth_method.<scope> ---

func TestScopeAuthMethodTacacsAndRadiusBothRoundTrip(t *testing.T) {
	c := tempConf(t)
	if get(t, c, "scope_auth_method.lab") != "" {
		t.Fatal("not empty")
	}
	must(t, c.Set("scope_auth_method.lab", "tacacs"))
	if get(t, c, "scope_auth_method.lab") != "tacacs" {
		t.Fatal("tacacs")
	}
	must(t, c.Set("scope_auth_method.lab", "radius"))
	if get(t, c, "scope_auth_method.lab") != "radius" {
		t.Fatal("radius")
	}
	must(t, c.Unset("scope_auth_method.lab"))
	if get(t, c, "scope_auth_method.lab") != "" {
		t.Fatal("unset")
	}
}

func TestScopeAuthMethodOnlyTacacsOrRadiusAScopeNameIsRequired(t *testing.T) {
	c := tempConf(t)
	refused(t, c.Set("scope_auth_method.lab", "tacplus"), "must be one of: tacacs, radius")
	refused(t, c.Set("scope_auth_method.lab", ""), "scope_auth_method.lab:")
	refused(t, c.Set("scope_auth_method", "radius"), "unknown config key")
}
