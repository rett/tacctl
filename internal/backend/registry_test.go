package backend_test

import (
	"errors"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/backend/faketest"
	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/ui"
)

// Ported from tests/unit/backend.bats: the registry, the contract, the
// lookup of one backend (backend_call) and the enabled list. The tests of
// the TACACS+ module's own verbs (artifacts, installed, listeners, service,
// last_login, secret_constraints, device_vars, status/log parts, describe
// values) move to internal/backend/tacacs with WP2.2; the source-grep and
// declare -f tests are dropped (docs/plans/go-rewrite.md 2.3).

func fakeFactory(id string) backend.Factory {
	return faketest.Factory(faketest.New(id, "/etc/"+id+".conf", os.TempDir()))
}

func TestContractTacacsAndRadiusAreRegisteredOnceEachTacacsFirst(t *testing.T) {
	// The shipped registry has the two slots in this order whatever order
	// the modules' init functions run in.
	r := backend.NewRegistry(backend.TACACS, backend.RADIUS)
	if err := r.Add(backend.RADIUS, fakeFactory("radius")); err != nil {
		t.Fatal(err)
	}
	if err := r.Add(backend.TACACS, fakeFactory("tacacs")); err != nil {
		t.Fatal(err)
	}
	if got := r.IDs(); !slices.Equal(got, []string{"tacacs", "radius"}) {
		t.Fatalf("ids %v", got)
	}
	if !r.Has("tacacs") || !r.Has("radius") || r.Has("ldap") || r.Has("") {
		t.Fatal("Has")
	}
	if err := r.Add(backend.TACACS, fakeFactory("tacacs")); err == nil || !strings.Contains(err.Error(), "registered twice") {
		t.Fatalf("duplicate: %v", err)
	}
	// Any other id comes after the slots, in the order it was added.
	_ = r.Add("zeta", fakeFactory("zeta"))
	_ = r.Add("alpha", fakeFactory("alpha"))
	if got := r.IDs(); !slices.Equal(got, []string{"tacacs", "radius", "zeta", "alpha"}) {
		t.Fatalf("ids %v", got)
	}
}

func TestContractTheDefaultRegistryHoldsOnlyTheShippedSlotsInOrder(t *testing.T) {
	// Until WP2.2 and WP2.3 register their modules the default registry is
	// empty; from then on it is exactly tacacs, radius (asserted by
	// internal/backend/all's test once the modules exist).
	got := backend.Default().IDs()
	for i, id := range got {
		if want := []string{"tacacs", "radius"}; i >= len(want) || want[i] != id {
			t.Fatalf("default registry %v", got)
		}
	}
}

func TestContractTacacssIsReservedAndIDsAreChecked(t *testing.T) {
	r := backend.NewRegistry()
	for _, id := range []string{"tacacss", "", "Tacacs", "1x", "a-b", "ta cacs"} {
		if err := r.Add(id, fakeFactory("x")); err == nil {
			t.Errorf("Add(%q) accepted", id)
		}
	}
	if err := r.Add("tacacss", fakeFactory("x")); err == nil || !strings.Contains(err.Error(), "reserved") {
		t.Fatalf("got %v", err)
	}
	if err := r.Add("fake", nil); err == nil {
		t.Fatal("nil factory accepted")
	}
	if !backend.IsReserved("tacacss") || backend.IsReserved("tacacs") {
		t.Fatal("IsReserved")
	}
	defer func() {
		if recover() == nil {
			t.Fatal("Register of a reserved id did not panic")
		}
	}()
	backend.Register("tacacss", fakeFactory("x"))
}

func TestContractTheStandInPassesTheContractCheck(t *testing.T) {
	e := newTenv(t)
	b, err := e.set.Get("fake")
	if err != nil {
		t.Fatal(err)
	}
	faketest.CheckContract(t, b)
}

func TestContractLifecyclePhasesAreTheDocumentedOnes(t *testing.T) {
	// BACKEND_INSTALL_PHASES, BACKEND_UPGRADE_PHASES,
	// BACKEND_UNINSTALL_PHASES of lib/backend.sh. That the commands run
	// them in this order is internal/lifecycle's test (WP3.3d).
	join := func(ps []backend.Phase) string {
		var s []string
		for _, p := range ps {
			s = append(s, string(p))
		}
		return strings.Join(s, " ")
	}
	if join(backend.InstallPhases) != "build files account start" ||
		join(backend.UpgradePhases) != "preflight build config files finish" ||
		join(backend.UninstallPhases) != "stop program data account" {
		t.Fatal("phases")
	}
}

func TestGetReturnsTheBackendAndItsVerbsReturnTheirStatus(t *testing.T) {
	e := newTenv(t)
	b, err := e.set.Get("fake")
	if err != nil || b.ID() != "fake" {
		t.Fatalf("%v %v", b, err)
	}
	again, _ := e.set.Get("fake")
	if again != b {
		t.Fatal("made twice in one invocation")
	}
	e.fake.StopFails = true
	_, err = b.Service(ctx, backend.ServiceStop, "now")
	if !errors.Is(err, backend.ErrFailed) || e.fake.Calls()[0] != "service stop now" {
		t.Fatalf("%v %v", err, e.fake.Calls())
	}
}

func TestGetAnUnknownBackendOrVerbIsAnError2(t *testing.T) {
	e := newTenv(t)
	_, err := e.set.Get("ldap")
	var ue *backend.UnknownError
	if !errors.As(err, &ue) || err.Error() != "Unknown backend 'ldap'." || backend.ExitCode(err) != 2 || ue.ExitCode() != 2 {
		t.Fatalf("got %v", err)
	}
	if _, err := e.set.Get(""); backend.ExitCode(err) != 2 {
		t.Fatalf("got %v", err)
	}
	b, _ := e.set.Get("fake")
	if _, err := b.Service(ctx, "no_such_verb", ""); backend.ExitCode(err) != 2 {
		t.Fatalf("got %v", err)
	}
}

func TestExitCodeAndReported(t *testing.T) {
	cases := []struct {
		err      error
		code     int
		reported bool
	}{
		{nil, 0, false},
		{backend.ErrFailed, 1, true},
		{backend.ErrRefused, 3, true},
		{backend.ErrUnsupported, 2, true},
		{&backend.UnknownError{ID: "x"}, 2, false},
		{backend.ErrAdopt, 10, false},
		{errors.New("other"), 1, false},
	}
	for _, c := range cases {
		if backend.ExitCode(c.err) != c.code || backend.Reported(c.err) != c.reported {
			t.Errorf("%v: %d %v", c.err, backend.ExitCode(c.err), backend.Reported(c.err))
		}
	}
	if backend.ErrRefused.ExitCode() != 3 || !strings.Contains(backend.ErrRefused.Error(), "refused") {
		t.Fatal(backend.ErrRefused.Error())
	}
	for g, want := range map[backend.GateResult][2]any{
		backend.GateOK: {0, "ok"}, backend.GateAdopt: {10, "adopt"},
		backend.GateRefused: {3, "refused"}, backend.GateFailed: {1, "failed"},
	} {
		if g.Code() != want[0] || g.String() != want[1] {
			t.Errorf("%d: %d %s", g, g.Code(), g)
		}
	}
}

func TestDescribeAndHeading(t *testing.T) {
	e := newTenv(t)
	b, _ := e.set.Get("fake")
	d := b.Describe()
	if d.Protocol != "fake" || d.Impl != "faked" || d.ImportCmd != "" || !slices.Equal(d.Units, []string{"fake.service"}) {
		t.Fatalf("%+v", d)
	}
	if got := backend.Heading(b); got != "\n"+ui.Bold+"== Backend: fake (fake, faked) =="+ui.NC+"\n" {
		t.Fatalf("heading %q", got)
	}
	tac, _ := e.set.Get("tacacs")
	if got := backend.Heading(tac); !strings.Contains(got, "== Backend: tacacs (tacacs, tacquito) ==") {
		t.Fatalf("heading %q", got)
	}
}

// --- Enabled backends --------------------------------------------------------

func TestEnabledTacacsByDefaultWithAndWithoutATacctlYAML(t *testing.T) {
	e := newTenv(t)
	if got, err := e.set.Enabled(); err != nil || !slices.Equal(got, []string{"tacacs"}) {
		t.Fatalf("%v %v", got, err)
	}
	if err := e.env.Conf.Set("password.max_age_days", "30"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.p.Overrides); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.set.Enabled(); !slices.Equal(got, []string{"tacacs"}) {
		t.Fatalf("%v", got)
	}
	if !e.set.IsEnabled("tacacs") || e.set.IsEnabled("fake") {
		t.Fatal("IsEnabled")
	}
}

func TestEnabledTheShippedDefaultIsTheSchemasDefault(t *testing.T) {
	e := newTenv(t)
	rule, ok := conf.NewSchema(e.reg.IDs()).RuleFor("backends.enabled")
	if !ok {
		t.Fatal("no rule")
	}
	var def []string
	for _, v := range rule.Default.([]any) {
		def = append(def, v.(string))
	}
	if !slices.Equal(def, backend.DefaultEnabled) {
		t.Fatalf("schema default %v, DefaultEnabled %v", def, backend.DefaultEnabled)
	}
	// Every id the schema accepts has a module, and every module is
	// accepted.
	if !slices.Equal(rule.Values, e.reg.IDs()) {
		t.Fatalf("schema values %v, registry %v", rule.Values, e.reg.IDs())
	}
}

func TestEnabledReadsBackendsEnabledInItsOrder(t *testing.T) {
	e := newTenv(t)
	e.enable("fake, tacacs")
	if got, _ := e.set.Enabled(); !slices.Equal(got, []string{"fake", "tacacs"}) {
		t.Fatalf("%v", got)
	}
	e.enable("fake, fake")
	if got, _ := e.set.Enabled(); !slices.Equal(got, []string{"fake"}) {
		t.Fatalf("%v", got)
	}
}

func TestEnabledABackendThisTacctlDoesNotHaveIsRefusedByName(t *testing.T) {
	e := newTenv(t)
	e.enable("tacacs, ldap")
	got, err := e.set.Enabled()
	var ee *backend.EnabledError
	if !errors.As(err, &ee) || got != nil {
		t.Fatalf("%v %v", got, err)
	}
	if err.Error() != "tacctl.yaml: backends.enabled names 'ldap', and this tacctl has no such backend (it has: tacacs fake)." {
		t.Fatalf("%q", err)
	}
	if e.set.IsEnabled("tacacs") {
		t.Fatal("IsEnabled with an unreadable list")
	}
}

func TestEnabledFollowsATacctlYAMLWriteInTheSameInvocation(t *testing.T) {
	e := newTenv(t)
	if got, _ := e.set.Enabled(); !slices.Equal(got, []string{"tacacs"}) {
		t.Fatal(got)
	}
	if err := e.env.Conf.SetList("backends.enabled", []string{"tacacs", "fake"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := e.set.Enabled(); !slices.Equal(got, []string{"tacacs", "fake"}) {
		t.Fatal(got)
	}
}

func TestSchemaBackendsEnabledTakesKnownBackendsOnlyNonEmptyNoDuplicates(t *testing.T) {
	e := newTenv(t)
	c := e.env.Conf
	for _, tc := range []struct {
		items []string
		want  string
	}{
		{[]string{"ldap"}, "'ldap' is not a backend"},
		{nil, "non-empty"},
		{[]string{"tacacs", "tacacs"}, "listed twice"},
	} {
		if err := c.SetList("backends.enabled", tc.items); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v", tc.items, err)
		}
	}
	if err := c.Set("backends.enabled", "tacacs"); err == nil || !strings.Contains(err.Error(), "requires list input") {
		t.Errorf("scalar: %v", err)
	}
	if _, err := os.Stat(e.p.Overrides); err == nil {
		t.Fatal("tacctl.yaml written")
	}
}

func TestSchemaBackendsEnabledTakesWhateverTheRegistryHolds(t *testing.T) {
	e := newTenv(t)
	// The registry of this test: tacacs, then fake; radius is a slot
	// without a module here.
	r := backend.NewRegistry(backend.TACACS, backend.RADIUS)
	for _, id := range []string{"tacacs", "radius", "fake"} {
		_ = r.Add(id, fakeFactory(id))
	}
	c := conf.Load(e.p.Overrides, r.IDs())
	c.Owner = nil
	if err := c.SetList("backends.enabled", []string{"tacacs", "fake"}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(readFile(t, e.p.Overrides), "fake"); n != 1 {
		t.Fatalf("%d", n)
	}
	// The overrides walk agrees.
	if probs := c.Schema.ValidateFile(e.p.Overrides); len(probs) != 0 {
		t.Fatalf("%v", probs)
	}
	// What is not registered is still refused, with the registry in the
	// message.
	err := c.SetList("backends.enabled", []string{"tacacs", "ldap"})
	if err == nil || !strings.Contains(err.Error(), "'ldap' is not a backend (known: tacacs, radius, fake)") {
		t.Fatalf("%v", err)
	}
}

func TestSchemaSettingBackendsEnabledToTheDefaultWritesNoOverride(t *testing.T) {
	e := newTenv(t)
	if err := e.env.Conf.SetList("backends.enabled", []string{"tacacs"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(e.p.Overrides); err == nil {
		t.Fatal("tacctl.yaml written")
	}
	if strings.Contains(conf.DefaultsText, "backends") {
		t.Fatal("backends in the shipped defaults")
	}
}

func TestSchemaAHandWrittenBackendsEnabledIsCheckedByTheOverridesWalk(t *testing.T) {
	e := newTenv(t)
	e.enable("tacacs")
	if probs := e.env.Conf.Schema.ValidateFile(e.p.Overrides); len(probs) != 0 {
		t.Fatalf("%v", probs)
	}
	e.enable("tacacs, bogus")
	probs := e.env.Conf.Schema.ValidateFile(e.p.Overrides)
	if !slices.ContainsFunc(probs, func(p string) bool {
		return strings.Contains(p, "backends.enabled: element 1: 'bogus' is not a backend")
	}) {
		t.Fatalf("%v", probs)
	}
}

// --- Helpers over the enabled backends ----------------------------------------

func TestArtifactsNamesAndOwner(t *testing.T) {
	e := newTenv(t)
	e.enable("tacacs, fake")
	got, err := e.set.Artifacts()
	if err != nil || !slices.Equal(got, []string{e.p.Config, e.dropIn(), e.fakeConf}) {
		t.Fatalf("%v %v", got, err)
	}
	if n, _ := e.set.ArtifactNames("tacacs"); n != e.p.Config+", "+e.dropIn() {
		t.Fatal(n)
	}
	if _, err := e.set.ArtifactNames("ldap"); backend.ExitCode(err) != 2 {
		t.Fatal(err)
	}
	if n := e.set.AllArtifactNames(); n != e.p.Config+", "+e.dropIn()+", "+e.fakeConf {
		t.Fatal(n)
	}
	if e.set.Owner(e.fakeConf) != "fake" || e.set.Owner(e.p.Config) != "tacacs" || e.set.Owner("/etc/other") != "" {
		t.Fatal("Owner")
	}
	e.enable("tacacs, ldap")
	if _, err := e.set.Artifacts(); err == nil || e.set.AllArtifactNames() != "" {
		t.Fatal("artifacts of an unreadable list")
	}
}

func TestLastLoginTheMostRecentAcrossEnabledBackends(t *testing.T) {
	e := newTenv(t)
	fake2 := e.addFake("fake2")
	e.enable("fake, fake2")
	if got := e.set.LastLogin(ctx, "alice"); got != "never" {
		t.Fatal(got)
	}
	e.fake.LastLoginAt = "2026-04-21 10:11:12"
	fake2.LastLoginAt = "2026-05-01 00:00:00"
	if got := e.set.LastLogin(ctx, "alice"); got != "2026-05-01 00:00:00" {
		t.Fatal(got)
	}
	fake2.LastLoginAt = ""
	if got := e.set.LastLogin(ctx, "alice"); got != "2026-04-21 10:11:12" {
		t.Fatal(got)
	}
	// A backend that is not enabled is not asked.
	e.enable("fake2")
	if got := e.set.LastLogin(ctx, "alice"); got != "never" {
		t.Fatal(got)
	}
}

func TestPresentIsEnabledThenInstalled(t *testing.T) {
	e := newTenv(t)
	fake2 := e.addFake("fake2")
	e.enable("fake")
	if got := e.set.Present(); !slices.Equal(got, []string{"fake", "tacacs"}) {
		t.Fatalf("%v", got) // tacacs (the test module) is always installed
	}
	fake2.SetInstalled(true)
	if got := e.set.Present(); !slices.Equal(got, []string{"fake", "tacacs", "fake2"}) {
		t.Fatalf("%v", got)
	}
	// An unreadable enabled list: every backend.
	e.enable("ldap")
	if got := e.set.Present(); !slices.Equal(got, []string{"tacacs", "fake", "fake2"}) {
		t.Fatalf("%v", got)
	}
}
