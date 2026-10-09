package lifecycle_test

// tests/integration/migrate_dead_command_matches.bats and
// migrate_exec_service_name.bats: the in-place migrations of a legacy
// tacquito.yaml that upgrades run (and their no-op with a store), and
// BackupConfig, the legacy-mode backup they take.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/rett/tacctl/internal/lifecycle"
	"github.com/rett/tacctl/internal/ui"
)

// operatorBlock is awk '/^operator: &operator/,/^  accounter:/' of
// tacquito.yaml.
func (e *tenv) operatorBlock() string {
	e.t.Helper()
	text := e.read(e.p.Config)
	i := strings.Index(text, "operator: &operator\n")
	if i < 0 {
		e.t.Fatal("no operator block")
	}
	rest := text[i:]
	j := strings.Index(rest, "\n  accounter:")
	if j < 0 {
		return rest
	}
	k := strings.Index(rest[j+1:], "\n")
	return rest[:j+1+k+1]
}

// addClearRule puts a real customization into the operator block: deny
// 'clear' outright.
func (e *tenv) addClearRule() {
	e.t.Helper()
	text := e.read(e.p.Config)
	old := "    - name: \"terminal\"\n      match: [\"^terminal .*$\"]\n      action: *action_permit\n"
	if !strings.Contains(text, old) {
		e.t.Fatal("fixture shape")
	}
	e.write(e.p.Config, strings.Replace(text, old, old+"    - name: \"clear\"\n      action: *action_deny\n", 1), 0o640)
}

// overrides appends to tacctl.yaml by hand (as an older tacctl left it)
// and reloads the view.
func (e *tenv) overrides(text string) {
	e.t.Helper()
	f, err := os.OpenFile(e.p.Overrides, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		e.t.Fatal(err)
	}
	_, _ = f.WriteString(text)
	_ = f.Close()
	e.be.Conf.Reload()
}

func (e *tenv) commandsJSON(group string) string {
	e.t.Helper()
	s, err := e.be.Conf.GetJSON("commands." + group)
	if err != nil {
		e.t.Fatal(err)
	}
	return s
}

const staleOperator = `commands:
  operator:
    - { name: show,       action: permit, match: ["^show .*$"] }
    - { name: ping,       action: permit, match: ["^ping( .*)?$"] }
    - { name: traceroute, action: permit, match: ["^traceroute( .*)?$"] }
    - { name: terminal,   action: permit, match: ["^terminal .*$"] }
    - { name: "*",        action: deny }
`

// --- conf_migrate_command_rules / conf_migrate_dead_command_matches ---

func TestMigrateScrapeAStaleBlockWithDeadRegexesIsNotAnOverride(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.dead-matches.yaml")
	if err := lifecycle.MigrateCommandRules(e.env); err != nil {
		t.Fatal(err)
	}
	hasNot(t, e.output(), "Migrated")
	if e.be.Conf.HasOverride("commands.operator") || e.be.Conf.HasOverride("commands.readonly") {
		t.Error("override written")
	}
}

func TestMigrateScrapeACustomizedBlockKeepsItsRulesAsAnOverride(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.dead-matches.yaml")
	e.addClearRule()
	if err := lifecycle.MigrateCommandRules(e.env); err != nil {
		t.Fatal(err)
	}
	has(t, e.output(), "[INFO] Migrated tacquito.yaml commands: block for group 'operator' → commands.operator\n")
	j := e.commandsJSON("operator")
	has(t, j, `"clear"`)
	hasNot(t, j, "^show")
	hasNot(t, j, "match")
	// Idempotent: the block now says what tacctl.yaml says.
	e.reset()
	if err := lifecycle.MigrateCommandRules(e.env); err != nil || e.output() != "" {
		t.Errorf("second run: %v %q", err, e.output())
	}
}

func TestMigrateHealAnOverrideEqualToTheDefaultIsDropped(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.dead-matches.yaml")
	e.overrides(staleOperator)
	if !e.be.Conf.HasOverride("commands.operator") {
		t.Fatal("setup")
	}
	if err := lifecycle.MigrateDeadCommandMatches(e.env); err != nil {
		t.Fatal(err)
	}
	has(t, e.output(), "[INFO] Dropped commands.operator override: its match regexes could never fire; shipped defaults now apply")
	if e.be.Conf.HasOverride("commands.operator") {
		t.Error("override kept")
	}
}

func TestMigrateHealACustomizedOverrideLosesOnlyTheDeadRegexes(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.dead-matches.yaml")
	e.overrides(`commands:
  operator:
    - { name: show,       action: permit, match: ["^show .*$", "running-config.*"] }
    - { name: ping,       action: permit, match: ["^ping( .*)?$"] }
    - { name: clear,      action: deny }
    - { name: "*",        action: deny }
`)
	if err := lifecycle.MigrateDeadCommandMatches(e.env); err != nil {
		t.Fatal(err)
	}
	has(t, e.output(), "[INFO] Rewrote commands.operator override: removed match regexes that could never fire")
	if !e.be.Conf.HasOverride("commands.operator") {
		t.Fatal("override dropped")
	}
	j := e.commandsJSON("operator")
	hasNot(t, j, "^show .*$")
	hasNot(t, j, "^ping")
	has(t, j, `"running-config.*"`)
	has(t, j, `"clear"`)
	// ping lost its only regex, so the key disappears (name-only rule).
	if !strings.Contains(j, `{"action": "permit", "name": "ping"}`) && !strings.Contains(j, `{"name": "ping", "action": "permit"}`) {
		t.Errorf("ping: %s", j)
	}
}

func TestMigrateHealIsANoOpWithoutDeadRegexes(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.dead-matches.yaml")
	e.overrides(`commands:
  operator:
    - { name: show,  action: permit, match: ["running-config.*"] }
    - { name: "*",   action: deny }
`)
	if err := lifecycle.MigrateDeadCommandMatches(e.env); err != nil || e.output() != "" {
		t.Errorf("%v %q", err, e.output())
	}
	has(t, e.commandsJSON("operator"), `"running-config.*"`)
}

func TestMigrateEndToEndShowIsANameOnlyPermitInTacquitoYAML(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.dead-matches.yaml")
	has(t, e.operatorBlock(), "^show .*$")
	if err := lifecycle.MigrateCommandRules(e.env); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.MigrateDeadCommandMatches(e.env); err != nil {
		t.Fatal(err)
	}
	if err := lifecycle.RegenerateCommands(ctx, e.env, ""); err != nil {
		t.Fatal(err)
	}
	b := e.operatorBlock()
	for _, s := range []string{`name: "show"`, `name: "terminal"`, `name: "*"`} {
		has(t, b, s)
	}
	// 'show' stays a name-only permit (no match: line under it).
	has(t, b, "    - name: \"show\"\n      action: *action_permit\n")
	if mode(t, e.p.Config) != 0o640 {
		t.Error("mode")
	}
	// Idempotent: nothing to write the second time (same inode).
	st1, _ := os.Stat(e.p.Config)
	if err := lifecycle.RegenerateCommands(ctx, e.env, ""); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(e.p.Config)
	if !os.SameFile(st1, st2) {
		t.Error("rewritten")
	}
}

func TestMigrateRegenerateOneGroupAndTheBlockShapes(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.dead-matches.yaml")
	e.overrides(`commands:
  operator:
    - { name: show,  action: permit, match: ["running-config.*", "version"] }
    - { name: "*",   action: deny }
  readonly: []
`)
	before := e.read(e.p.Config)
	if err := lifecycle.RegenerateCommands(ctx, e.env, "operator"); err != nil {
		t.Fatal(err)
	}
	b := e.operatorBlock()
	has(t, b, "  commands:\n    - name: \"show\"\n      match: [\"^(?:running-config.*)$\", \"^(?:version)$\"]\n      action: *action_permit\n"+
		"    - name: \"*\"\n      action: *action_deny\n  accounter:")
	// Only that group: readonly's block is as it was.
	ro := regexp.MustCompile(`(?ms)^readonly: &readonly\n.*?^  accounter:.*?\n`)
	if ro.FindString(before) != ro.FindString(e.read(e.p.Config)) {
		t.Error("readonly touched")
	}
	// Every group: readonly's empty list removes its commands: section.
	if err := lifecycle.RegenerateCommands(ctx, e.env, ""); err != nil {
		t.Fatal(err)
	}
	if blk := ro.FindString(e.read(e.p.Config)); strings.Contains(blk, "commands:") {
		t.Errorf("readonly block kept its commands:\n%s", blk)
	}
	if strings.Contains(e.read(e.p.Config), "\n\n\n") {
		t.Error("blank runs left")
	}
}

func TestMigrateUniversalNewlinesAndUnicodeNames(t *testing.T) {
	e := newTenv(t)
	// CRLF line ends are read as Python's text mode reads them; a group
	// whose name is not ASCII still counts as a word (Python's \w).
	text := strings.ReplaceAll(fixture(t, "tacquito.legacy-exec.yaml"), "\n", "\r\n")
	e.write(e.p.Config, text, 0o640)
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil {
		t.Fatal(err)
	}
	has(t, e.output(), "exec → shell for 3 group(s)")
	out := e.read(e.p.Config)
	if strings.Contains(out, "\r") || strings.Count(out, "\n  name: shell\n") != 3 {
		t.Error("not rewritten with universal newlines")
	}
	e.write(e.p.Config, "exec_bé: &exec_bé\n  name: exec\n", 0o640)
	e.reset()
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil {
		t.Fatal(err)
	}
	if e.read(e.p.Config) != "exec_bé: &exec_bé\n  name: shell\n" {
		t.Error(e.read(e.p.Config))
	}
}

// --- with a store ---

func TestMigrateWithAStoreTheScrapeIngestsNothing(t *testing.T) {
	e := newTenv(t)
	e.loadFixture("tacquito.dead-matches.yaml")
	e.addClearRule()
	if err := lifecycle.MigrateCommandRules(e.env); err != nil || e.output() != "" {
		t.Errorf("%v %q", err, e.output())
	}
	if e.be.Conf.HasOverride("commands.operator") {
		t.Error("override written")
	}
}

func TestMigrateWithAStoreHealAndRegenerateReRender(t *testing.T) {
	e := newTenv(t)
	e.loadFixture("tacquito.dead-matches.yaml")
	if err := e.set.ConfigRender(ctx, true); err != nil {
		t.Fatal(err)
	}
	e.overrides(`commands:
  operator:
    - { name: show,  action: permit, match: ["^show .*$", "running-config.*"] }
    - { name: clear, action: deny }
    - { name: "*",   action: deny }
`)
	if err := lifecycle.MigrateDeadCommandMatches(e.env); err != nil {
		t.Fatal(err)
	}
	e.reset()
	if err := lifecycle.RegenerateCommands(ctx, e.env, ""); err != nil || e.output() != "" {
		t.Fatalf("%v %q", err, e.output())
	}
	b := e.operatorBlock()
	has(t, b, `name: "show"`)
	has(t, b, `"^(?:running-config.*)$"`)
	has(t, b, `name: "clear"`)
	hasNot(t, b, "^show .*$")
	// Rendered and recorded: nothing left to render.
	if err := e.set.ConfigRender(ctx, false); err != nil {
		t.Fatal(err)
	}
	has(t, e.output(), "already up to date")
}

func TestMigrateWithAStoreRegenerateLeavesAHandEditedFileAlone(t *testing.T) {
	e := newTenv(t)
	e.loadFixture("tacquito.dead-matches.yaml")
	if err := e.set.ConfigRender(ctx, true); err != nil {
		t.Fatal(err)
	}
	f, _ := os.OpenFile(e.p.Config, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("# hand edit\n")
	_ = f.Close()
	e.overrides("commands:\n  operator:\n    - { name: \"*\", action: permit }\n")
	before := sha(t, e.p.Config)
	e.reset()
	if err := lifecycle.RegenerateCommands(ctx, e.env, ""); err != nil {
		t.Fatal(err)
	}
	has(t, e.output(), "was edited since tacctl rendered it")
	has(t, e.output(), "was not re-rendered")
	if sha(t, e.p.Config) != before {
		t.Error("overwritten")
	}
}

func TestMigrateConfigValidateFlagsADeadRegexOverride(t *testing.T) {
	e := newTenv(t)
	e.loadFixture("tacquito.dead-matches.yaml")
	e.overrides(`commands:
  operator:
    - { name: show,  action: permit, match: ["^show .*$"] }
    - { name: "*",   action: deny }
`)
	lines := strings.Join(e.be.Conf.Schema.ValidateFile(e.p.Overrides), "\n")
	has(t, lines, "commands.operator")
	has(t, lines, "can never match")
}

// --- conf_migrate_exec_service_name ---

func (e *tenv) backupCount() int {
	m, _ := filepath.Glob(filepath.Join(e.p.BackupDir, "tacquito.yaml.*"))
	return len(m)
}

func countLines(text, line string) int {
	return len(regexp.MustCompile(`(?m)^`+regexp.QuoteMeta(line)+`$`).FindAllString(text, -1))
}

func TestMigrateExecRewritesAllThreeCiscoAnchors(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.legacy-exec.yaml")
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil {
		t.Fatal(err)
	}
	has(t, e.output(), "[INFO] Migrated tacquito.yaml service name(s) exec → shell for 3 group(s)\n")
	cfg := e.read(e.p.Config)
	if countLines(cfg, "  name: shell") != 3 || countLines(cfg, "  name: exec") != 0 {
		t.Error(cfg)
	}
	// Junos services are not touched.
	if countLines(cfg, "  name: junos-exec") != 3 {
		t.Error("junos")
	}
	// Each anchor keeps its priv-lvl values.
	for anchor, v := range map[string]string{"exec_operator": "values: [7]", "exec_superuser": "values: [15]"} {
		i := strings.Index(cfg, "\n"+anchor+":")
		blk := cfg[i+1:]
		blk = strings.Join(strings.SplitN(blk, "\n", 6)[:5], "\n")
		has(t, blk, "name: shell")
		has(t, blk, v)
	}
	if mode(t, e.p.Config) != 0o640 {
		t.Error("mode")
	}
}

func TestMigrateExecBacksUpThePreMigrationConfig(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.legacy-exec.yaml")
	if e.backupCount() != 0 {
		t.Fatal("setup")
	}
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil {
		t.Fatal(err)
	}
	m, _ := filepath.Glob(filepath.Join(e.p.BackupDir, "tacquito.yaml.*"))
	if len(m) != 1 || countLines(e.read(m[0]), "  name: exec") != 3 {
		t.Fatal(m)
	}
	has(t, e.output(), "[INFO] Config backed up to "+m[0]+"\n")
	if !regexp.MustCompile(`tacquito\.yaml\.[0-9]{8}_[0-9]{6}_[0-9]{3}$`).MatchString(m[0]) || mode(t, m[0]) != 0o640 {
		t.Error(m[0])
	}
}

func TestMigrateExecASecondRunIsANoOp(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.legacy-exec.yaml")
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil {
		t.Fatal(err)
	}
	sum, n := sha(t, e.p.Config), e.backupCount()
	e.reset()
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil || e.output() != "" {
		t.Errorf("%v %q", err, e.output())
	}
	if e.backupCount() != n || sha(t, e.p.Config) != sum {
		t.Error("changed")
	}
}

func TestMigrateExecNoOpOnACurrentConfig(t *testing.T) {
	e := newTenv(t)
	e.placeFixture("tacquito.minimal.yaml")
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil || e.output() != "" || e.backupCount() != 0 {
		t.Errorf("%v %q", err, e.output())
	}
}

func TestMigrateExecWithAStoreTheFileIsLeftAlone(t *testing.T) {
	e := newTenv(t)
	e.loadFixture("tacquito.legacy-exec.yaml")
	before := sha(t, e.p.Config)
	if err := lifecycle.MigrateExecServiceName(e.env); err != nil || e.output() != "" {
		t.Errorf("%v %q", err, e.output())
	}
	if sha(t, e.p.Config) != before || e.backupCount() != 0 {
		t.Error("touched")
	}
	// The importer read 'exec' as the Cisco shell service, and the renderer
	// only ever writes 'shell'.
	if err := e.set.ConfigRender(ctx, true); err != nil {
		t.Fatal(err)
	}
	cfg := e.read(e.p.Config)
	if countLines(cfg, "  name: shell") != 3 || countLines(cfg, "  name: exec") != 0 {
		t.Error(cfg)
	}
}

// --- backup_config ---

func TestBackupConfigKeepsTheNewestThirty(t *testing.T) {
	e := newTenv(t)
	e.write(e.p.Config, "live\n", 0o640)
	for i := range 30 {
		f := filepath.Join(e.p.BackupDir, fmt.Sprintf("tacquito.yaml.2000%04d_000000", i))
		e.write(f, "old\n", 0o600)
		mt := time.Date(2000, 1, 1, 0, 0, i, 0, time.UTC)
		_ = os.Chtimes(f, mt, mt)
	}
	now := time.Date(2026, 10, 3, 1, 2, 3, 45e6, time.Local)
	if err := lifecycle.BackupConfig(e.p, e.be.Out, now); err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(e.p.BackupDir, "tacquito.yaml.20261003_010203_045")
	if e.read(dst) != "live\n" || mode(t, dst) != 0o640 || mode(t, e.p.BackupDir) != 0o750 {
		t.Error("copy")
	}
	if e.backupCount() != 30 || exists(filepath.Join(e.p.BackupDir, "tacquito.yaml.20000000_000000")) {
		t.Error("retention")
	}
	// No config to copy: cp's complaint, and the error is reported.
	_ = os.Remove(e.p.Config)
	e.reset()
	if err := lifecycle.BackupConfig(e.p, e.be.Out, now); err != ui.ErrReported {
		t.Error(err)
	}
	has(t, e.output(), "cp: ")
}

// --- tacacs_render_apply ---

func TestRenderApplyRefusesWithoutAStoreAndOnAHandEdit(t *testing.T) {
	e := newTenv(t)
	if _, err := lifecycle.RenderApply(ctx, e.env, false); err == nil {
		t.Fatal("rendered without a store")
	}
	has(t, e.output(), "[ERROR] store not initialised")
	e.loadFixture("tacquito.minimal.yaml")
	if err := e.set.ConfigRender(ctx, true); err != nil {
		t.Fatal(err)
	}
	if changed, err := lifecycle.RenderApply(ctx, e.env, false); changed || err != nil {
		t.Error("an up-to-date render changed something", changed, err)
	}
	f, _ := os.OpenFile(e.p.Config, os.O_APPEND|os.O_WRONLY, 0)
	_, _ = f.WriteString("# hand edit\n")
	_ = f.Close()
	e.reset()
	if _, err := lifecycle.RenderApply(ctx, e.env, false); err == nil {
		t.Fatal("a hand edit was overwritten")
	}
	has(t, e.output(), "was edited since tacctl rendered it; rendering would discard those edits.")
	e.reset()
	if changed, err := lifecycle.RenderApply(ctx, e.env, true); !changed || err != nil {
		t.Fatal(changed, err)
	}
	has(t, e.output(), "[WARN] Previous "+e.p.Config+" saved to ")
}

// --- a migration that fails: upgrade stops, install goes on ---

// failingSync is a legacy install whose first migration (the scrape of a
// customised commands: block) cannot write tacctl.yaml (the state
// directory takes no new files), and whose exec services are still named
// 'exec'. Checked against 0.1.16 by sourcing bin/tacctl.sh and running
// config_sync_existing under 'set -e' (upgrade) and under '|| true'
// (install, errexit off): see the expectations below.
func failingSync(t *testing.T) *tenv {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	e := newTenv(t)
	e.placeFixture("tacquito.dead-matches.yaml")
	e.addClearRule()
	back := regexp.MustCompile(`(?m)^(exec_\w+: &exec_\w+\n  name: )shell$`).ReplaceAllString(e.read(e.p.Config), "${1}exec")
	e.write(e.p.Config, back, 0o640)
	if countLines(e.read(e.p.Config), "  name: exec") != 3 {
		t.Fatal("setup")
	}
	if err := os.Chmod(e.p.StateDir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(e.p.StateDir, 0o700) })
	return e
}

// Upgrade (0.1.16 under 'set -e'): the run stops at the failed write;
// nothing after it happens.
func TestConfigSyncUpgradeStopsAtTheFirstFailedMigration(t *testing.T) {
	e := failingSync(t)
	before := sha(t, e.p.Config)
	changed, err := lifecycle.ConfigSyncExisting(ctx, e.env, lifecycle.SyncOptions{})
	if err == nil || changed {
		t.Fatal(changed, err)
	}
	out := e.output()
	has(t, out, "[ERROR] ")
	hasNot(t, out, "Migrated")
	hasNot(t, out, "Config backed up")
	if sha(t, e.p.Config) != before || e.backupCount() != 0 {
		t.Error("the run went on after the failure")
	}
	// The tacacs module's phase entry point is this mode.
	e.reset()
	if _, err := e.b.ConfigSyncExisting(ctx); err == nil || sha(t, e.p.Config) != before {
		t.Error("the phase went on after the failure")
	}
}

// Install (0.1.16 with errexit off): the failure is printed, the scrape
// still announces the group (as 0.1.16 did), and the remaining migrations
// run: the backup, the exec rename, the commands: blocks (from tacctl.yaml
// as it is, so the customised rule is gone, as in 0.1.16).
func TestConfigSyncInstallPrintsTheFailureAndRunsTheRest(t *testing.T) {
	e := failingSync(t)
	changed, err := lifecycle.ConfigSyncExisting(ctx, e.env, lifecycle.SyncOptions{ContinueOnError: true})
	if err == nil || !changed {
		t.Fatal(changed, err)
	}
	has(t, plain(e.stderr.String()), "[ERROR] tacctl.yaml: cannot write "+e.p.Overrides)
	out := plain(e.stdout.String())
	iErr := 0
	iScrape := strings.Index(out, "[INFO] Migrated tacquito.yaml commands: block for group 'operator' → commands.operator\n")
	iBackup := strings.Index(out, "[INFO] Config backed up to ")
	iExec := strings.Index(out, "[INFO] Migrated tacquito.yaml service name(s) exec → shell for 3 group(s)\n")
	if iErr < 0 || iScrape < iErr || iBackup < iScrape || iExec < iBackup {
		t.Errorf("order: %d %d %d %d\n%s", iErr, iScrape, iBackup, iExec, out)
	}
	cfg := e.read(e.p.Config)
	if countLines(cfg, "  name: exec") != 0 || strings.Contains(cfg, "name: \"clear\"\n      action: *action_deny") || e.backupCount() != 1 {
		t.Error(cfg)
	}
}

// InstallSeed's legacy path is the install mode.
func TestInstallSeedOverALegacyConfigRunsEveryMigration(t *testing.T) {
	e := failingSync(t)
	r, err := lifecycle.InstallSeed(ctx, e.env)
	if err != nil || r.Mode != lifecycle.SeedLegacy {
		t.Fatalf("%+v %v\n%s", r, err, e.output())
	}
	has(t, e.output(), "exec → shell for 3 group(s)")
	has(t, e.output(), "Store migration stopped")
}
