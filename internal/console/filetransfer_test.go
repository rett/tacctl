package console

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/tier"
)

func TestParseSize(t *testing.T) {
	for _, c := range []struct {
		in   string
		want int64
	}{
		{"1", 1}, {"1000", 1000}, {"512K", 512 << 10}, {"512k", 512 << 10}, {"256M", 256 << 20}, {"2G", 2 << 30},
		{"1T", 1 << 40}, {"1024G", 1 << 40}, {"1048576K", 1 << 30}, {"007", 7},
	} {
		got, err := ParseSize(c.in)
		if err != nil || got != c.want {
			t.Errorf("ParseSize(%q) = %d, %v; want %d", c.in, got, err, c.want)
		}
	}
	for _, in := range []string{
		"", "0", "0K", "-1", "-5M", "+5", "1.5G", "1e3", "G", "K", "12X", "12MB", "1 M", " 1", "0x10", "unlimited", "off",
		"1025G", "2T", "9223372036854775807", "9223372036854775808", "99999999999999999999", "9007199254740993T",
	} {
		if n, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) = %d: accepted", in, n)
		}
	}
	// Over 1 TiB is refused with a message that says so; zero says zero.
	if _, err := ParseSize("2T"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("2T: %v", err)
	}
	if _, err := ParseSize("0"); err == nil || !strings.Contains(err.Error(), "zero") {
		t.Errorf("0: %v", err)
	}
	if _, err := ParseSize("9223372036854775808"); err == nil || !strings.Contains(err.Error(), "too large") {
		t.Errorf("overflow: %v", err)
	}
	// A unit with no number is a malformed size, not a large one.
	for _, in := range []string{"K", "k", "M", "G", "T"} {
		if _, err := ParseSize(in); err == nil || !strings.Contains(err.Error(), "Invalid size '"+in+"'") || strings.Contains(err.Error(), "too large") {
			t.Errorf("%s: %v", in, err)
		}
	}
}

func TestFormatSize(t *testing.T) {
	for in, want := range map[int64]string{
		1: "1", 1000: "1000", 1024: "1K", 1536: "1536", 512 << 10: "512K", 1 << 20: "1M", 256 << 20: "256M", (1 << 20) + 1: "1048577",
		1 << 30: "1G", 3 << 30: "3G", 1 << 40: "1T", 1500 << 20: "1500M",
	} {
		if got := FormatSize(in); got != want {
			t.Errorf("FormatSize(%d) = %q, want %q", in, got, want)
		}
	}
	// what is printed is read back as the same number
	for _, n := range []int64{1, 1000, 1024, 5 << 20, 7 << 30, 1 << 40, 123457} {
		if back, err := ParseSize(FormatSize(n)); err != nil || back != n {
			t.Errorf("%d: %q -> %d, %v", n, FormatSize(n), back, err)
		}
	}
	if QuotaWord(0) != "unlimited" || RateWord(0) != "off" || QuotaWord(2<<20) != "2M" || RateWord(1<<10) != "1K" {
		t.Error("the words of quota and rate")
	}
	if n, err := ParseQuota("unlimited"); err != nil || n != 0 {
		t.Errorf("unlimited: %d %v", n, err)
	}
	if n, err := ParseRate("off"); err != nil || n != 0 {
		t.Errorf("off: %d %v", n, err)
	}
	if _, err := ParseQuota("off"); err == nil {
		t.Error("a quota of off")
	}
	if _, err := ParseRate("unlimited"); err == nil {
		t.Error("a rate of unlimited")
	}
}

// The defaults: off for every tier but the superuser tier, quota 256 MiB
// (none for the superuser tier), no rate; nothing is written to the file.
func TestFileTransferDefaults(t *testing.T) {
	p := &Policy{File: Defaults()}
	for _, c := range []struct {
		t     tier.Tier
		on    bool
		quota int64
	}{
		{tier.Readonly, false, 256 << 20}, {tier.Operator, false, 256 << 20}, {tier.Engineer, false, 256 << 20}, {tier.Superuser, true, 0},
		{tier.None, false, 0}, {tier.Unrestricted, false, 0},
	} {
		got := p.FileTransfer("dave", c.t)
		if got.Enabled != c.on || got.Rate != 0 {
			t.Errorf("%s: %+v", c.t, got)
		}
		if c.on && got.Quota != c.quota {
			t.Errorf("%s: quota %d", c.t, got.Quota)
		}
	}
	if q, from := p.FileTransferQuota("dave", tier.Operator); q != 256<<20 || from != "default" {
		t.Errorf("quota %d %q", q, from)
	}
	text, err := Defaults().Text()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), "file_transfer") {
		t.Errorf("the defaults write the key:\n%s", text)
	}
	// setting the superuser tier alone, or a tier on and off again, is the default
	f := Defaults()
	if err := f.SetFileTransfer(tier.Operator, true); err != nil {
		t.Fatal(err)
	}
	if err := f.SetFileTransfer(tier.Operator, false); err != nil {
		t.Fatal(err)
	}
	if text, err = f.Text(); err != nil || strings.Contains(string(text), "file_transfer") {
		t.Errorf("%v\n%s", err, text)
	}
}

func TestSetFileTransfer(t *testing.T) {
	f := Defaults()
	for _, tr := range []tier.Tier{tier.Engineer, tier.Readonly} {
		if err := f.SetFileTransfer(tr, true); err != nil {
			t.Fatalf("%s: %v", tr, err)
		}
	}
	// the engineer tier is not closed; the list is lowest first with the superuser tier in
	if want := []tier.Tier{tier.Readonly, tier.Engineer, tier.Superuser}; !reflect.DeepEqual(f.FileTransferTiers, want) {
		t.Errorf("tiers %v, want %v", f.FileTransferTiers, want)
	}
	if err := f.SetFileTransfer(tier.Superuser, false); err == nil || !strings.Contains(err.Error(), "always") {
		t.Errorf("superuser off: %v", err)
	}
	if err := f.SetFileTransfer(tier.Superuser, true); err != nil {
		t.Errorf("superuser on: %v", err)
	}
	if err := f.SetFileTransfer(tier.Readonly, false); err != nil {
		t.Fatal(err)
	}
	if want := []tier.Tier{tier.Engineer, tier.Superuser}; !reflect.DeepEqual(f.FileTransferTiers, want) {
		t.Errorf("tiers %v, want %v", f.FileTransferTiers, want)
	}
}

// The user's own setting wins over the tier's, in both directions, but for
// the superuser tier (always) and a caller with no tier (never); an enable is
// for the tier it was set for.
func TestFileTransferForUsers(t *testing.T) {
	f := Defaults()
	if err := f.SetFileTransfer(tier.Operator, true); err != nil {
		t.Fatal(err)
	}
	f.SetFileTransferUser("carol", true, tier.Readonly)
	f.SetFileTransferUser("bob", false, "")
	f.SetFileTransferUser("alice", false, "")
	f.SetFileTransferUser("erin", true, tier.Engineer)
	f.SetFileTransferUser("gus", true, tier.Operator)
	p := &Policy{File: f}
	for _, c := range []struct {
		user string
		t    tier.Tier
		want bool
		why  string
	}{
		{"carol", tier.Readonly, true, "user setting"},
		{"dave", tier.Readonly, false, "tier readonly"},
		{"bob", tier.Operator, false, "user setting"},
		{"eve", tier.Operator, true, "tier operator"},
		{"alice", tier.Superuser, true, "always"},
		{"erin", tier.Engineer, true, "user setting"}, // the engineer tier can be given it
		{"carol", tier.None, false, "no tier; stale: set for readonly, now none"},
		{"gus", tier.Operator, true, "user setting"},
		{"gus", tier.Readonly, false, "tier readonly; stale: set for operator, now readonly"},
		{"gus", tier.Superuser, true, "always; stale: set for operator, now superuser"},
		{"carol", tier.Operator, true, "tier operator; stale: set for readonly, now operator"},
		{"bob", tier.Readonly, false, "user setting"},
		{"erin", tier.Operator, true, "tier operator; stale: set for engineer, now operator"},
	} {
		if got := p.FileTransferFor(c.user, c.t); got != c.want {
			t.Errorf("%s at %s: %v, want %v", c.user, c.t, got, c.want)
		}
		if on, why := p.FileTransferWhy(c.user, c.t); on != c.want || why != c.why {
			t.Errorf("%s at %s: why %v %q, want %v %q", c.user, c.t, on, why, c.want, c.why)
		}
		if got := p.FileTransfer(c.user, c.t).Enabled; got != c.want {
			t.Errorf("%s at %s: FileTransfer %v", c.user, c.t, got)
		}
	}
	// a caller with no tier never has it, whatever the file says
	f.SetFileTransferUser("dave", true, tier.None)
	if p.FileTransferFor("dave", tier.Unrestricted) || p.FileTransferFor("dave", tier.None) || p.FileTransfer("dave", tier.Unrestricted) != (FileTransfer{}) {
		t.Error("unrestricted or none has file transfer")
	}
	if was, stale := p.FileTransferStale("gus", tier.Readonly); !stale || was != tier.Operator {
		t.Errorf("stale %v %v", was, stale)
	}
	if _, stale := p.FileTransferStale("bob", tier.Readonly); stale {
		t.Error("a disable is never stale")
	}
}

// Quota and rate: the user's value wins over the tier's, the tier's over the
// built-in default; unlimited and off are values.
func TestFileTransferQuotaAndRate(t *testing.T) {
	f := Defaults()
	f.SetFileTransferQuota(tier.Operator, 1<<30, false)
	f.SetFileTransferQuota(tier.Superuser, 2<<30, false)
	f.SetFileTransferQuota(tier.Engineer, 0, false) // unlimited
	f.FileTransferQuotaUsers["bob"] = 512 << 10
	f.FileTransferQuotaUsers["carol"] = 0
	f.SetFileTransferRate(tier.Operator, 1<<20)
	f.FileTransferRateUsers["bob"] = 0
	f.FileTransferRateUsers["carol"] = 64 << 10
	for _, t2 := range Tiers {
		if err := f.SetFileTransfer(t2, true); err != nil && t2 != tier.Superuser {
			t.Fatal(err)
		}
	}
	p := &Policy{File: f}
	for _, c := range []struct {
		user        string
		t           tier.Tier
		quota, rate int64
		qFrom       string
	}{
		{"dave", tier.Readonly, 256 << 20, 0, "default"},
		{"dave", tier.Operator, 1 << 30, 1 << 20, "tier setting"},
		{"dave", tier.Engineer, 0, 0, "tier setting"},
		{"dave", tier.Superuser, 2 << 30, 0, "tier setting"},
		{"bob", tier.Operator, 512 << 10, 0, "user setting"},
		{"carol", tier.Readonly, 0, 64 << 10, "user setting"},
	} {
		got := p.FileTransfer(c.user, c.t)
		if !got.Enabled || got.Quota != c.quota || got.Rate != c.rate {
			t.Errorf("%s at %s: %+v, want quota %d rate %d", c.user, c.t, got, c.quota, c.rate)
		}
		if _, from := p.FileTransferQuota(c.user, c.t); from != c.qFrom {
			t.Errorf("%s at %s: quota from %q", c.user, c.t, from)
		}
	}
	// back to the default
	f.SetFileTransferQuota(tier.Operator, 0, true)
	f.SetFileTransferRate(tier.Operator, 0)
	if got := p.FileTransfer("dave", tier.Operator); got.Quota != 256<<20 || got.Rate != 0 {
		t.Errorf("after the reset: %+v", got)
	}
	// the user is not asked for with no name
	if q, from := p.FileTransferQuota("", tier.Readonly); q != 256<<20 || from != "default" {
		t.Errorf("no user: %d %q", q, from)
	}
}

const fileTransferText = Header + `version: 1
settings:
  idle_timeout: 30
  agent_forwarding: false
  ssh_escape: false
  system_shell: /bin/bash
  system_shell_tiers: [superuser]
  forwarding_tiers: [superuser]
  gateway_ports: false
  list_max: 40
  file_transfer:
    tiers: [operator, engineer, superuser]
    users: {bob: disable, carol: 'enable:readonly'}
    quota: {operator: 1G, superuser: unlimited}
    quota_users: {carol: 512K}
    rate: {operator: 1M}
    rate_users: {bob: 'off', carol: '1000'}
`

// The settings are written and read back as they are set, sizes in the
// largest exact unit, in the order of the file above (the YAML writer quotes the words that are
// booleans or numbers to a plain reader); a file with them is
// rewritten to the same bytes.
func TestFileTransferRoundTrip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.yaml")
	_, err := Mutate(p, nil, func(f *File) error {
		if err := f.SetFileTransfer(tier.Engineer, true); err != nil {
			return err
		}
		if err := f.SetFileTransfer(tier.Operator, true); err != nil {
			return err
		}
		f.SetFileTransferUser("carol", true, tier.Readonly)
		f.SetFileTransferUser("bob", false, "")
		f.SetFileTransferQuota(tier.Operator, 1<<30, false)
		f.SetFileTransferQuota(tier.Superuser, 0, false)
		f.FileTransferQuotaUsers["carol"] = 512 << 10
		f.SetFileTransferRate(tier.Operator, 1<<20)
		f.FileTransferRateUsers["bob"] = 0
		f.FileTransferRateUsers["carol"] = 1000
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(p)
	if string(got) != fileTransferText {
		t.Errorf("the file:\n%s\nwant:\n%s", got, fileTransferText)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.FileTransferTiers, []tier.Tier{tier.Operator, tier.Engineer, tier.Superuser}) ||
		f.FileTransferUsers["bob"] || !f.FileTransferUsers["carol"] || f.FileTransferUserTiers["carol"] != tier.Readonly ||
		f.FileTransferQuota[tier.Operator] != 1<<30 || f.FileTransferQuota[tier.Superuser] != 0 || len(f.FileTransferQuota) != 2 ||
		f.FileTransferQuotaUsers["carol"] != 512<<10 || f.FileTransferRate[tier.Operator] != 1<<20 ||
		f.FileTransferRateUsers["bob"] != 0 || f.FileTransferRateUsers["carol"] != 1000 || len(f.FileTransferRateUsers) != 2 {
		t.Errorf("read back: %+v", f)
	}
	if changed, err := Mutate(p, nil, func(*File) error { return nil }); err != nil || changed {
		t.Errorf("a second write changed the file: %v %v", changed, err)
	}
	// the clone is deep
	c := f.Clone()
	c.FileTransferUsers["zed"] = true
	c.FileTransferQuota[tier.Readonly] = 5
	c.FileTransferRateUsers["zed"] = 5
	c.FileTransferTiers[0] = tier.Readonly
	if _, ok := f.FileTransferUsers["zed"]; ok || len(f.FileTransferQuota) != 2 || len(f.FileTransferRateUsers) != 2 || f.FileTransferTiers[0] != tier.Operator {
		t.Error("Clone shares a map or a list")
	}
}

// A file with the user's rate written as an unquoted off (a boolean to YAML
// 1.1) is read as off.
func TestFileTransferRateUnquotedOff(t *testing.T) {
	p := write(t, t.TempDir(), "console.yaml", "version: 1\nsettings:\n  file_transfer:\n    tiers: [superuser]\n    rate_users: {bob: off}\n", 0o600)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if n, ok := f.FileTransferRateUsers["bob"]; !ok || n != 0 {
		t.Errorf("%v %v", n, ok)
	}
}

// A tier's rate of off (quoted or not) is the built-in setting, as it is for
// a user: it is read, and nothing is stored for the tier.
func TestFileTransferTierRateOff(t *testing.T) {
	for _, body := range []string{"rate: {operator: 'off', engineer: 1M}", "rate: {operator: off, engineer: 1M}"} {
		p := write(t, t.TempDir(), "console.yaml", "version: 1\nsettings:\n  file_transfer:\n    tiers: [superuser]\n    "+body+"\n", 0o600)
		f, err := Load(p)
		if err != nil {
			t.Fatalf("%s: %v", body, err)
		}
		if _, ok := f.FileTransferRate[tier.Operator]; ok || f.FileTransferRate[tier.Engineer] != 1<<20 {
			t.Errorf("%s: %v", body, f.FileTransferRate)
		}
	}
}

func TestFileTransferInvalidFiles(t *testing.T) {
	for _, c := range []struct{ name, body, want string }{
		{"not a mapping", "file_transfer: yes\n", "must be a mapping"},
		{"unknown key", "file_transfer: {tiers: [superuser], rates: {}}\n", "unknown key 'rates'"},
		{"unknown tier", "file_transfer: {tiers: [admin]}\n", "invalid or repeated tier 'admin'"},
		{"repeated tier", "file_transfer: {tiers: [operator, operator]}\n", "invalid or repeated tier 'operator'"},
		{"none tier", "file_transfer: {tiers: [none]}\n", "invalid or repeated tier 'none'"},
		{"tier not a string", "file_transfer: {tiers: [1]}\n", "invalid value for 'tiers'"},
		{"user enable without tier", "file_transfer: {users: {bob: enable}}\n", "must be disable or enable"},
		{"user disable with tier", "file_transfer: {users: {bob: 'disable:operator'}}\n", "must be disable or enable"},
		{"user enable for superuser", "file_transfer: {users: {bob: 'enable:superuser'}}\n", "must be disable or enable"},
		{"user enable for none", "file_transfer: {users: {bob: 'enable:none'}}\n", "must be disable or enable"},
		{"bad user name", "file_transfer: {users: {'a.b': disable}}\n", "invalid user name 'a.b'"},
		{"bad quota user name", "file_transfer: {quota_users: {'a b': 1M}}\n", "invalid user name"},
		{"quota tier", "file_transfer: {quota: {admin: 1M}}\n", "invalid tier 'admin'"},
		{"quota zero", "file_transfer: {quota: {operator: 0}}\n", "must be a size or unlimited"},
		{"quota negative", "file_transfer: {quota: {operator: -5}}\n", "must be a size or unlimited"},
		{"quota too large", "file_transfer: {quota: {operator: 2T}}\n", "must be a size or unlimited"},
		{"quota int too large", "file_transfer: {quota: {operator: 9999999999999999}}\n", "must be a size or unlimited"},
		{"quota fraction", "file_transfer: {quota: {operator: 1.5G}}\n", "must be a size or unlimited"},
		{"quota off", "file_transfer: {quota: {operator: 'off'}}\n", "must be a size or unlimited"},
		{"rate unlimited", "file_transfer: {rate: {operator: unlimited}}\n", "must be a size"},
		{"rate list", "file_transfer: {rate_users: {bob: [1]}}\n", "must be a size or off"},
		{"quota users list", "file_transfer: {quota_users: [bob]}\n", "must be a mapping"},
	} {
		p := write(t, t.TempDir(), "console.yaml", "version: 1\nsettings:\n  "+c.body, 0o600)
		_, err := Load(p)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want %q", c.name, err, c.want)
		}
	}
	// the writer refuses what the reader would
	f := Defaults()
	f.FileTransferQuota[tier.Operator] = -1
	if _, err := f.Text(); err == nil {
		t.Error("a negative quota is written")
	}
	f = Defaults()
	f.FileTransferRate[tier.Operator] = 0
	if _, err := f.Text(); err == nil {
		t.Error("a zero rate for a tier is written")
	}
	f = Defaults()
	f.FileTransferQuotaUsers["bob"] = MaxFileTransferSize + 1
	if _, err := f.Text(); err == nil {
		t.Error("a quota over 1 TiB is written")
	}
	f = Defaults()
	f.FileTransferUsers["bob"] = true // no tier stamp
	if _, err := f.Text(); err == nil {
		t.Error("an enable without a tier is written")
	}
}

// A file without the key is read and written as before: the sizes of the
// older settings do not move, and the key is added only when it is needed.
func TestFileTransferKeyIsOptional(t *testing.T) {
	p := write(t, t.TempDir(), "console.yaml", "version: 1\nsettings:\n  idle_timeout: 12\n", 0o600)
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(f.FileTransferTiers, []tier.Tier{tier.Superuser}) || len(f.FileTransferUsers) != 0 {
		t.Errorf("%+v", f)
	}
	// an empty tiers list in a file is no tier but the superuser tier's always
	p = write(t, t.TempDir(), "console.yaml", "version: 1\nsettings:\n  file_transfer: {tiers: []}\n", 0o600)
	f, err = Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !(&Policy{File: f}).FileTransferTier(tier.Superuser) || (&Policy{File: f}).FileTransferTier(tier.Operator) {
		t.Error("an empty list")
	}
}

// The user's settings follow a rename and go with a removal, and the upgrade's
// rename of a name with a period carries them.
func TestFileTransferFollowsTheUser(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "console.yaml")
	if _, err := Mutate(p, nil, func(f *File) error {
		f.SetFileTransferUser("alice", true, tier.Operator)
		f.FileTransferQuotaUsers["alice"] = 1 << 30
		f.FileTransferRateUsers["alice"] = 1 << 20
		f.SetFileTransferUser("bob", false, "")
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	m := MoveUserSettings(p, "alice", "carol")
	if m.Err != nil || !m.FileHad || m.FileWhat != "enable:operator, quota 1G, rate 1M" || !m.Had() || m.ShellHad || m.CacheHad {
		t.Fatalf("move: %+v", m)
	}
	f, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if f.FileTransferUsers["carol"] != true || f.FileTransferUserTiers["carol"] != tier.Operator || f.FileTransferQuotaUsers["carol"] != 1<<30 ||
		f.FileTransferRateUsers["carol"] != 1<<20 || len(f.FileTransferUsers) != 2 || len(f.FileTransferQuotaUsers) != 1 || len(f.FileTransferRateUsers) != 1 {
		t.Errorf("after the move: %+v", f)
	}
	// a removal leaves nothing for the next user of the name
	m = MoveUserSettings(p, "carol", "")
	if m.Err != nil || !m.FileHad {
		t.Fatalf("drop: %+v", m)
	}
	f, _ = Load(p)
	if len(f.FileTransferUsers) != 1 || len(f.FileTransferQuotaUsers) != 0 || len(f.FileTransferRateUsers) != 0 || f.FileTransferUsers["bob"] {
		t.Errorf("after the drop: %+v", f)
	}
	// a user with no setting does not touch the file
	before, _ := os.ReadFile(p)
	if m = MoveUserSettings(p, "dave", "erin"); m.Had() || m.Err != nil {
		t.Errorf("dave: %+v", m)
	}
	if after, _ := os.ReadFile(p); string(after) != string(before) {
		t.Error("the file was rewritten")
	}

	q := write(t, dir, "dotted.yaml", `version: 1
settings:
  file_transfer:
    tiers: [operator, superuser]
    users: {alice.smith: 'enable:operator', dave.x: disable}
    quota_users: {alice.smith: 1G, erin.y: unlimited}
    rate_users: {alice.smith: 1M}
`, 0o600)
	res, err := RenameUsers(q, []UserRename{{"alice.smith", "alice_smith"}})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Moves[0].FileHad || strings.Join(res.Dropped, ",") != "dave.x,erin.y" {
		t.Errorf("rename: %+v", res)
	}
	f, err = Load(q)
	if err != nil {
		t.Fatalf("the file written is not read: %v", err)
	}
	if !f.FileTransferUsers["alice_smith"] || f.FileTransferQuotaUsers["alice_smith"] != 1<<30 || f.FileTransferRateUsers["alice_smith"] != 1<<20 ||
		len(f.FileTransferUsers) != 1 || len(f.FileTransferQuotaUsers) != 1 {
		t.Errorf("after the rename: %+v", f)
	}
	// DropDottedUserKeys names what it drops
	r := write(t, dir, "old.yaml", "version: 1\nsettings:\n  file_transfer:\n    tiers: [superuser]\n    users: {a.b: 'enable:readonly'}\n    rate_users: {a.b: 1M}\n", 0o600)
	text, dropped, err := DropDottedUserKeys(r)
	if err != nil || len(dropped) != 1 || dropped[0] != (DroppedSetting{"a.b", "file transfer enable:readonly, rate 1M"}) {
		t.Fatalf("dropped %v %v", dropped, err)
	}
	if strings.Contains(string(text), "a.b") {
		t.Errorf("the text keeps the name:\n%s", text)
	}
}

// The console's own process reads the file transfer fields of the answer: a
// transfer is off unless the answer says it is on, a damaged number is left
// out (no limit, off), and the line the root side writes is read back to the
// same settings.
func TestParseRemoteFileTransfer(t *testing.T) {
	r, ok := ParseRemote("shell=console tier=operator file_transfer=yes ft_quota=268435456 ft_rate=1048576")
	if !ok || r.FileTransfer != (FileTransfer{Enabled: true, Quota: 256 << 20, Rate: 1 << 20}) || r.FileTransferSettings() != r.FileTransfer {
		t.Errorf("on: %+v %v", r.FileTransfer, ok)
	}
	r, _ = ParseRemote("shell=console tier=superuser file_transfer=yes ft_quota=0 ft_rate=0")
	if got := r.FileTransferSettings(); got != (FileTransfer{Enabled: true}) {
		t.Errorf("unlimited: %+v", got)
	}
	for _, line := range []string{
		"shell=console tier=operator file_transfer=no",
		"shell=console tier=operator",
		"shell=console tier=operator file_transfer=maybe ft_quota=5",
		"shell=console tier=operator ft_quota=5 ft_rate=5", // numbers without the switch
		"shell=console tier=operator file_transfer=no ft_quota=5 ft_rate=5",
	} {
		r, ok := ParseRemote(line)
		if !ok || r.FileTransferSettings().Enabled || (r.FileTransferSettings() != FileTransfer{}) {
			t.Errorf("%q: %+v %v", line, r.FileTransferSettings(), ok)
		}
	}
	// a damaged number is left out
	r, _ = ParseRemote("shell=console tier=operator file_transfer=yes ft_quota=-1 ft_rate=x")
	if got := r.FileTransferSettings(); got != (FileTransfer{Enabled: true}) {
		t.Errorf("damaged: %+v", got)
	}
	r, _ = ParseRemote("shell=console tier=operator file_transfer=yes ft_quota=2199023255553 ft_rate=99999999999999999999")
	if got := r.FileTransferSettings(); got != (FileTransfer{Enabled: true}) {
		t.Errorf("out of range: %+v", got)
	}
	// no answer: no file transfer
	if r, ok := ParseRemote(""); ok || r.FileTransferSettings() != (FileTransfer{}) || DefaultRemote().FileTransfer != (FileTransfer{}) {
		t.Errorf("no answer: %+v %v", r.FileTransfer, ok)
	}
	// what the root side writes is what the console reads
	for _, ft := range []FileTransfer{{}, {Enabled: true}, {Enabled: true, Quota: 5 << 30, Rate: 64 << 10}, {Enabled: true, Quota: MaxFileTransferSize, Rate: MaxFileTransferSize}} {
		r, ok := ParseRemote("shell=console tier=readonly" + FileTransferFields(ft))
		if !ok || r.FileTransferSettings() != ft {
			t.Errorf("%+v -> %q -> %+v", ft, FileTransferFields(ft), r.FileTransferSettings())
		}
	}
	if FileTransferFields(FileTransfer{Quota: 5, Rate: 5}) != "" {
		t.Error("a disabled transfer writes its limits")
	}
}
