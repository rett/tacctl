package conf

import (
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/reports"
)

// The limits of the stored reports (0.2.26, D326): reports.max_size in bytes
// (0 to 1 GiB) and reports.max_count (0 to 100000), 0 for no cap.

func TestReportsLimitDefaultsAreTheReportsPackages(t *testing.T) {
	if ReportsMaxSizeDefault != reports.DefaultMaxSize || ReportsMaxCountDefault != reports.DefaultMaxCount {
		t.Errorf("defaults %d %d, reports has %d %d", ReportsMaxSizeDefault, ReportsMaxCountDefault, reports.DefaultMaxSize, reports.DefaultMaxCount)
	}
	s := NewSchema(DefaultBackends)
	if v, ok := s.ImplicitDefault(ReportsMaxSizeKey); !ok || v != ReportsMaxSizeDefault {
		t.Errorf("default of %s = %v, %v", ReportsMaxSizeKey, v, ok)
	}
	if v, ok := s.ImplicitDefault(ReportsMaxCountKey); !ok || v != ReportsMaxCountDefault {
		t.Errorf("default of %s = %v, %v", ReportsMaxCountKey, v, ok)
	}
	c := tempConf(t)
	if v, _ := c.Get(ReportsMaxSizeKey, "x"); v != "x" {
		t.Errorf("unset size reads %q: the caller's fallback is the default", v)
	}
	if c.HasOverride(ReportsMaxSizeKey) || c.HasOverride(ReportsMaxCountKey) {
		t.Error("a fresh file has an override")
	}
}

func TestReportsLimitsAreBounded(t *testing.T) {
	s := NewSchema(DefaultBackends)
	for _, v := range []any{0, 1, 10485760, 1 << 30} {
		if p := s.Validate(ReportsMaxSizeKey, v, false); p != "" {
			t.Errorf("%s = %v: %s", ReportsMaxSizeKey, v, p)
		}
	}
	for _, v := range []any{-1, 1<<30 + 1, "10Mi", "big", 1.5, true} {
		if p := s.Validate(ReportsMaxSizeKey, v, false); p == "" {
			t.Errorf("%s = %#v is accepted", ReportsMaxSizeKey, v)
		}
	}
	for _, v := range []any{0, 1, 100, 100000} {
		if p := s.Validate(ReportsMaxCountKey, v, false); p != "" {
			t.Errorf("%s = %v: %s", ReportsMaxCountKey, v, p)
		}
	}
	for _, v := range []any{-1, 100001, "many", 2.5, true} {
		if p := s.Validate(ReportsMaxCountKey, v, false); p == "" {
			t.Errorf("%s = %#v is accepted", ReportsMaxCountKey, v)
		}
	}
	for _, bad := range []string{"reports", "reports.max_sizes", "reports.max_size.x", "reports.max-size"} {
		if _, ok := s.RuleFor(bad); ok {
			t.Errorf("%q is a schema key", bad)
		}
	}
}

func TestReportsLimitsRoundTripThroughSet(t *testing.T) {
	c := tempConf(t)
	must(t, c.Set(ReportsMaxSizeKey, "20971520"))
	must(t, c.Set(ReportsMaxCountKey, "0"))
	got := Load(c.Path, DefaultBackends)
	if v, _ := got.Get(ReportsMaxSizeKey, ""); v != "20971520" {
		t.Errorf("size = %q", v)
	}
	if v, _ := got.Get(ReportsMaxCountKey, ""); v != "0" {
		t.Errorf("count = %q: 0 is a value, not unset", v)
	}
	if !got.HasOverride(ReportsMaxSizeKey) || !got.HasOverride(ReportsMaxCountKey) {
		t.Error("the keys are not overrides")
	}
	text, _ := os.ReadFile(c.Path)
	if !strings.Contains(string(text), "reports:") || !strings.Contains(string(text), "max_size: 20971520") || !strings.Contains(string(text), "max_count: 0") {
		t.Errorf("file:\n%s", text)
	}
	if prob := got.Problem(); prob != "" {
		t.Errorf("the file does not validate: %s", prob)
	}
	for _, bad := range []struct{ k, v string }{
		{ReportsMaxSizeKey, "1073741825"}, {ReportsMaxSizeKey, "-1"}, {ReportsMaxSizeKey, "20Mi"},
		{ReportsMaxCountKey, "100001"}, {ReportsMaxCountKey, "-5"}, {ReportsMaxCountKey, "x"},
	} {
		if err := c.Set(bad.k, bad.v); err == nil {
			t.Errorf("Set(%s, %s) succeeded", bad.k, bad.v)
		}
	}
	if v, _ := Load(c.Path, DefaultBackends).Get(ReportsMaxSizeKey, ""); v != "20971520" {
		t.Errorf("a refused value changed the file: %q", v)
	}
	must(t, c.Unset(ReportsMaxSizeKey))
	must(t, c.Unset(ReportsMaxCountKey))
	if v, _ := Load(c.Path, DefaultBackends).Get(ReportsMaxSizeKey, "x"); v != "x" {
		t.Errorf("after unset the size reads %q", v)
	}
}
