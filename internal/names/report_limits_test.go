package names

import "testing"

func TestParseReportSize(t *testing.T) {
	ok := map[string]int64{
		"0": 0, "1": 1, "512": 512, "10485760": 10485760, "1Ki": 1024, "20Mi": 20 << 20,
		"1Gi": 1 << 30, "0Mi": 0, "1048576Ki": 1 << 30, "007": 7, "1073741824": 1 << 30,
	}
	for in, want := range ok {
		if got, err := ParseReportSize(in); err != nil || got != want {
			t.Errorf("ParseReportSize(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{
		"", "Mi", "-1", "+1", "1.5Mi", "1 Mi", "1mi", "1MiB", "1M", "1G", "abc", "1e3", "0x10",
		"1073741825", "2Gi", "1048577Ki", "1025Mi", "99999999999999999999", "99999999999999999999Gi",
		"1Mi ", " 1", "١٢",
	} {
		if got, err := ParseReportSize(in); err == nil {
			t.Errorf("ParseReportSize(%q) = %d, want an error", in, got)
		}
	}
}

func TestParseReportCount(t *testing.T) {
	for in, want := range map[string]int{"0": 0, "1": 1, "100": 100, "100000": 100000, "007": 7} {
		if got, err := ParseReportCount(in); err != nil || got != want {
			t.Errorf("ParseReportCount(%q) = %d, %v; want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "-1", "+1", "1.5", "100001", "99999999999999999999", "10Mi", "abc", " 5"} {
		if got, err := ParseReportCount(in); err == nil {
			t.Errorf("ParseReportCount(%q) = %d, want an error", in, got)
		}
	}
}

func TestFormatReportLimits(t *testing.T) {
	for n, want := range map[int64]string{
		0: "no cap", -1: "no cap", 1: "1 byte", 1000: "1000 bytes", 1024: "1 KiB", 1536: "1536 bytes",
		10 << 20: "10 MiB", 3 << 30: "3 GiB", 1<<20 + 1: "1048577 bytes", 2 << 10: "2 KiB",
	} {
		if got := FormatReportSize(n); got != want {
			t.Errorf("FormatReportSize(%d) = %q, want %q", n, got, want)
		}
	}
	for n, want := range map[int]string{0: "no cap", 1: "1 report", 2: "2 reports", 100: "100 reports"} {
		if got := FormatReportCount(n); got != want {
			t.Errorf("FormatReportCount(%d) = %q, want %q", n, got, want)
		}
	}
}
