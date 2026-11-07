package names

import (
	"fmt"
	"strconv"
	"strings"
)

// The limits of the stored reports (docs/plans/0.2.26-plan.md D326): the
// global settings reports.max_size and reports.max_count and the per-user
// override fields of the store. 0 is no cap; the upper bounds keep a typing
// mistake from being taken for a limit.
const (
	// ReportMaxSizeCap is the largest size limit, in bytes (1 GiB).
	ReportMaxSizeCap int64 = 1 << 30
	// ReportMaxCountCap is the largest count limit.
	ReportMaxCountCap = 100000
)

// ClearWord is the word of 'user reports-limit <user> [max-size|max-count]
// clear'. It is no number, so it is never a value.
const ClearWord = "clear"

// ParseReportSize reads a size limit: a number of bytes, or a number with the
// suffix Ki, Mi or Gi (powers of 1024), from 0 (no cap) to ReportMaxSizeCap.
func ParseReportSize(s string) (int64, error) {
	digits, mult := s, int64(1)
	for _, suf := range []struct {
		word string
		mult int64
	}{{"Ki", 1 << 10}, {"Mi", 1 << 20}, {"Gi", 1 << 30}} {
		if d, ok := strings.CutSuffix(s, suf.word); ok {
			digits, mult = d, suf.mult
			break
		}
	}
	bad := fmt.Errorf("%q is not a size: write a number of bytes, or a number with Ki, Mi or Gi (such as 20Mi), from 0 (no cap) to 1Gi", s)
	if digits == "" || strings.Trim(digits, "0123456789") != "" {
		return 0, bad
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		return 0, bad
	}
	if n > ReportMaxSizeCap/mult {
		return 0, fmt.Errorf("%q is over the largest size limit, 1Gi (%d bytes); 0 is no cap", s, ReportMaxSizeCap)
	}
	return n * mult, nil
}

// ParseReportCount reads a count limit: a whole number from 0 (no cap) to
// ReportMaxCountCap.
func ParseReportCount(s string) (int, error) {
	if s == "" || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("%q is not a count: write a whole number of reports, from 0 (no cap) to %d", s, ReportMaxCountCap)
	}
	n, err := strconv.Atoi(s)
	if err != nil || n > ReportMaxCountCap {
		return 0, fmt.Errorf("%q is over the largest count limit, %d; 0 is no cap", s, ReportMaxCountCap)
	}
	return n, nil
}

// FormatReportSize says a size limit in a few words: "no cap" for 0, the
// binary unit when the size is an exact multiple (10 MiB), else the bytes.
func FormatReportSize(n int64) string {
	switch {
	case n <= 0:
		return "no cap"
	case n%(1<<30) == 0:
		return strconv.FormatInt(n>>30, 10) + " GiB"
	case n%(1<<20) == 0:
		return strconv.FormatInt(n>>20, 10) + " MiB"
	case n%(1<<10) == 0:
		return strconv.FormatInt(n>>10, 10) + " KiB"
	case n == 1:
		return "1 byte"
	}
	return strconv.FormatInt(n, 10) + " bytes"
}

// FormatReportCount says a count limit: "no cap" for 0.
func FormatReportCount(n int) string {
	if n <= 0 {
		return "no cap"
	}
	return strconv.Itoa(n) + " " + map[bool]string{true: "report", false: "reports"}[n == 1]
}
