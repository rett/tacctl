package hosts

import (
	"strconv"
	"strings"
)

// The registry and the UID file are read with awk in 0.1.16 ('$1 == u',
// '$2 > m', 'print m + 1'). awk compares two values as numbers when both
// look like numbers (a field or a -v value that is a decimal number, blanks
// around it allowed) and as strings otherwise; these helpers reproduce that
// for the few comparisons the bash makes, so a hand-edited file reads the
// same.

// awkNumber is the value of s when it looks like a number to awk.
func awkNumber(s string) (float64, bool) {
	t := strings.Trim(s, " \t\n")
	if t == "" {
		return 0, false
	}
	// strconv accepts forms awk does not (hex, inf, nan, underscores).
	for _, r := range t {
		if !strings.ContainsRune("0123456789+-.eE", r) {
			return 0, false
		}
	}
	f, err := strconv.ParseFloat(t, 64)
	if err != nil {
		return 0, false
	}
	return f, true
}

// awkEqual is awk's 'a == b' for two field or -v values.
func awkEqual(a, b string) bool {
	x, okA := awkNumber(a)
	y, okB := awkNumber(b)
	if okA && okB {
		return x == y
	}
	return a == b
}

// awkFields is 'awk -F<sep>' field splitting of one record: $1, $2, ...
func awkFields(record, sep string) []string { return strings.Split(record, sep) }

// awkField is $n (1-based), "" past the last field.
func awkField(fields []string, n int) string {
	if n-1 < len(fields) {
		return fields[n-1]
	}
	return ""
}

// awkRecords are the records of a file's text: lines, the last one counted
// even without a newline.
func awkRecords(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// awkPrefixNumber is awk's numeric value of a string that does not look
// like a number: its longest leading number (strtod), else 0.
func awkPrefixNumber(s string) float64 {
	t := strings.TrimLeft(s, " \t\n")
	best := 0.0
	for i := len(t); i > 0; i-- {
		if f, err := strconv.ParseFloat(t[:i], 64); err == nil && !strings.ContainsAny(t[:i], "xXnNiI_") {
			best = f
			break
		}
	}
	return best
}

// awkString is a number as awk prints it: an integral value as an integer,
// anything else with %.6g.
func awkString(f float64) string {
	if f == float64(int64(f)) {
		return strconv.FormatInt(int64(f), 10)
	}
	return strconv.FormatFloat(f, 'g', 6, 64)
}
