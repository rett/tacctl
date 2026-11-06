package reports

import (
	"errors"
	"fmt"
	"strconv"
	"time"
)

// The default limits (D326). The settings reports.max-size and
// reports.max-count hold the values in use; 0 means no cap.
const (
	DefaultMaxSize  int64 = 10 << 20
	DefaultMaxCount       = 100
)

// MaxNameLen is the longest report name in bytes, without the extension.
const MaxNameLen = 64

// ValidName says whether s can be the name of a report: 1 to 64 bytes of
// letters, digits, dot, underscore and hyphen, no leading dot.
func ValidName(s string) error {
	switch {
	case s == "":
		return errors.New("a report name is empty")
	case len(s) > MaxNameLen:
		return fmt.Errorf("a report name is at most %d bytes (this one has %d)", MaxNameLen, len(s))
	case s[0] == '.':
		return errors.New("a report name does not start with a dot")
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		ok := c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
			c == '.' || c == '_' || c == '-'
		if !ok {
			return fmt.Errorf("a report name holds only letters, digits, '.', '_' and '-' (%q does not)", s)
		}
	}
	return nil
}

// DefaultName is the name of a new report of a type: <type>-<yyyymmdd> with
// the date in UTC, then <type>-<yyyymmdd>-2, -3 and so on. taken receives each
// candidate as a name without the extension and says whether a report of that
// name exists in any format (the caller checks the files and their .meta); the
// first candidate it does not take is returned. A nil taken takes nothing.
func DefaultName(typ string, now time.Time, taken func(string) bool) string {
	base := typ + "-" + now.UTC().Format("20060102")
	if taken == nil || !taken(base) {
		return base
	}
	for n := 2; ; n++ {
		name := base + "-" + strconv.Itoa(n)
		if !taken(name) {
			return name
		}
	}
}

// FileName is the name of the report file: the name plus the extension of the
// format (.txt, .csv or .json).
func FileName(name, format string) (string, error) {
	if err := ValidName(name); err != nil {
		return "", err
	}
	ext := Ext(format)
	if ext == "" {
		return "", errFormat(format)
	}
	return name + ext, nil
}

// LimitError is a limit a report went over. Limit is "size" or "count"; the
// caller adds the name of the setting.
type LimitError struct {
	Limit string
	Value int64
	Max   int64
}

func (e *LimitError) Error() string {
	if e.Limit == "size" {
		return fmt.Sprintf("the report is %d bytes, over the size limit of %d bytes", e.Value, e.Max)
	}
	return fmt.Sprintf("that would be %d reports, over the count limit of %d reports", e.Value, e.Max)
}

// CheckLimits checks a report against the caps. size is the size of the new
// report in bytes; count is the number of reports the user would have with it
// (those already stored plus this one). A cap of 0 or less is no cap. The size
// is checked first; the error is a *LimitError.
func CheckLimits(size int64, count int, maxSize int64, maxCount int) error {
	if maxSize > 0 && size > maxSize {
		return &LimitError{Limit: "size", Value: size, Max: maxSize}
	}
	if maxCount > 0 && count > maxCount {
		return &LimitError{Limit: "count", Value: int64(count), Max: int64(maxCount)}
	}
	return nil
}
