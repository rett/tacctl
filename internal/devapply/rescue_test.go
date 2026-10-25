package devapply

import (
	"errors"
	"testing"
)

// The rescue line 'show system commit' ends with when a rescue
// configuration is saved is a marker: no entry, never entry 0.
func TestParseHistoryRescueLine(t *testing.T) {
	const e0 = "0   2026-10-13 14:00:00 UTC by alice via cli commit confirmed, rollback in 10mins\n    tacctl apply x by alice\n"
	const e1 = "1   2026-10-12 01:00:00 UTC by root via other\n"
	const rescue = "rescue 2024-01-04 11:42:38 UTC by root via cli\n"

	h, err := parseHistory(e0 + e1 + rescue)
	if err != nil || len(h) != 2 || h[0].Seq != 0 || h[0].RollbackIn != 10 || h[1].Comment != "" {
		t.Errorf("at the end: %+v %v", h, err)
	}
	h, err = parseHistory("0   2026-10-13 14:00:00 UTC by alice via cli\n\nrescue   2024-01-04 11:42:38 UTC by root via cli\n")
	if err != nil || len(h) != 1 || h[0].User != "alice" || h[0].RollbackIn != 0 {
		t.Errorf("after one entry: %+v %v", h, err)
	}
	// the comment below the rescue line is the marker's
	h, err = parseHistory(e0 + e1 + rescue + "    saved by hand\n")
	if err != nil || len(h) != 2 || h[1].Comment != "" || h[0].Comment != "tacctl apply x by alice" {
		t.Errorf("comment: %+v %v", h, err)
	}

	for name, in := range map[string]string{
		"only":     rescue,
		"middle":   e0 + rescue + e1,
		"twice":    e0 + rescue + rescue,
		"no-via":   e0 + "rescue 2024-01-04 11:42:38 UTC by root\n",
		"no-time":  e0 + "rescue by root via cli\n",
		"no-by":    e0 + "rescue 2024-01-04 11:42:38 UTC root via cli\n",
		"misspelt": e0 + "rescued 2024-01-04 11:42:38 UTC by root via cli\n",
		"no-space": e0 + "rescue2024-01-04 11:42:38 UTC by root via cli\n",
		"stray":    e0 + rescue + "whatever\n",
	} {
		if _, err := parseHistory(in); !errors.Is(err, ErrUnrecognised) {
			t.Errorf("%s: %v", name, err)
		}
	}
}
