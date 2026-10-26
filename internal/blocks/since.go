package blocks

import (
	"fmt"
	"strings"
)

// Since0219 is a system block that holds statements 0.2.19 added to the
// grammar: the closed rule tables (syslog, the login and password policy,
// the ssh settings, summer time), the login announcement, the 'absent'
// lines, the IOS motd and exec banners and the delete or no lines that
// leave one of them out. A release before 0.2.19 lints such a block as an
// error, and its plan and walkthrough of the devices the block reaches fail
// until the lines are taken out.
type Since0219 struct {
	Level  Level
	Vendor string
	// Count is the number of such statements.
	Count int
}

// String names the block and the number of statements; no text of the block
// is in it.
func (u Since0219) String() string {
	n := "statements"
	if u.Count == 1 {
		n = "statement"
	}
	return fmt.Sprintf("%s, %s system block: %d %s", u.Level, u.Vendor, u.Count, n)
}

// FindSince0219 lists the system blocks of the store that hold statements
// 0.2.19 added, scopes first and then devices, each in the order of the
// store. A block that cannot be read is skipped: the rollback is not
// the place to report it ('tacctl config validate' is).
func (s *Store) FindSince0219() []Since0219 {
	var levels []Level
	if scopes, err := s.Scopes(); err == nil {
		for _, sc := range scopes {
			levels = append(levels, ScopeLevel(sc))
		}
	}
	if devs, err := s.Devices(); err == nil {
		for _, d := range devs {
			levels = append(levels, DeviceLevel(d))
		}
	}
	var out []Since0219
	for _, l := range levels {
		for _, v := range Vendors {
			data, err := s.Read(l, v, BlockSystem)
			if err != nil {
				continue
			}
			if n := since0219Count(v, string(data)); n > 0 {
				out = append(out, Since0219{Level: l, Vendor: v, Count: n})
			}
		}
	}
	return out
}

func since0219Count(vendor, text string) int {
	ruleLines := func(nm []SystemNotManaged) int {
		n := 0
		for _, d := range nm {
			if strings.HasPrefix(d.Kind, "rule:") {
				n++
			}
		}
		return n
	}
	one := func(m *LoginMessage) int {
		if m == nil {
			return 0
		}
		return 1
	}
	if vendor == VendorCisco {
		b, _ := ParseIOSSystem(text)
		if b == nil {
			return 0
		}
		return len(b.Rules) + ruleLines(b.NotManaged) + one(b.BannerMOTD) + one(b.BannerExec)
	}
	b, _ := ParseSystem(text)
	if b == nil {
		return 0
	}
	return len(b.Rules) + ruleLines(b.NotManaged) + one(b.Announcement)
}
