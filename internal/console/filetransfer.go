package console

// The console's file transfer settings (settings.file_transfer in
// console.yaml): who may transfer files to and from their home through the
// console, how much the home may hold (the quota) and how fast a transfer
// may go (the rate). The model is the system shell's, with three
// differences: it is off for every tier but the superuser tier by default,
// the engineer tier is not closed to it (a transfer is limited to the
// user's home, where a shell or a forwarded port would reach the server),
// and a tier or a user may also have a quota and a rate.

import (
	"slices"
	"strconv"
	"strings"

	"github.com/rett/tacctl/internal/tier"
	"github.com/rett/tacctl/internal/yamlpy"
)

// The limits of the file transfer settings.
const (
	// DefaultQuota is the quota, in bytes, of a tier with no setting of
	// its own, for every tier but the superuser tier, which has none.
	DefaultQuota int64 = 256 << 20
	// MaxFileTransferSize is the largest quota or rate a setting can name:
	// 1 TiB.
	MaxFileTransferSize int64 = 1 << 40

	// Unlimited and RateOff are the words of 'no quota' and 'no rate limit'
	// on the command line and in the file.
	Unlimited = "unlimited"
	RateOff   = "off"
)

// FileTransfer is what the settings give a user at a tier: whether the
// console may transfer files for them, the quota of their home in bytes
// (0: unlimited) and the rate in bytes per second (0: no limit).
type FileTransfer struct {
	Enabled     bool
	Quota, Rate int64
}

// fileTransferUserTiers are the tiers a user's enable can be set for (the
// superuser tier needs none).
var fileTransferUserTiers = []tier.Tier{tier.Readonly, tier.Operator, tier.Engineer}

// ParseSize reads a size in bytes: plain bytes, or a number with the unit
// K, M, G or T (powers of 1024, in either case). Zero, a negative number, a
// fraction, an overflow and more than 1 TiB (MaxFileTransferSize) are
// refused. The words unlimited and off are the callers' business.
func ParseSize(s string) (int64, error) {
	bad := fail("Invalid size '" + s + "': expected a number of bytes or a number with K, M, G or T (such as 512K, 256M or 2G), at most 1T.")
	if s == "" {
		return 0, bad
	}
	mult := int64(1)
	digits := s
	switch s[len(s)-1] {
	case 'k', 'K':
		mult = 1 << 10
	case 'm', 'M':
		mult = 1 << 20
	case 'g', 'G':
		mult = 1 << 30
	case 't', 'T':
		mult = 1 << 40
	}
	if mult != 1 {
		digits = s[:len(s)-1]
	}
	if digits == "" {
		// a unit with no number: 'K'
		return 0, bad
	}
	for _, c := range digits {
		if c < '0' || c > '9' {
			return 0, bad
		}
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil {
		// only overflow gets here: the characters are digits
		return 0, fail("Size '" + s + "' is too large: at most 1T.")
	}
	if n == 0 {
		return 0, fail("Size '" + s + "' is zero: give a size above zero, or unlimited for no limit.")
	}
	if n > MaxFileTransferSize/mult {
		return 0, fail("Size '" + s + "' is too large: at most 1T.")
	}
	return n * mult, nil
}

// FormatSize is a size in the largest unit that holds it exactly (1G, 512K,
// 1000 for bytes that fit none).
func FormatSize(n int64) string {
	for _, u := range []struct {
		div  int64
		name string
	}{{1 << 40, "T"}, {1 << 30, "G"}, {1 << 20, "M"}, {1 << 10, "K"}} {
		if n >= u.div && n%u.div == 0 {
			return strconv.FormatInt(n/u.div, 10) + u.name
		}
	}
	return strconv.FormatInt(n, 10)
}

// QuotaWord is a quota as the file and the listings write it.
func QuotaWord(n int64) string {
	if n == 0 {
		return Unlimited
	}
	return FormatSize(n)
}

// RateWord is a rate as the file and the listings write it.
func RateWord(n int64) string {
	if n == 0 {
		return RateOff
	}
	return FormatSize(n)
}

// ParseQuota reads a quota word: a size, or unlimited (0).
func ParseQuota(s string) (int64, error) {
	if s == Unlimited {
		return 0, nil
	}
	return ParseSize(s)
}

// ParseRate reads a rate word: a size in bytes per second, or off (0).
func ParseRate(s string) (int64, error) {
	if s == RateOff {
		return 0, nil
	}
	return ParseSize(s)
}

// FileTransferUserNames are the users with a file transfer switch of their
// own, by name.
func (f *File) FileTransferUserNames() []string { return sortedKeys(f.FileTransferUsers) }

// FileTransferQuotaUserNames are the users with a quota of their own.
func (f *File) FileTransferQuotaUserNames() []string { return sortedKeys(f.FileTransferQuotaUsers) }

// FileTransferRateUserNames are the users with a rate of their own.
func (f *File) FileTransferRateUserNames() []string { return sortedKeys(f.FileTransferRateUsers) }

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// SetFileTransfer switches file transfer on or off for tier t. The
// superuser tier always has it. The list that is written is the tiers that
// have it, lowest first, the superuser tier included.
func (f *File) SetFileTransfer(t tier.Tier, on bool) error {
	if t == tier.Superuser && !on {
		return fail("The superuser tier always has file transfer; it cannot be disabled. Nothing was changed.")
	}
	var out []tier.Tier
	for _, x := range Tiers {
		has := x == tier.Superuser || slices.Contains(f.FileTransferTiers, x)
		if x == t {
			has = on
		}
		if has {
			out = append(out, x)
		}
	}
	f.FileTransferTiers = out
	return nil
}

// SetFileTransferUser gives the user a file transfer switch of their own: an
// enable is recorded with the tier it is set for (readonly, operator or
// engineer; the superuser tier needs none), a disable with none.
func (f *File) SetFileTransferUser(name string, on bool, t tier.Tier) {
	f.FileTransferUsers[name] = on
	if on {
		f.FileTransferUserTiers[name] = t
	} else {
		delete(f.FileTransferUserTiers, name)
	}
}

// DropFileTransferUser removes the user's file transfer switch.
func (f *File) DropFileTransferUser(name string) {
	delete(f.FileTransferUsers, name)
	delete(f.FileTransferUserTiers, name)
}

// SetFileTransferQuota sets the quota of tier t in bytes (0: unlimited), or
// returns it to the built-in default (def).
func (f *File) SetFileTransferQuota(t tier.Tier, n int64, def bool) {
	if def {
		delete(f.FileTransferQuota, t)
		return
	}
	f.FileTransferQuota[t] = n
}

// SetFileTransferRate sets the rate of tier t in bytes per second, 0: off
// (the default, so nothing is stored).
func (f *File) SetFileTransferRate(t tier.Tier, n int64) {
	if n == 0 {
		delete(f.FileTransferRate, t)
		return
	}
	f.FileTransferRate[t] = n
}

// fileTransferDefault reports whether the file has no file transfer setting
// but the built-in ones: nothing is written for it.
func (f *File) fileTransferDefault() bool {
	return len(f.FileTransferUsers) == 0 && len(f.FileTransferQuota) == 0 && len(f.FileTransferQuotaUsers) == 0 &&
		len(f.FileTransferRate) == 0 && len(f.FileTransferRateUsers) == 0 &&
		slices.Equal(f.FileTransferTiers, []tier.Tier{tier.Superuser})
}

// DefaultTierQuota is the built-in quota of tier t in bytes: none for the
// superuser tier, 256 MiB for the others.
func DefaultTierQuota(t tier.Tier) int64 {
	if t == tier.Superuser {
		return 0
	}
	return DefaultQuota
}

// checkFileTransfer is the invariants of the file transfer settings.
func (f *File) checkFileTransfer(userName func(string) bool) error {
	seen := map[tier.Tier]bool{}
	for _, t := range f.FileTransferTiers {
		if _, ok := ParseTier(string(t)); !ok || seen[t] {
			return fail("settings.file_transfer.tiers: invalid or repeated tier '" + string(t) + "'.")
		}
		seen[t] = true
	}
	for u, on := range f.FileTransferUsers {
		if !userName(u) {
			return fail("settings.file_transfer.users: invalid user name '" + u + "'.")
		}
		if t := f.FileTransferUserTiers[u]; on && !slices.Contains(fileTransferUserTiers, t) {
			return fail("settings.file_transfer.users: '" + u + "' must be disable or enable:readonly|operator|engineer.")
		}
	}
	for key, m := range map[string]map[tier.Tier]int64{"quota": f.FileTransferQuota, "rate": f.FileTransferRate} {
		for t, n := range m {
			if _, ok := ParseTier(string(t)); !ok {
				return fail("settings.file_transfer." + key + ": invalid tier '" + string(t) + "'.")
			}
			if n < 0 || n > MaxFileTransferSize || (key == "rate" && n == 0) {
				return fail("settings.file_transfer." + key + ": invalid size for '" + string(t) + "'.")
			}
		}
	}
	for key, m := range map[string]map[string]int64{"quota_users": f.FileTransferQuotaUsers, "rate_users": f.FileTransferRateUsers} {
		for u, n := range m {
			if !userName(u) {
				return fail("settings.file_transfer." + key + ": invalid user name '" + u + "'.")
			}
			if n < 0 || n > MaxFileTransferSize {
				return fail("settings.file_transfer." + key + ": invalid size for '" + u + "'.")
			}
		}
	}
	return nil
}

// parseFileTransfer reads settings.file_transfer.
func parseFileTransfer(f *File, m *yamlpy.Map) error {
	for k, v := range m.All() {
		bad := fail("settings.file_transfer: invalid value for '" + k + "'.")
		switch k {
		case "tiers":
			var l []tier.Tier
			switch x := v.(type) {
			case nil:
			case []any:
				for _, e := range x {
					s, ok := e.(string)
					if !ok {
						return bad
					}
					l = append(l, tier.Tier(s))
				}
			default:
				return bad
			}
			f.FileTransferTiers = l
		case "users":
			switch x := v.(type) {
			case nil:
			case *yamlpy.Map:
				for name, uv := range x.All() {
					s, ok := uv.(string)
					word, tr, hasTier := strings.Cut(s, ":")
					switch {
					case !ok, word != "disable" && word != "enable", word == "disable" && hasTier, word == "enable" && !hasTier:
						return fail("settings.file_transfer.users: '" + name + "' must be disable or enable:readonly|operator|engineer.")
					}
					f.FileTransferUsers[name] = word == "enable"
					if word == "enable" {
						f.FileTransferUserTiers[name] = tier.Tier(tr)
					}
				}
			default:
				return fail("settings.file_transfer.users must be a mapping of user to disable or enable:<tier>.")
			}
		case "quota", "rate":
			x, ok := v.(*yamlpy.Map)
			if v == nil {
				continue
			}
			if !ok {
				return fail("settings.file_transfer." + k + " must be a mapping of tier to a size.")
			}
			for name, sv := range x.All() {
				n, err := sizeValue(sv, k == "quota")
				if err != nil {
					return fail("settings.file_transfer." + k + ": '" + name + "' must be a size" + map[bool]string{true: " or unlimited", false: " or off"}[k == "quota"] + ".")
				}
				switch {
				case k == "quota":
					f.FileTransferQuota[tier.Tier(name)] = n
				case n != 0:
					f.FileTransferRate[tier.Tier(name)] = n
				}
				// a tier's rate of off is the built-in setting: nothing is stored
			}
		case "quota_users", "rate_users":
			x, ok := v.(*yamlpy.Map)
			if v == nil {
				continue
			}
			if !ok {
				return fail("settings.file_transfer." + k + " must be a mapping of user to a size.")
			}
			for name, sv := range x.All() {
				n, err := sizeValue(sv, k == "quota_users")
				if err != nil {
					return fail("settings.file_transfer." + k + ": '" + name + "' must be a size or " + map[bool]string{true: Unlimited, false: RateOff}[k == "quota_users"] + ".")
				}
				if k == "quota_users" {
					f.FileTransferQuotaUsers[name] = n
				} else {
					f.FileTransferRateUsers[name] = n
				}
			}
		default:
			return fail("settings.file_transfer: unknown key '" + k + "'.")
		}
	}
	return nil
}

// sizeValue reads a size from the file: a number of bytes, a size word, or
// unlimited (quota) / off (rate). An unquoted off is a boolean to YAML 1.1:
// false is read as off too.
func sizeValue(v any, quota bool) (int64, error) {
	switch x := v.(type) {
	case int:
		if x <= 0 {
			return 0, fail("size")
		}
		if int64(x) > MaxFileTransferSize {
			return 0, fail("size")
		}
		return int64(x), nil
	case bool:
		if !x && !quota {
			return 0, nil
		}
	case string:
		if quota {
			return ParseQuota(x)
		}
		return ParseRate(x)
	}
	return 0, fail("size")
}

// fileTransferDoc is settings.file_transfer, written only when something is
// not the built-in setting, so a file that never touched it is read by every
// release.
func (f *File) fileTransferDoc() *yamlpy.Map {
	words := func(l []tier.Tier) []string {
		out := make([]string, 0, len(l))
		for _, t := range l {
			out = append(out, string(t))
		}
		return out
	}
	m := yamlpy.NewMap("tiers", words(f.FileTransferTiers))
	if len(f.FileTransferUsers) > 0 {
		users := yamlpy.NewMap()
		for _, u := range f.FileTransferUserNames() {
			if f.FileTransferUsers[u] {
				users.Set(u, "enable:"+string(f.FileTransferUserTiers[u]))
			} else {
				users.Set(u, "disable")
			}
		}
		m.Set("users", users)
	}
	tierMap := func(key string, vals map[tier.Tier]int64, word func(int64) string) {
		if len(vals) == 0 {
			return
		}
		out := yamlpy.NewMap()
		for _, t := range Tiers {
			if n, ok := vals[t]; ok {
				out.Set(string(t), word(n))
			}
		}
		m.Set(key, out)
	}
	userMap := func(key string, vals map[string]int64, word func(int64) string) {
		if len(vals) == 0 {
			return
		}
		out := yamlpy.NewMap()
		for _, u := range sortedKeys(vals) {
			out.Set(u, word(vals[u]))
		}
		m.Set(key, out)
	}
	tierMap("quota", f.FileTransferQuota, QuotaWord)
	userMap("quota_users", f.FileTransferQuotaUsers, QuotaWord)
	tierMap("rate", f.FileTransferRate, RateWord)
	userMap("rate_users", f.FileTransferRateUsers, RateWord)
	return m
}
