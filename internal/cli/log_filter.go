package cli

// The filters of 'log tail|search|failures|accounting': --since, --until,
// --user, --device, --type (accounting) and --json. The command parses them
// here; the backends apply them to their logs (internal/backend/logfilter.go;
// what each backend can match is in docs/cli/maintenance.md).

import (
	"net/netip"
	"slices"
	"strings"

	"github.com/rett/tacctl/internal/backend"
)

// kindLogTypes is the fixed list of the values of --type, for completion.
const kindLogTypes = "login|change|command"

// logFilterFlags are the filters of a verb of the family; --type is the
// accounting log's only.
func logFilterFlags(accounting bool) []Flag {
	fl := []Flag{
		{Names: []string{"--since"}, Value: true, Arg: "<time>", Desc: "Show entries from that time on",
			Long: "Show the entries from that time on (inclusive): " + backend.LogTimeForms + ". A date alone is that day's midnight"},
		{Names: []string{"--until"}, Value: true, Arg: "<time>", Desc: "Show entries up to that time",
			Long: "Show the entries up to that time (inclusive), in the forms of --since"},
		{Names: []string{"--user"}, Value: true, Kind: KindUsers, Arg: "<name>", Desc: "Show the entries of that user",
			Long: "Show the entries of that user, as the log writes the name"},
		{Names: []string{"--device"}, Value: true, Kind: KindDevices, Arg: "<name|address>", Desc: "Show the entries of that device or host",
			Long: "Show the entries of that device or host: a registered device or an enrolled host by name (those the caller may see) or an address. What each log can match is described under Log inspection"},
	}
	if accounting {
		fl = append(fl, Flag{Names: []string{"--type"}, Value: true, Kind: kindLogTypes, Arg: "login|change|command", Desc: "Show one kind of accounting record",
			Long: "Show one kind of record: command, change (a Junos change-log entry) or login (the start or stop of a session). How a record is classified is described under Log inspection"})
	}
	return append(fl, Flag{Names: []string{"--json"}, Desc: "Write one JSON object per entry",
		Long: "Write one JSON object per line, with no headings, for jq"})
}

// logFilterUsage is the usage line of the filter errors, as every other usage
// error of the command has one: the verb and the options the error is about,
// with the values as the help lists them.
func logFilterUsage(sub string, names ...string) string {
	var b strings.Builder
	b.WriteString("Usage: tacctl log " + sub)
	for _, n := range names {
		for _, f := range logFilterFlags(true) {
			if f.Names[0] == n {
				b.WriteString(" [" + n + " " + f.Arg + "]")
			}
		}
	}
	b.WriteString(" ...")
	return b.String()
}

// logFilterArgs are the filters as typed.
type logFilterArgs struct {
	since, until, user, device, typ string
	json                            bool
	sub                             string // the verb, for the usage line of an error
}

// take reads the filter flag at args[*i], if it is one: --name value or
// --name=value. handled is false for any other word.
func (a *logFilterArgs) take(inv *invocation, sub string, args []string, i *int) (handled bool, err error) {
	w := args[*i]
	a.sub = sub
	if w == "--json" {
		a.json = true
		return true, nil
	}
	name, val, hasVal := strings.Cut(w, "=")
	var dst *string
	var what string
	switch name {
	case "--since":
		dst, what = &a.since, "a time"
	case "--until":
		dst, what = &a.until, "a time"
	case "--user":
		dst, what = &a.user, "a user name"
	case "--device":
		dst, what = &a.device, "a device name or an address"
	case "--type":
		dst, what = &a.typ, "login, change or command"
	default:
		return false, nil
	}
	if name == "--type" && sub != "accounting" {
		return true, inv.usageErr("--type applies to 'log accounting' only.", logFilterUsage("accounting", "--type"))
	}
	if !hasVal {
		val = arg(args, *i+1)
		// The next word is another option, not this one's value ('--user
		// --json'): a value of its own is needed. A single dash is a value
		// ('--since -1h').
		if strings.HasPrefix(val, "--") {
			val = ""
		} else {
			*i++
		}
	}
	if val == "" {
		return true, inv.usageErr(name+" needs "+what+".", logFilterUsage(sub, name))
	}
	*dst = val
	return true, nil
}

// build is the backend filter the arguments make: the times resolved, the
// type checked, the device found in what the caller may see.
func (a *logFilterArgs) build(inv *invocation) (backend.LogFilter, error) {
	f := backend.LogFilter{User: a.user, Type: a.typ, JSON: a.json}
	now := inv.app.Knobs.Now()
	var err error
	if a.since != "" {
		if f.Since, err = backend.ParseLogTime(a.since, now); err != nil {
			return f, inv.usageErr("--since: "+err.Error()+".", logFilterUsage(a.sub, "--since"))
		}
	}
	if a.until != "" {
		if f.Until, err = backend.ParseLogTime(a.until, now); err != nil {
			return f, inv.usageErr("--until: "+err.Error()+".", logFilterUsage(a.sub, "--until"))
		}
	}
	if !f.Since.IsZero() && !f.Until.IsZero() && f.Since.After(f.Until) {
		return f, inv.usageErr("--since ("+f.Since.Format(backend.LogTimeLayout)+") is later than --until ("+f.Until.Format(backend.LogTimeLayout)+").", logFilterUsage(a.sub, "--since", "--until"))
	}
	if a.typ != "" && !slices.Contains(backend.LogTypes, a.typ) {
		return f, inv.usageErr("Unknown --type '"+a.typ+"' (use "+strings.Join(backend.LogTypes, ", ")+").", logFilterUsage(a.sub, "--type"))
	}
	if a.device != "" {
		f.Device = a.device
		if f.Addrs, err = inv.logDeviceAddrs(a.sub, a.device); err != nil {
			return f, err
		}
	}
	return f, nil
}

// logDeviceAddrs are the canonical addresses --device stands for: the address
// itself, or the address of the registered device or enrolled host of that
// name that the caller may see.
func (inv *invocation) logDeviceAddrs(sub, v string) ([]string, error) {
	if a := backend.CanonAddr(v); a != "" {
		return []string{a}, nil
	}
	if _, err := netip.ParseAddr(v); err == nil {
		return nil, inv.usageErr("--device: '"+v+"' is not an address of a device.", logFilterUsage(sub, "--device"))
	}
	e, ok := inv.logResolver().Lookup(v, inv.deviceFilter())
	if !ok {
		return nil, inv.usageErr("Unknown device or host '" + v + "' (a registered device, an enrolled host or an address).")
	}
	a := backend.CanonAddr(e.Address)
	if a == "" {
		return nil, inv.usageErr("'" + e.Name + "' has no address recorded, so its log entries cannot be told apart; give its address with --device.")
	}
	return []string{a}, nil
}
