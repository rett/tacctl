package cli

// 'device check --sources' and 'device scan --sources' (0.2.23, D315): an
// opt-in test of the addresses the AAA clients of a device send from. A source
// address of a device's TACACS+ or RADIUS client that is not its registered
// address is connected to, the SSH host key is read without logging in (the
// host-key scan of 'device hostkey': ssh-keyscan, then tacctl's own client,
// with the timing scale of the device) and compared with the key pinned for
// the device. An address that does not answer, or that presents another key,
// is a warning: it may belong to another device, or be out of this server's
// reach by design. Nothing else follows from it: the device keeps its state,
// no difference is counted, and nothing is pinned, recorded or stored. A pull,
// a plan, a diff and a list never run it. The addresses come from the stored
// pull (devconf.AAASourceAddresses).

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/rett/tacctl/internal/devconf"
	"github.com/rett/tacctl/internal/devreg"
	"github.com/rett/tacctl/internal/devssh"
	"github.com/rett/tacctl/internal/shellquote"
)

// sourcesMax is how many source addresses of one device are tested; the rest
// is said to be left out.
const sourcesMax = 8

// The results of a source.
const (
	sourceOK          = "ok"
	sourceUnreachable = "unreachable"
	sourceMismatch    = "mismatch"
	sourceSkipped     = "skipped"
)

// sourceResult is one source of the AAA client: the address tested, or the
// source that was left out (Address empty for a source-interface with no
// address to test).
type sourceResult struct {
	Address   string `json:"address,omitempty"`
	Source    string `json:"source,omitempty"`
	Interface string `json:"interface,omitempty"`
	Result    string `json:"result"`
	// Fingerprint is the key the address presented (a mismatch) and Pinned
	// the device's own.
	Fingerprint string `json:"fingerprint,omitempty"`
	Pinned      string `json:"pinned,omitempty"`
	// Device is the registered device that holds the address of a mismatch
	// as its own.
	Device string `json:"device,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// sourceReport is what the test of one device found.
type sourceReport struct {
	Device  string
	Results []sourceResult
	// Note says why a device has nothing to test (never pulled, no source
	// stated, no pinned key); the other fields are then empty.
	Note string
	// Registered: the device's registered address is one of its sources (it
	// is not tested; the host-key scan reads it).
	Registered bool
	// Over is how many addresses beyond sourcesMax were left out.
	Over int
}

// count is the number of results with the result r.
func (r sourceReport) count(res string) int {
	n := 0
	for _, x := range r.Results {
		if x.Result == res {
			n++
		}
	}
	return n
}

// tested is the number of addresses connected to.
func (r sourceReport) tested() int {
	return r.count(sourceOK) + r.count(sourceUnreachable) + r.count(sourceMismatch)
}

// noteNoSource is the note of a device whose pull states no source address.
const noteNoSource = "the device states no source address of its AAA client"

// keyReader reads the SSH host keys at an address, as the scan of the
// device's own address does.
type keyReader func(addr string) ([]devreg.HostKey, error)

// canonSourceAddr is addr as the sources are compared: an IP address in its
// canonical form, else as it is.
func canonSourceAddr(addr string) string {
	if a, err := netip.ParseAddr(strings.TrimSpace(addr)); err == nil {
		return a.Unmap().String()
	}
	return addr
}

// sameKey reports whether a presented key is one of the pinned ones.
func sameKey(pinned []devreg.HostKey, k devreg.HostKey) bool {
	for _, p := range pinned {
		if p.Type == k.Type && p.Blob == k.Blob {
			return true
		}
	}
	return false
}

// mismatchPrints are the fingerprints a mismatch names: the presented key of a
// type the device has pinned (else the first presented) and the device's own
// key of that type (else its first).
func mismatchPrints(pinned, got []devreg.HostKey) (presented, own string) {
	k := got[0]
	for _, g := range got {
		if slicesHasType(pinned, g.Type) {
			k = g
			break
		}
	}
	p := pinned[0]
	for _, c := range pinned {
		if c.Type == k.Type {
			p = c
			break
		}
	}
	return k.Fingerprint(), p.Fingerprint()
}

// sharesType reports whether a presented key is of a type that is pinned.
func sharesType(pinned, got []devreg.HostKey) bool {
	for _, g := range got {
		if slicesHasType(pinned, g.Type) {
			return true
		}
	}
	return false
}

// typeNames are the key types of keys, in lower case, one each ("ed25519,
// rsa").
func typeNames(keys []devreg.HostKey) string {
	var out []string
	for _, k := range keys {
		n := strings.ToLower(k.Label())
		if !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return strings.Join(out, ", ")
}

func slicesHasType(keys []devreg.HostKey, typ string) bool {
	for _, k := range keys {
		if k.Type == typ {
			return true
		}
	}
	return false
}

// testSources tests the sources of one device: each address but the registered
// one is read with read and compared with the pinned keys, one after the
// other. ctx ends the test: what is left is skipped.
func testSources(ctx context.Context, device, registered string, pinned []string, srcs devconf.SourceAddresses, read keyReader) sourceReport {
	rep := sourceReport{Device: device}
	pk := devreg.ParseHostKeys(pinned)
	if srcs.Empty() {
		rep.Note = noteNoSource
		return rep
	}
	if len(pk) == 0 {
		rep.Note = "not compared: no host key is pinned for " + device
		return rep
	}
	for _, s := range srcs.Skipped {
		rep.Results = append(rep.Results, sourceResult{Source: s.Source, Result: sourceSkipped, Reason: s.Reason})
	}
	reg := canonSourceAddr(registered)
	var todo []devconf.SourceAddr
	for _, a := range srcs.Addrs {
		if a.Address == reg {
			rep.Registered = true
			continue
		}
		todo = append(todo, a)
	}
	for i, a := range todo {
		if i >= sourcesMax {
			rep.Over = len(todo) - sourcesMax
			for _, left := range todo[i:] {
				rep.Results = append(rep.Results, sourceResult{Address: left.Address, Interface: left.Via, Result: sourceSkipped,
					Reason: "more than " + strconv.Itoa(sourcesMax) + " source addresses: not tested"})
			}
			break
		}
		x := sourceResult{Address: a.Address, Interface: a.Via}
		if ctx.Err() != nil {
			x.Result, x.Reason = sourceSkipped, "interrupted"
			rep.Results = append(rep.Results, x)
			continue
		}
		got, err := read(a.Address)
		switch {
		case ctx.Err() != nil:
			x.Result, x.Reason = sourceSkipped, "interrupted"
		case err != nil || len(got) == 0:
			x.Result = sourceUnreachable
			if err != nil && !errors.Is(err, devreg.ErrNoAnswer) {
				x.Reason = firstLineOf(strings.Join(msgs(err), " "))
			}
		default:
			matched := false
			for _, k := range got {
				if sameKey(pk, k) {
					matched = true
					break
				}
			}
			switch {
			case matched:
				x.Result = sourceOK
			case !sharesType(pk, got):
				// the two sets have no key type in common: no key is wrong
				x.Result = sourceSkipped
				x.Reason = "not compared: presented only " + typeNames(got) + ", pinned " + typeNames(pk)
			default:
				x.Result = sourceMismatch
				x.Fingerprint, x.Pinned = mismatchPrints(pk, got)
			}
		}
		rep.Results = append(rep.Results, x)
	}
	return rep
}

// sourcesOf are the sources of a device from its stored pull: nothing for a
// device never pulled (the note says so).
func (inv *invocation) sourcesOf(e devreg.Entry, recs *devconf.Records, store devconf.Store) (devconf.SourceAddresses, string) {
	rec, ok := recs.Of(e.Name)
	if !ok {
		return devconf.SourceAddresses{}, "its configuration was never read: tacctl device config pull " + shellquote.Q(e.Name)
	}
	secs, err := store.Sections(e.Name, e.Vendor)
	if err != nil {
		return devconf.SourceAddresses{}, "its stored configuration cannot be read: tacctl device config pull " + shellquote.Q(e.Name)
	}
	fam, err := devconf.Family(e.Vendor)
	if err != nil || fam == devconf.FamilyWTI {
		return devconf.SourceAddresses{}, "only a Cisco or Juniper device states the source of its AAA client"
	}
	srcs := devconf.AAASourceAddresses(e.Vendor, secs[devconf.SectionAAA], rec.Interfaces)
	if srcs.Empty() && rec.Interfaces == nil && fam == devconf.FamilyIOS {
		// an IOS source-interface the section leaves out is kept in the
		// interface facts, which a pull before 0.2.23 did not make
		return devconf.SourceAddresses{}, devconf.SkipNotRecorded
	}
	return srcs, ""
}

// testDeviceSources tests the sources of the devices among entries: a few
// devices at once (as a scan reads host keys), the addresses of one device one
// after the other. The reports are in the order of entries (a host has none).
func (inv *invocation) testDeviceSources(entries []devreg.Entry, quiet bool) []sourceReport {
	out := make([]sourceReport, len(entries))
	// a long run says where it is, on a terminal and apart from the report
	var said sync.Mutex
	progress := func(name string) {
		if quiet || !inv.hooks.terminalWriter(inv.app.Out.Stderr) {
			return
		}
		said.Lock()
		defer said.Unlock()
		inv.stderrLine("testing source addresses of " + name + " ...")
	}
	recs := inv.configRecords()
	store := inv.configStore()
	sem := make(chan struct{}, devreg.KeyscanParallel)
	var wg sync.WaitGroup
	for i, e := range entries {
		if e.Source != devreg.SourceDevice {
			out[i] = sourceReport{Device: e.Name}
			continue
		}
		srcs, note := inv.sourcesOf(e, recs, store)
		if note != "" {
			out[i] = sourceReport{Device: e.Name, Note: note}
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			progress(e.Name)
			_, port, legacy, _ := scanTarget(e)
			timing := devssh.ScanTiming{}.Scaled(inv.scaleOfEntry(e))
			fallback := inv.hooks.scanFallback(inv)
			read := func(addr string) ([]devreg.HostKey, error) {
				return devreg.ScanWithTiming(inv.ctx, inv.app.Runner, addr, port, legacy, fallback, timing)
			}
			out[i] = testSources(inv.ctx, e.Name, e.Address, e.HostKeys, srcs, read)
			for j, x := range out[i].Results {
				if x.Result == sourceMismatch {
					// whose address it is, when it is another registered device's
					if d := inv.deviceAt(x.Address); d != nil && !strings.EqualFold(d.Name, e.Name) {
						out[i].Results[j].Device = d.Name
					}
				}
			}
		}()
	}
	wg.Wait()
	return out
}

// sourceLabel names a source in a line: the interface when the address came
// through one, else the address.
func sourceLabel(x sourceResult) string {
	if x.Interface != "" {
		return "source-interface " + x.Interface + " (" + x.Address + ")"
	}
	return "source-address " + x.Address
}

// printSources prints one device's report: a warning for each address that
// does not answer or presents another key, a line for each source left out,
// one summary. prefix leads every line (the device's name in a scan).
// quietEmpty drops a device that states no source at all; any other reason for
// testing nothing is said.
func (inv *invocation) printSources(r sourceReport, prefix string, quietEmpty bool) {
	out := inv.app.Out
	if len(r.Results) == 0 && !r.Registered {
		if !quietEmpty || r.Note != noteNoSource {
			out.Info(prefix + "no source address was tested: " + r.Note)
		}
		return
	}
	for _, x := range r.Results {
		switch x.Result {
		case sourceUnreachable:
			if x.Reason != "" {
				out.Warn(prefix + sourceLabel(x) + " could not be tested: " + x.Reason)
				break
			}
			out.Warn(prefix + sourceLabel(x) + " is unreachable from this server; it may be unreachable by design")
		case sourceMismatch:
			whose := "another device"
			if x.Device != "" {
				whose += " (" + x.Device + ")"
			}
			out.Warn(prefix + sourceLabel(x) + " presents another SSH host key (" + x.Fingerprint + "), the device's is " +
				x.Pinned + ": the address may belong to " + whose)
		case sourceSkipped:
			switch {
			case x.Source != "":
				out.Info(prefix + x.Source + " skipped: " + x.Reason)
			case strings.HasPrefix(x.Reason, "not compared"):
				out.Info(prefix + sourceLabel(x) + " " + x.Reason)
			}
		}
	}
	if r.Over > 0 {
		out.Info(prefix + howMany(r.Over, "more source address") + " not tested (at most " + strconv.Itoa(sourcesMax) + " per device)")
	}
	n := r.tested()
	switch {
	case n == 0 && r.Registered:
		out.Info(prefix + "no source address to test other than the registered address, which the host-key scan reads")
	case n == 0:
		out.Info(prefix + "no source address was tested")
	case n == r.count(sourceOK):
		out.Info(prefix + howMany(n, "source address") + " tested, all present the device's key")
	default:
		line := prefix + howMany(n, "source address") + " tested: " + strconv.Itoa(r.count(sourceOK))
		if r.count(sourceOK) == 1 {
			line += " presents the device's key"
		} else {
			line += " present the device's key"
		}
		if u := r.count(sourceUnreachable); u > 0 {
			line += ", " + strconv.Itoa(u) + " unreachable"
		}
		if m := r.count(sourceMismatch); m > 0 {
			line += ", " + strconv.Itoa(m)
			if m == 1 {
				line += " presents another key"
			} else {
				line += " present another key"
			}
		}
		out.Info(line)
	}
}

// auditSources writes the one audit line of a run of the test: how many
// addresses were tested and how they fared, no address among it.
func (inv *invocation) auditSources(reps []sourceReport) {
	tested, unreachable, mismatched := 0, 0, 0
	for _, r := range reps {
		tested += r.tested()
		unreachable += r.count(sourceUnreachable)
		mismatched += r.count(sourceMismatch)
	}
	inv.detail("sources", kvp("tested", strconv.Itoa(tested)), kvp("unreachable", strconv.Itoa(unreachable)),
		kvp("mismatched", strconv.Itoa(mismatched)))
}

// printCheckSources prints the report under the checklist of e: a host has no
// AAA client to test.
func (inv *invocation) printCheckSources(e devreg.Entry, r sourceReport) {
	if e.Source != devreg.SourceDevice {
		inv.app.Out.Info("Source addresses are tested for devices only.")
		return
	}
	inv.printSources(r, "", false)
}

// sourcesJSON is the sources array of a device in 'device check --json' with
// --sources: every source, tested or left out.
func sourcesJSON(r sourceReport) []sourceResult {
	out := append([]sourceResult{}, r.Results...)
	if len(out) == 0 && r.Note != "" && r.Note != noteNoSource {
		out = append(out, sourceResult{Result: sourceSkipped, Reason: r.Note})
	}
	return out
}
