package devreg

import (
	"slices"
	"strings"
)

// Notice kinds (docs/plans/operator-console.md 3.6 and 3.7). The registry
// itself raises GenericName and HostKeyUnpinned; the scan-time kinds are
// raised by the packages that scan, and share the acknowledgement here.
const (
	NoticeGenericName      = "generic-name"
	NoticeHostKeyUnpinned  = "hostkey-unpinned"
	NoticeHostKeyAdded     = "hostkey-added"
	NoticeHostKeyUnreach   = "hostkey-unreachable"
	NoticeHostKeyChanged   = "hostkey-changed"
	NoticeAmbiguousNASID   = "ambiguous-nas-id"
	NoticeGenericNASID     = "generic-nas-id"
	NoticeNameMismatch     = "name-mismatch"
	NoticeDuplicateAddress = "duplicate-address"
	NoticeIdentityChanged  = "identity-changed"
	NoticeAddressChanged   = "address-changed"
)

// AckableKinds are the notices an operator may acknowledge per device.
// hostkey-changed is not among them: only re-pinning clears it.
var AckableKinds = []string{
	NoticeGenericName, NoticeHostKeyUnpinned, NoticeHostKeyAdded, NoticeHostKeyUnreach,
	NoticeAmbiguousNASID, NoticeGenericNASID, NoticeNameMismatch, NoticeDuplicateAddress, NoticeIdentityChanged,
	NoticeAddressChanged,
}

// HostAckableKinds are the notices an operator may acknowledge for an
// enrolled host (its other notices are cleared on the host).
var HostAckableKinds = []string{NoticeAddressChanged}

// Notice is one finding about an entry: its kind, a line of text that ends
// in the command that fixes or acknowledges it, and whether it has been
// acknowledged.
type Notice struct {
	Kind  string
	Text  string
	Acked bool
}

// RenameHints are the per-vendor commands that give a device a name of its
// own (the [A] texts of the design stay to be verified in the lab).
var renameHints = map[string]string{
	"cisco":   "Cisco IOS/IOS-XE: 'hostname <name>', and so RADIUS carries it, 'radius-server attribute 32 include-in-access-req format %h'",
	"juniper": "Junos: 'set system host-name <name>'",
	"wti":     "WTI: set the Site ID / unit name in the /N network menu (the menu item varies by firmware)",
	"linux":   "Linux hosts: 'hostnamectl set-hostname <name>'",
}

// RenameHints are the commands that name a device of vendor (every
// vendor's when the vendor says nothing: other).
func RenameHints(vendor string) []string {
	if h, ok := renameHints[vendor]; ok {
		return []string{h}
	}
	return []string{renameHints["cisco"], renameHints["juniper"], renameHints["wti"], renameHints["linux"]}
}

// GenericRefusal is the refusal of a generic name with its remediation
// steps; what is the thing being named ('device', 'host'), and keep the
// command that registers it anyway (” for none).
func GenericRefusal(name, vendor, keep string) error {
	lines := []string{
		"'" + name + "' is a generic name (a factory or image default); devices are told apart by name.",
		"Give it a name of its own first:",
	}
	for _, h := range RenameHints(vendor) {
		lines = append(lines, "  "+h)
	}
	lines = append(lines, "then register it under that name.")
	if keep != "" {
		lines = append(lines, "To keep this name deliberately: "+keep)
	}
	return fail(lines...)
}

// NoticesFor are the notices of e, in a fixed order, with the
// acknowledged ones marked: the ones the registry itself raises, then the
// scan-time ones of the seen cache (notices_scan.go). Host entries (vendor
// linux) get no hostkey-unpinned notice: 'host enroll' and 'host sync' pin
// their keys.
func (r *Resolver) NoticesFor(e Entry) []Notice {
	ns := append(r.registryNotices(e), r.scanNotices(e)...)
	for i := range ns {
		if ns[i].Acked {
			ns[i].Text = settled(ns[i].Text)
		}
	}
	return ns
}

// settled is an acknowledged notice's text: what happened, without what
// to do about it (the check to make and the acknowledgement asked for).
func settled(text string) string {
	for _, cut := range []string{" — readdressed, or replaced?", ", then acknowledge it:", ", or acknowledge it:", "; or acknowledge it:"} {
		if i := strings.Index(text, cut); i >= 0 {
			text = text[:i]
		}
	}
	return strings.TrimRight(text, " ;,")
}

// registryNotices are the notices the registry raises by itself.
func (r *Resolver) registryNotices(e Entry) []Notice {
	var out []Notice
	add := func(kind, text string) {
		out = append(out, Notice{Kind: kind, Text: text, Acked: slices.Contains(e.Ack, kind)})
	}
	if IsGeneric(e.Name, r.extraGeneric()) {
		if e.Source == SourceHost {
			add(NoticeGenericName, "'"+e.Name+"' is a generic name. "+renameHints["linux"]+
				", then re-enroll it under that name: 'tacctl host unenroll "+e.Name+"', 'tacctl host enroll <host> --name <new>'")
		} else {
			add(NoticeGenericName, "'"+e.Name+"' is a generic name. "+strings.Join(RenameHints(e.Vendor), "; ")+
				"; then 'tacctl device rename "+e.Name+" <new>', or acknowledge it: 'tacctl device notice "+e.Name+" ack generic-name'")
		}
	}
	if e.Source == SourceHost && e.PrevAddress != "" {
		text := "the address of '" + e.Name + "' changed from " + e.PrevAddress + " to " + e.Address + " (" + e.AddressChanged +
			", seen by host enroll or sync) — readdressed, or replaced? verify on the host"
		if r.Model != nil && e.Scope != "" {
			if info, ok := r.Model.LookupAddr(e.Address); !ok || info.Scope != e.Scope {
				text += "; scope '" + e.Scope + "' does not answer " + e.Address + ": 'tacctl scope prefixes " + e.Scope + " add " + e.Address + "/32'"
			}
		}
		add(NoticeAddressChanged, text+", then acknowledge it: 'tacctl device notice "+e.Name+" ack "+NoticeAddressChanged+"'")
	}
	if e.Source == SourceDevice && len(e.HostKeys) == 0 {
		add(NoticeHostKeyUnpinned, "no host key is pinned for '"+e.Name+"', so tacctl cannot tell the device from an impostor; "+
			"compare its fingerprint on the console ("+VerifyHint(e.Vendor)+"), then pin it: 'tacctl device hostkey "+e.Name+" accept', "+
			"or acknowledge it: 'tacctl device notice "+e.Name+" ack hostkey-unpinned'")
	}
	return out
}

// Open are the notices that have not been acknowledged.
func Open(ns []Notice) []Notice {
	var out []Notice
	for _, n := range ns {
		if !n.Acked {
			out = append(out, n)
		}
	}
	return out
}
