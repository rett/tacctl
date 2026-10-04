package devreg

// The scan-time notices (docs/plans/operator-console.md 3.6 item 3 and
// 3.7): computed from the seen cache that 'device scan' and 'device check'
// fill, never stored; only their acknowledgements are (ack: in
// devices.yaml). Every text ends in the command that fixes or acknowledges
// the notice.
//
//	hostkey-changed      the last re-scan offered no pinned key, or another
//	                     key of a pinned type (cannot be acknowledged)
//	hostkey-added        it offered a key of a type nothing is pinned for
//	hostkey-unreachable  the last re-scan read no key
//	duplicate-address    two entries hold one address, or an address
//	                     identifies as another entry's name
//	identity-changed     the NAS-Identifier an address sends changed
//	generic-nas-id       the NAS-Identifier is a generic name
//	name-mismatch        the NAS-Identifier is not the entry's name
//	ambiguous-nas-id     one NAS-Identifier is sent from several addresses

import (
	"slices"
	"strconv"
	"strings"
	"time"
)

// noticeIndex is what the scan-time notices compare an entry with: every
// entry by address and by name, and every seen address by NAS-Identifier.
type noticeIndex struct {
	byAddr map[string][]Entry
	byName map[string]Entry
	byNAS  map[string][]string
}

func (r *Resolver) index() *noticeIndex {
	if r.idx != nil {
		return r.idx
	}
	x := &noticeIndex{byAddr: map[string][]Entry{}, byName: map[string]Entry{}, byNAS: map[string][]string{}}
	for _, e := range r.All() {
		if e.Address != "" {
			x.byAddr[e.Address] = append(x.byAddr[e.Address], e)
		}
		x.byName[strings.ToLower(e.Name)] = e
	}
	for _, s := range r.Seen.All() {
		if s.LastNASID != "" {
			k := strings.ToLower(s.LastNASID)
			x.byNAS[k] = append(x.byNAS[k], s.Address)
		}
	}
	r.idx = x
	return x
}

// ackTail is the way to acknowledge kind on e: a registry device only
// (an enrolled host's notices are cleared on the host).
func ackTail(e Entry, kind string) string {
	if e.Source != SourceDevice {
		return ""
	}
	return ", or acknowledge it: 'tacctl device notice " + e.Name + " ack " + kind + "'"
}

// whenText is a time as the notices print it ('never' for none).
func whenText(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	return t.Format("2006-01-02 15:04")
}

// nameMatches reports whether a NAS-Identifier is e's own name: its
// registry name, its hostname, or the hostname's first label, compared
// without regard to case.
func nameMatches(e Entry, nas string) bool {
	if strings.EqualFold(nas, e.Name) {
		return true
	}
	if e.Hostname != "" {
		h := strings.TrimSuffix(e.Hostname, ".")
		first, _, _ := strings.Cut(h, ".")
		if strings.EqualFold(nas, h) || strings.EqualFold(nas, first) {
			return true
		}
	}
	first, _, _ := strings.Cut(nas, ".")
	return strings.EqualFold(first, e.Name)
}

// scanNotices are the notices the seen cache raises for e.
func (r *Resolver) scanNotices(e Entry) []Notice {
	var out []Notice
	add := func(kind, text string) {
		acked := kind != NoticeHostKeyChanged && slices.Contains(e.Ack, kind)
		out = append(out, Notice{Kind: kind, Text: text, Acked: acked})
	}
	out = append(out, r.hostKeyNotices(e)...)
	if e.Address == "" {
		return out
	}
	x := r.index()
	dup := false
	for _, o := range x.byAddr[e.Address] {
		if !strings.EqualFold(o.Name, e.Name) {
			dup = true
			add(NoticeDuplicateAddress, e.Address+" is the address of both '"+e.Name+"' and '"+o.Name+
				"'; give each its own: 'tacctl device address <name> <address>'"+ackTail(e, NoticeDuplicateAddress))
			break
		}
	}
	s, ok := r.Seen.Of(e.Address)
	if !ok || s.LastNASID == "" {
		return out
	}
	nas := s.LastNASID
	hints := strings.Join(RenameHints(e.Vendor), "; ")
	if s.PrevNASID != "" && !strings.EqualFold(s.PrevNASID, nas) {
		add(NoticeIdentityChanged, e.Address+" now identifies as '"+nas+"' (was '"+s.PrevNASID+"', changed "+whenText(s.NASChanged)+
			") — replaced or reset? verify on the device"+ackTail(e, NoticeIdentityChanged))
	}
	other, isOther := x.byName[strings.ToLower(nas)]
	switch {
	case IsGeneric(nas, r.extraGeneric()):
		add(NoticeGenericNASID, e.Address+" identifies itself as '"+nas+"' (NAS-Identifier), a generic name; give the device its own: "+
			hints+ackTail(e, NoticeGenericNASID))
	case isOther && !strings.EqualFold(other.Name, e.Name) && !dup:
		add(NoticeDuplicateAddress, e.Address+" ('"+e.Name+"') identifies itself as '"+nas+"', which is registered at "+
			dashAddr(other.Address)+"; one address answers for two devices: check both"+ackTail(e, NoticeDuplicateAddress))
	case !nameMatches(e, nas):
		fix := "'tacctl device rename " + e.Name + " " + nas + "'"
		if e.Source == SourceHost {
			fix = "'hostnamectl set-hostname " + e.Name + "' on the host"
		}
		add(NoticeNameMismatch, e.Address+" identifies itself as '"+nas+"', not '"+e.Name+"' (informational); align them: "+
			fix+", or name the device ("+hints+")"+ackTail(e, NoticeNameMismatch))
	}
	if addrs := x.byNAS[strings.ToLower(nas)]; len(addrs) > 1 {
		add(NoticeAmbiguousNASID, "NAS-Identifier '"+nas+"' is sent from "+strconv.Itoa(len(addrs))+" addresses ("+
			strings.Join(addrs, ", ")+"); give each device a name of its own: "+hints+ackTail(e, NoticeAmbiguousNASID))
	}
	return out
}

func dashAddr(a string) string {
	if a == "" {
		return "no address"
	}
	return a
}

// hostKeyNotices compare e's pinned keys with what the last re-scan read.
// An entry with nothing pinned has the hostkey-unpinned notice instead.
func (r *Resolver) hostKeyNotices(e Entry) []Notice {
	if len(e.HostKeys) == 0 {
		return nil
	}
	k, ok := r.Seen.KeyScanOf(e.Name)
	// A scan of another address or port than the device's (changed since)
	// says nothing about it.
	if !ok || (e.Source == SourceDevice && (k.Address != e.Address || k.Port != e.SSHPort())) {
		return nil
	}
	ack := func(kind string) bool { return slices.Contains(e.Ack, kind) }
	verify := "Verify on the console (" + VerifyHint(e.Vendor) + ")"
	if k.Unreachable {
		return []Notice{{Kind: NoticeHostKeyUnreach, Acked: ack(NoticeHostKeyUnreach),
			Text: "no host key could be read from '" + e.Name + "' (" + k.Address + " port " + strconv.Itoa(k.Port) + ") at " +
				whenText(k.Scanned) + "; last good scan " + whenText(k.LastGood) +
				"; check the device and the path, then 'tacctl device check " + e.Name + "'" + ackTail(e, NoticeHostKeyUnreach)}}
	}
	offered := ParseHostKeys(k.Offered)
	c := Compare(e.HostKeys, offered)
	switch {
	case c.Changed:
		return []Notice{{Kind: NoticeHostKeyChanged,
			Text: "the host key of '" + e.Name + "' changed (scan " + whenText(k.Scanned) + "): pinned " +
				Displays(ParseHostKeys(e.HostKeys)) + "; offered " + Displays(offered) +
				"; 'tacctl ssh' refuses it until it is pinned again. " + verify +
				", then 'tacctl device hostkey " + e.Name + " accept'"}}
	case len(c.Added) > 0:
		return []Notice{{Kind: NoticeHostKeyAdded, Acked: ack(NoticeHostKeyAdded),
			Text: "'" + e.Name + "' offers a new host key type (scan " + whenText(k.Scanned) + "): " + Displays(c.Added) +
				"; the pinned keys are unchanged. " + verify + ", then 'tacctl device hostkey " + e.Name + " accept'" +
				ackTail(e, NoticeHostKeyAdded)}}
	}
	return nil
}
