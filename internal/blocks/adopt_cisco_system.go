package blocks

// The draft of 'block adopt' for an IOS system block (0.2.7): the device's
// own system lines, read live as 'show running-config | include ^(banner|ip
// domain|ip name-server|clock |ntp |logging |service timestamps|login |security |ip ssh)' with the banner's own lines from
// 'show running-config | section ^banner', turned into the text of a
// block to prune. A pure function of text, as AdoptSystem is, with the same
// meaning of same and up.
//
// What a draft holds is only what the grammar of the block takes and what the
// block does not state already. A key's string is never adopted (the device
// prints the ciphertext, or the text of a key typed with no encryption on):
// the draft says so per key and leaves the statement to be typed. A
// multi-address 'ip name-server' line is one object per address.
//
// Nothing here echoes the banner or a key: the notes are counts and the
// shapes of what was left out.

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// AdoptIOSSystem is the draft of an IOS system block from raw (the lines of
// the two reads); same is the block in force at the level the draft is for and
// up the block of the layer beneath it (a device's draft: the scope's);
// either may be nil.
func AdoptIOSSystem(raw string, same, up *IOSSystemBlock, layer Layer) AdoptResult {
	var res AdoptResult
	var accepted []string
	banners := map[string]*LoginMessage{}
	var outside int
	keys := map[int]bool{}
	lines := strings.Split(raw, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		f := strings.Fields(line)
		switch {
		case BannerKindOf(line) != "":
			kind := BannerKindOf(line)
			body, took, ok := DeviceBannerOf(kind, lines[i:])
			i += took - 1
			if !ok {
				res.Left = append(res.Left, "the "+kind+" banner could not be read (it is not closed by its delimiter): it is not adopted")
				continue
			}
			if banners[kind] == nil {
				banners[kind] = &LoginMessage{Body: body}
			}
		case f[0] == "banner":
			// motd, exec and the other banners are not a block's: the lines
			// after them, up to the delimiter, are text
			_, took, _ := deviceBannerOf(lines[i:])
			i += took - 1
			outside++
		case f[0] == "ntp" && len(f) >= 3 && f[1] == "authentication-key":
			n, _ := strconv.Atoi(f[2])
			if !keys[n] {
				keys[n] = true
				if n > 0 {
					res.Left = append(res.Left, fmt.Sprintf("ntp authentication-key %d holds the device's own key string (printed encrypted, or as typed), so it cannot be adopted: type it in the block where the device lacks it", n))
				} else {
					res.Left = append(res.Left, "an ntp authentication-key holds the device's own key string, so it cannot be adopted")
				}
			}
		case f[0] == "ip" && len(f) >= 3 && (f[1] == "name-server"):
			// one object per address, in the vrf the line names
			head, addrs := "ip name-server ", f[2:]
			if f[2] == "vrf" && len(f) >= 4 {
				head, addrs = "ip name-server vrf "+f[3]+" ", f[4:]
			}
			if f[2] == "vrf" && len(f) < 4 {
				outside++
				continue
			}
			for _, a := range addrs {
				s := head + a
				if _, fs := ParseIOSSystem(s + "\n"); HasErrors(fs) {
					outside++
					continue
				}
				accepted = append(accepted, s)
			}
		default:
			if _, fs := ParseIOSSystem(line + "\n"); HasErrors(fs) {
				outside++
				continue
			}
			accepted = append(accepted, strings.Join(f, " "))
		}
	}
	dev, _ := ParseIOSSystem(strings.Join(accepted, "\n") + "\n")
	for kind, m := range banners {
		*dev.bannerField(kind) = m
	}
	incl := &IOSSystemBlock{}
	var already, conflict int
	single := func(dv *Value, sv, uv *Value, set func(*Value)) {
		if dv == nil {
			return
		}
		switch {
		case sv != nil:
			if sv.Text == dv.Text {
				already++
			} else {
				conflict++
			}
		case uv != nil && uv.Text == dv.Text:
			already++
		default:
			set(dv)
		}
	}
	valueOf := func(b *IOSSystemBlock, f func(*IOSSystemBlock) *Value) *Value {
		if b == nil {
			return nil
		}
		return f(b)
	}
	single(dev.DomainName, valueOf(same, func(b *IOSSystemBlock) *Value { return b.DomainName }),
		valueOf(up, func(b *IOSSystemBlock) *Value { return b.DomainName }), func(v *Value) { incl.DomainName = v })
	for _, kind := range BannerKinds {
		dm := dev.BannerOf(kind)
		if dm == nil {
			continue
		}
		var sm, um *Value
		if m := same.BannerOf(kind); m != nil {
			sm = &Value{Text: m.Body}
		}
		if m := up.BannerOf(kind); m != nil {
			um = &Value{Text: m.Body}
		}
		kind, dm := kind, dm
		single(&Value{Text: dm.Body}, sm, um, func(*Value) { *incl.bannerField(kind) = dm })
	}
	if z := dev.Timezone; z != nil {
		eq := func(o *IOSTimezone) bool { return o.Zone == z.Zone && o.Hours == z.Hours && o.Minutes == z.Minutes }
		switch {
		case same != nil && same.Timezone != nil && eq(same.Timezone):
			already++
		case same != nil && same.Timezone != nil:
			conflict++
		case up != nil && up.Timezone != nil && eq(up.Timezone):
			already++
		default:
			incl.Timezone = z
		}
	}
	if a := dev.NTPAuthenticate; a != nil {
		switch {
		case same != nil && same.NTPAuthenticate != nil, up != nil && up.NTPAuthenticate != nil:
			already++
		default:
			incl.NTPAuthenticate = a
		}
	}
	// the statements of the closed table (logging, timestamps, login and
	// password policy, ssh, summer time): by their identity, as a single value
	// is
	for _, r := range dev.Rules {
		find := func(b *IOSSystemBlock) *RuleStmt {
			if b == nil {
				return nil
			}
			if i := indexRule(b.Rules, r.Rule, r.Head); i >= 0 {
				return &b.Rules[i]
			}
			return nil
		}
		same1 := func(o *RuleStmt) bool { return strings.Join(o.Args, " ") == strings.Join(r.Args, " ") }
		switch o := find(same); {
		case o != nil && same1(o):
			already++
		case o != nil:
			conflict++
		default:
			if u := find(up); u != nil && same1(u) {
				already++
			} else if def := ruleByID(r.Rule); def != nil && def.DeviceOnly && layer != LayerDevice {
				res.Left = append(res.Left, r.Text()+" names an address of this device, which a scope's block does not state: it is left out (state it in the device's own block)")
			} else {
				incl.Rules = append(incl.Rules, r)
			}
		}
	}
	list := func(dst *[]Value, dv []Value, sv, uv []Value) {
		for _, v := range dv {
			has := func(l []Value) bool {
				return slices.ContainsFunc(l, func(o Value) bool { return o.Text == v.Text })
			}
			if has(sv) || has(uv) {
				already++
				continue
			}
			*dst = append(*dst, v)
		}
	}
	listOf := func(b *IOSSystemBlock, f func(*IOSSystemBlock) []Value) []Value {
		if b == nil {
			return nil
		}
		return f(b)
	}
	// the statements of a vrf are objects of that vrf: the same value in
	// another vrf is another statement
	for _, v := range dev.VRFDomainNames {
		find := func(b *IOSSystemBlock) *IOSVRFValue {
			if b != nil {
				for i := range b.VRFDomainNames {
					if b.VRFDomainNames[i].VRF == v.VRF {
						return &b.VRFDomainNames[i]
					}
				}
			}
			return nil
		}
		switch o := find(same); {
		case o != nil && o.Text == v.Text:
			already++
		case o != nil:
			conflict++
		default:
			if u := find(up); u != nil && u.Text == v.Text {
				already++
			} else {
				incl.VRFDomainNames = append(incl.VRFDomainNames, v)
			}
		}
	}
	vrfList := func(dst *[]IOSVRFValue, dv []IOSVRFValue, sv, uv []IOSVRFValue) {
		for _, v := range dv {
			has := func(l []IOSVRFValue) bool {
				return slices.ContainsFunc(l, func(o IOSVRFValue) bool { return o.VRF == v.VRF && o.Text == v.Text })
			}
			if has(sv) || has(uv) {
				already++
				continue
			}
			*dst = append(*dst, v)
		}
	}
	vrfListOf := func(b *IOSSystemBlock, f func(*IOSSystemBlock) []IOSVRFValue) []IOSVRFValue {
		if b == nil {
			return nil
		}
		return f(b)
	}
	vrfList(&incl.VRFDomainList, dev.VRFDomainList, vrfListOf(same, func(b *IOSSystemBlock) []IOSVRFValue { return b.VRFDomainList }),
		vrfListOf(up, func(b *IOSSystemBlock) []IOSVRFValue { return b.VRFDomainList }))
	vrfList(&incl.VRFNameServers, dev.VRFNameServers, vrfListOf(same, func(b *IOSSystemBlock) []IOSVRFValue { return b.VRFNameServers }),
		vrfListOf(up, func(b *IOSSystemBlock) []IOSVRFValue { return b.VRFNameServers }))
	list(&incl.DomainList, dev.DomainList, listOf(same, func(b *IOSSystemBlock) []Value { return b.DomainList }),
		listOf(up, func(b *IOSSystemBlock) []Value { return b.DomainList }))
	list(&incl.NameServers, dev.NameServers, listOf(same, func(b *IOSSystemBlock) []Value { return b.NameServers }),
		listOf(up, func(b *IOSSystemBlock) []Value { return b.NameServers }))
	for _, s := range dev.NTPServers {
		find := func(b *IOSSystemBlock) *IOSNTPServer {
			if b == nil {
				return nil
			}
			for i := range b.NTPServers {
				if b.NTPServers[i].sameServer(s) {
					return &b.NTPServers[i]
				}
			}
			return nil
		}
		eq := func(o *IOSNTPServer) bool {
			return o.Prefer == s.Prefer && o.Version == s.Version && o.Key == s.Key && strings.EqualFold(o.Source, s.Source)
		}
		switch o := find(same); {
		case o != nil && eq(o):
			already++
		case o != nil:
			conflict++
		default:
			if u := find(up); u != nil && eq(u) {
				already++
			} else {
				if s.Source != "" && layer != LayerDevice && !isLoopbackName(s.Source) {
					res.Left = append(res.Left, "ntp server "+s.Host+" source "+s.Source+" names an interface of this device, which a scope's block does not state: the server is adopted without it (state it in the device's own block)")
					s.Source = ""
				}
				incl.NTPServers = append(incl.NTPServers, s)
			}
		}
	}
	for _, k := range dev.NTPTrustedKeys {
		has := func(b *IOSSystemBlock) bool {
			return b != nil && slices.ContainsFunc(b.NTPTrustedKeys, func(o KeyRef) bool { return o.Number == k.Number })
		}
		if has(same) || has(up) {
			already++
			continue
		}
		incl.NTPTrustedKeys = append(incl.NTPTrustedKeys, k)
	}
	res.Text = incl.String(false)
	res.Statements = len(IOSSystemUnits(incl))
	res.Objects = res.Statements

	note := func(n int, label, tail string) {
		if n > 0 {
			res.Notes = append(res.Notes, fmt.Sprintf("%s: %d %s, %s", label, n, count(n, "statement", "statements"), tail))
		}
	}
	note(outside, "outside what an IOS system block takes ('ip domain lookup', 'ntp master', 'ntp source', other banners, and the like)", "not adopted")
	note(already, "stated already, with the same value, by this block or the scope's", "not repeated")
	note(conflict, "differing from what this block states (a single value, or a server with other options)", "left as they are (edit them in place)")
	return res
}

// deviceBannerOf is DeviceBanner for a banner of any type ('banner motd ^C
// ...'): how many lines it takes.
func deviceBannerOf(lines []string) (body string, took int, ok bool) {
	if len(lines) == 0 {
		return "", 0, false
	}
	f := strings.Fields(lines[0])
	if len(f) < 2 {
		return "", 1, false
	}
	cp := slices.Clone(lines)
	cp[0] = "banner login " + strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(lines[0]), "banner "+f[1]))
	return DeviceBanner(cp)
}
