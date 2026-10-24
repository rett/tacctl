package snmp

// The vendor a device says it is (0.2.17 D260, docs/plans/vendor-detection.md):
// its sysObjectID.0 names the enterprise, its sysDescr.0 the operating
// system. A vendor is named only when both agree on one tacctl reads;
// anything else is a reason and no vendor.

import (
	"strings"
)

// The enterprise numbers (under 1.3.6.1.4.1) that detection recognises.
const (
	enterpriseCisco   = "9"
	enterpriseJuniper = "2636"
	enterpriseWTI     = "2634"
)

// enterprisesPrefix is iso.org.dod.internet.private.enterprises.
const enterprisesPrefix = "1.3.6.1.4.1."

// The sysDescr starts that make an enterprise-9 answer cisco: IOS and
// IOS-XE. ASA, NX-OS and IOS XR answer under enterprise 9 too, and tacctl
// does not read them as cisco; nor any other sysDescr (an older IOS image
// that describes itself otherwise waits for a capture).
var ciscoDescrs = []string{"Cisco IOS Software", "Cisco IOS XE Software"}

// offered are the vendors a detection names. juniper and wti are
// recognised, but offered only once a lab capture of each device's
// sysObjectID.0 and sysDescr.0 is a fixture of this package's tests.
var offered = map[string]bool{"cisco": true}

// Offered reports whether detection names vendor (the vendors a lab capture
// backs).
func Offered(vendor string) bool { return offered[vendor] }

// DetectVendor is the vendor objectID (sysObjectID.0, dotted) and descr
// (sysDescr.0) name together, with the reason: what was recognised. An
// empty vendor is no answer, and reason says why: an enterprise-9 answer
// without the IOS or IOS-XE sysDescr, a vendor not offered yet, an unknown
// enterprise, a missing sysObjectID or sysDescr.
func DetectVendor(objectID, descr string) (vendor, reason string) {
	oid := strings.TrimPrefix(strings.TrimSpace(objectID), ".")
	d := strings.TrimSpace(descr)
	if oid == "" {
		return "", "no sysObjectID"
	}
	ent, ok := enterpriseOf(oid)
	if !ok {
		return "", "a sysObjectID outside the enterprises (" + oid + ")"
	}
	switch ent {
	case enterpriseCisco:
		if d == "" {
			return "", "Cisco (enterprise 9) with no sysDescr"
		}
		for _, p := range ciscoDescrs {
			if strings.HasPrefix(d, p) {
				return offer("cisco", p)
			}
		}
		return "", "Cisco device, sysDescr not recognised as IOS or IOS-XE"
	case enterpriseJuniper:
		if d == "" {
			return "", "Juniper (enterprise 2636) with no sysDescr"
		}
		if !strings.Contains(strings.ToUpper(d), "JUNOS") {
			return "", "Juniper device, sysDescr does not name Junos"
		}
		return offer("juniper", "Junos")
	case enterpriseWTI:
		return offer("wti", "WTI")
	}
	return "", "an unknown enterprise (" + ent + ")"
}

// offer is vendor with what named it, or no vendor when detection does not
// name it yet.
func offer(vendor, what string) (string, string) {
	if !offered[vendor] {
		return "", what + ", which detection does not name yet (" + vendor + " is set by hand)"
	}
	return vendor, what
}

// enterpriseOf is the enterprise number of an object identifier under
// 1.3.6.1.4.1.
func enterpriseOf(oid string) (string, bool) {
	rest, ok := strings.CutPrefix(oid, enterprisesPrefix)
	if !ok {
		return "", false
	}
	ent, _, _ := strings.Cut(rest, ".")
	return ent, ent != ""
}
