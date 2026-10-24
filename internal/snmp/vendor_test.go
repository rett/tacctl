package snmp

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// The rows named "capture" are real captures of lab devices: the
// sysObjectID.0 and sysDescr.0 each device answered. The other rows are
// synthetic: each holds only the words the detection rule looks at
// (docs/plans/vendor-detection.md), and none is a capture of a device.
func TestDetectVendor(t *testing.T) {
	for _, c := range []struct {
		name, oid, descr string
		vendor, reason   string
	}{
		{"capture: Junos EX4300-48MP", "1.3.6.1.4.1.2636.1.1.1.4.63.9",
			"Juniper Networks, Inc. ex4300-48mp Ethernet Switch, kernel JUNOS 25.4R1-S3.3, Build date: 2026-09-11 01:36:47 UTC Copyright (c) 1996-2026 Juniper Networks, Inc.",
			"juniper", "Junos"},
		{"capture: IOS 12.4 (7200 emulator)", "1.3.6.1.4.1.9.1.222",
			"Cisco IOS Software, 7200 Software (C7200-ITPK9-M), Version 12.4(15)SW, RELEASE SOFTWARE (fc2)\r\n" +
				"Technical Support: http://www.cisco.com/techsupport\r\n" +
				"Copyright (c) 1986-2007 by Cisco Systems, Inc.\r\n" +
				"Compiled Wed 24-Oct-07 17:17 by prod_rel_team",
			"cisco", "Cisco IOS Software"},
		{"capture: IOS 15.6 (IOSv)", "1.3.6.1.4.1.9.1.1041",
			"Cisco IOS Software, IOSv Software (VIOS-ADVENTERPRISEK9-M), Version 15.6(2)T, RELEASE SOFTWARE (fc2)",
			"cisco", "Cisco IOS Software"},
		// This image's sysDescr starts "Cisco IOS Software", not "Cisco IOS XE
		// Software"; the XE prefix is for newer images.
		{"capture: IOS-XE 16.7 (CSR1000v)", "1.3.6.1.4.1.9.1.1537",
			"Cisco IOS Software [Fuji], Virtual XE Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 16.7.1, RELEASE SOFTWARE (fc6)",
			"cisco", "Cisco IOS Software"},
		// The sysDescr is generic Linux text: the enterprise is the only evidence.
		{"capture: WTI", "1.3.6.1.4.1.2634.1.8", "Linux localhost 5.4.0 #1 Tue Mar 24 13:05:15 PDT 2026 armv7l",
			"wti", "WTI"},
		{"IOS", "1.3.6.1.4.1.9.1.9999", "Cisco IOS Software, SYNTHETIC test platform, Version 0.0(0)",
			"cisco", "Cisco IOS Software"},
		{"IOS-XE", ".1.3.6.1.4.1.9.1.9998", "  Cisco IOS XE Software, SYNTHETIC test platform\r\nmore lines",
			"cisco", "Cisco IOS XE Software"},
		{"enterprise 9, not IOS", "1.3.6.1.4.1.9.1.9997", "Cisco SYNTHETIC security appliance, Version 0.0",
			"", "Cisco device, sysDescr not recognised as IOS or IOS-XE"},
		{"enterprise 9, IOS XR is not IOS", "1.3.6.1.4.1.9.1.9996", "Cisco IOS XR Software (SYNTHETIC)",
			"", "Cisco device, sysDescr not recognised as IOS or IOS-XE"},
		{"enterprise 9, no sysDescr", "1.3.6.1.4.1.9.1.9999", "", "", "Cisco (enterprise 9) with no sysDescr"},
		{"Junos, lower case in the sysDescr", "1.3.6.1.4.1.2636.1.1.1.9999", "SYNTHETIC router, kernel junos 0.0",
			"juniper", "Junos"},
		{"enterprise 2636 without Junos", "1.3.6.1.4.1.2636.1.1.1.9999", "SYNTHETIC appliance", "", "Juniper device, sysDescr does not name Junos"},
		{"enterprise 2636, no sysDescr", "1.3.6.1.4.1.2636.1.1.1.9999", "", "", "Juniper (enterprise 2636) with no sysDescr"},
		{"WTI, no sysDescr", "1.3.6.1.4.1.2634.9999", "", "wti", "WTI"},
		{"an unknown enterprise", "1.3.6.1.4.1.99999.1", "Cisco IOS Software, SYNTHETIC", "", "an unknown enterprise (99999)"},
		{"a longer enterprise number is not WTI", "1.3.6.1.4.1.26340.1", "Linux SYNTHETIC", "", "an unknown enterprise (26340)"},
		{"outside the enterprises", "1.3.6.1.2.1.1", "Cisco IOS Software", "", "a sysObjectID outside the enterprises (1.3.6.1.2.1.1)"},
		{"no sysObjectID", "", "Cisco IOS Software, SYNTHETIC", "", "no sysObjectID"},
		{"empty sysDescr, unknown enterprise", "1.3.6.1.4.1.99999.1", "", "", "an unknown enterprise (99999)"},
	} {
		v, r := DetectVendor(c.oid, c.descr)
		if v != c.vendor || r != c.reason {
			t.Errorf("%s: DetectVendor(%q, %q) = %q, %q; want %q, %q", c.name, c.oid, c.descr, v, r, c.vendor, c.reason)
		}
	}
	if !Offered("cisco") || !Offered("juniper") || !Offered("wti") || Offered("other") || Offered("") {
		t.Error("Offered: cisco, juniper and wti only")
	}
}

// sysObjectID.0 and sysDescr.0 in one request, over v2c and v3; an agent
// without them answers noSuchObject, read as empty.
func TestSysIdentityAgainstTheAgent(t *testing.T) {
	ctx := context.Background()
	a := &Agent{SysName: "sw1", Community: "c0mmunity", SysObjectID: "1.3.6.1.4.1.9.1.9999",
		SysDescr: "Cisco IOS Software, SYNTHETIC test platform"}
	port := startAgent(t, a)
	before := a.Requests.Load()
	id, err := fast(Config{Version: V2c, Port: port, Community: "c0mmunity"}).SysIdentity(ctx, "127.0.0.1")
	if err != nil || id.ObjectID != a.SysObjectID || id.Descr != a.SysDescr {
		t.Fatalf("v2c SysIdentity = %+v, %v", id, err)
	}
	if n := a.Requests.Load() - before; n != 1 {
		t.Errorf("v2c SysIdentity: %d requests, want 1 (both objects in one)", n)
	}
	if _, err := fast(Config{Version: V2c, Port: port, Community: "wrong"}).SysIdentity(ctx, "127.0.0.1"); err == nil {
		t.Error("wrong community answered")
	}
	bare := &Agent{SysName: "sw2", Community: "c0mmunity"}
	port = startAgent(t, bare)
	if id, err := fast(Config{Version: V2c, Port: port, Community: "c0mmunity"}).SysIdentity(ctx, "127.0.0.1"); err != nil || id != (Identity{}) {
		t.Errorf("no identity = %+v, %v", id, err)
	}
	v3 := &Agent{SysName: "rtr1", User: "alice", AuthPass: "auth-passphrase", PrivPass: "priv-passphrase", Auth: AuthSHA256,
		SysObjectID: "1.3.6.1.4.1.2636.1.1.1.9999", SysDescr: "SYNTHETIC router, kernel JUNOS 0.0"}
	port = startAgent(t, v3)
	c3 := fast(Config{Version: V3, Port: port, User: "alice", AuthPass: "auth-passphrase", PrivPass: "priv-passphrase",
		Auth: AuthSHA256, Priv: PrivAES128})
	id, err = c3.SysIdentity(ctx, "127.0.0.1")
	if err != nil || id.ObjectID != v3.SysObjectID || !strings.Contains(id.Descr, "JUNOS") {
		t.Errorf("v3 SysIdentity = %+v, %v", id, err)
	}
	// The one-object reads are unchanged beside it.
	if name, err := c3.SysName(ctx, "127.0.0.1"); err != nil || name != "rtr1" {
		t.Errorf("v3 SysName = %q, %v", name, err)
	}
}

// An answer that came and cannot be read is an AnswerError, not a timeout.
func TestAnswerErrors(t *testing.T) {
	var ae *AnswerError
	if _, err := answer(pdu{errorStatus: 2}, []string{SysObjectIDOID, SysDescrOID}); !errors.As(err, &ae) {
		t.Errorf("error-status: %v", err)
	}
	if _, err := answer(pdu{varbinds: []varbind{{oid: SysNameOID}}}, []string{SysObjectIDOID, SysDescrOID}); !errors.As(err, &ae) {
		t.Errorf("other objects: %v", err)
	}
}
