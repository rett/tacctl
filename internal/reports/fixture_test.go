package reports

import "time"

// now is the time every test generates at.
var now = time.Date(2026, 11, 6, 9, 30, 15, 0, time.UTC)

func at(day, hour, min int) time.Time {
	return time.Date(2026, 11, day, hour, min, 0, 0, time.UTC)
}

// fixture is a small fleet: a Junos virtual chassis of three members, a Cisco
// stack of two, a standalone device with a model and a serial, one with
// neither, a device never pulled, one whose fields start with the characters a
// spreadsheet runs and carry a control character, and one with a Unicode name.
// The slice is deliberately not in name order.
func fixture() []Device {
	return []Device{
		{
			Name: "web1", Address: "203.0.113.20", Vendor: "linux", Scope: "lab",
			Model: "=SUM(A1)", Serial: "+SN000007", Release: "-1.0", Location: "@Rack 4, DC1",
			Description: "uses\x1b[31m colour", Pulled: at(5, 8, 0), Applied: at(4, 7, 5),
			ConfigState: "differs", GateState: "-held",
		},
		{
			Name: "sw1", Address: "192.0.2.11", Vendor: "cisco", Scope: "site-a",
			Model: "WS-C3850-24T", Serial: "SN000004", Release: "16.12.4", Location: "Rack 4, DC1",
			Description: "access stack", Pulled: at(6, 7, 45), Applied: at(1, 12, 0),
			ConfigState: "ok", GateState: "ok",
			Members: []Member{
				{ID: "2", Role: "member", Model: "WS-C3850-24T", Serial: "SN000005", Release: "16.12.4", Status: "Ready", Priority: 1},
				{ID: "1", Role: "master", Model: "WS-C3850-24T", Serial: "SN000004", Release: "16.12.4", Status: "Ready", Priority: 15},
			},
		},
		{
			Name: "jsw1", Address: "192.0.2.10", Vendor: "junos", Scope: "site-a",
			Model: "EX4300-48T", Serial: "SN000001", Release: "21.4R3-S5.4", Location: "Rack 4, DC1",
			Description: "core virtual chassis", Pulled: at(6, 7, 30), Applied: at(2, 9, 0),
			ConfigState: "ok", GateState: "held",
			Members: []Member{
				{ID: "0", Role: "master", Model: "EX4300-48T", Serial: "SN000001", Release: "21.4R3-S5.4", Status: "Prsnt", Priority: 129},
				{ID: "10", Role: "linecard", Model: "EX4300-48T", Serial: "SN000003", Release: "21.4R3-S5.4", Status: "Prsnt", Priority: 0},
				{ID: "1", Role: "backup", Model: "EX4300-48T", Serial: "SN000002", Release: "21.4R3-S5.4", Status: "Prsnt", Priority: 129},
			},
		},
		{
			Name: "rtr1", Address: "198.51.100.1", Vendor: "junos", Scope: "site-a",
			Model: "MX204", Serial: "SN000006", Release: "22.2R1.9", Location: "Lab rack 2",
			Pulled: at(3, 22, 10), ConfigState: "failed", GateState: "",
		},
		{
			Name: "core1", Address: "198.51.100.2", Vendor: "wti", Scope: "lab",
			ConfigState: "ok", Pulled: at(6, 6, 0), Applied: at(6, 6, 5),
		},
		{
			Name: "fw1", Address: "2001:db8::1", Vendor: "cisco", Scope: "lab",
			ConfigState: "never",
		},
		{
			Name: "ünï1", Address: "10.0.0.9", Vendor: "linux", Scope: "lab",
			Model: "Model Ü", Serial: "SN000008", Release: "1.2", Description: "Zürich",
			Pulled: at(4, 10, 0), ConfigState: "ok", GateState: "ok",
		},
	}
}
