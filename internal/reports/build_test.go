package reports

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"
)

func column(r Report, name string) []string {
	idx := -1
	for i, c := range r.Columns {
		if c == name {
			idx = i
		}
	}
	var out []string
	for _, row := range r.Rows {
		out = append(out, row[idx])
	}
	return out
}

func TestColumns(t *testing.T) {
	want := map[string]string{
		TypeInventory: "name,address,vendor,scope,model,serial,release,members,location,description,pulled",
		TypeMembers:   "device,member,role,model,serial,release,status,priority,pulled",
		TypeSoftware:  "name,vendor,model,release,pulled",
		TypeConfig:    "name,scope,state,pulled,applied",
	}
	for typ, cols := range want {
		if got := strings.Join(Columns(typ), ","); got != cols {
			t.Errorf("Columns(%s) = %s, want %s", typ, got, cols)
		}
		if len(Columns(typ)) != len(jsonKeys(typ)) && typ != TypeMembers {
			t.Errorf("%s: %d columns, %d json keys", typ, len(Columns(typ)), len(jsonKeys(typ)))
		}
	}
	if Columns("nope") != nil {
		t.Error("Columns of an unknown type is not nil")
	}
	if got := strings.Join(Types(), ","); got != "inventory,members,software,config" {
		t.Errorf("Types() = %s", got)
	}
}

func TestBuildUnknownType(t *testing.T) {
	_, err := Build("uptime", fixture(), now)
	if err == nil {
		t.Fatal("unknown type accepted")
	}
	for _, w := range []string{`"uptime"`, "inventory", "members", "software", "config"} {
		if !strings.Contains(err.Error(), w) {
			t.Errorf("error %q does not mention %s", err, w)
		}
	}
}

func TestBuildRowShape(t *testing.T) {
	for _, typ := range Types() {
		r, err := Build(typ, fixture(), now)
		if err != nil {
			t.Fatal(err)
		}
		if r.Schema != 1 || r.Type != typ || !r.Generated.Equal(now) {
			t.Errorf("%s: header %+v", typ, r)
		}
		if len(r.Rows) != len(r.Objects) || len(r.Rows) == 0 {
			t.Fatalf("%s: %d rows, %d objects", typ, len(r.Rows), len(r.Objects))
		}
		for i, row := range r.Rows {
			if len(row) != len(r.Columns) {
				t.Errorf("%s row %d: %d cells for %d columns", typ, i, len(row), len(r.Columns))
			}
			for _, k := range r.Keys {
				if _, ok := r.Objects[i][k]; !ok {
					t.Errorf("%s row %d: object has no key %s", typ, i, k)
				}
			}
			if len(r.Objects[i]) != len(r.Keys) {
				t.Errorf("%s row %d: %d keys in the object, %d expected", typ, i, len(r.Objects[i]), len(r.Keys))
			}
		}
		if r.Devices != 7 {
			t.Errorf("%s: Devices = %d", typ, r.Devices)
		}
	}
}

func TestBuildDoesNotChangeInput(t *testing.T) {
	devs := fixture()
	before, _ := json.Marshal(devs)
	for _, typ := range Types() {
		if _, err := Build(typ, devs, now); err != nil {
			t.Fatal(err)
		}
	}
	after, _ := json.Marshal(devs)
	if string(before) != string(after) {
		t.Error("Build changed its input")
	}
}

func TestBuildSortOrder(t *testing.T) {
	r, _ := Build(TypeSoftware, fixture(), now)
	got := strings.Join(column(r, "name"), ",")
	if want := "core1,fw1,jsw1,rtr1,sw1,web1,ünï1"; got != want {
		t.Errorf("names = %s, want %s", got, want)
	}
	// The comparison is by bytes: upper case before lower case, whatever the locale.
	devs := []Device{{Name: "b"}, {Name: "B"}, {Name: "a"}, {Name: "A"}}
	r, _ = Build(TypeConfig, devs, now)
	if got := strings.Join(column(r, "name"), ","); got != "A,B,a,b" {
		t.Errorf("names = %s", got)
	}
	// Equal names keep the order they came in.
	devs = []Device{{Name: "x", Scope: "two"}, {Name: "x", Scope: "one"}}
	r, _ = Build(TypeConfig, devs, now)
	if got := strings.Join(column(r, "scope"), ","); got != "two,one" {
		t.Errorf("scopes = %s", got)
	}
}

func TestMembersReport(t *testing.T) {
	r, _ := Build(TypeMembers, fixture(), now)
	var lines []string
	for _, row := range r.Rows {
		lines = append(lines, row[0]+"/"+row[1]+"/"+row[2]+"/"+row[4]+"/"+row[7])
	}
	want := []string{
		// core1 has neither a model nor a serial: left out.
		// fw1 too.
		"jsw1/0/master/SN000001/129",
		"jsw1/1/backup/SN000002/129",
		"jsw1/10/linecard/SN000003/0",
		"rtr1/-/-/SN000006/",
		"sw1/1/master/SN000004/15",
		"sw1/2/member/SN000005/1",
		"web1/-/-/+SN000007/",
		"ünï1/-/-/SN000008/",
	}
	if !reflect.DeepEqual(lines, want) {
		t.Errorf("rows:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
	if r.Devices != 7 {
		t.Errorf("Devices = %d (devices left out still count)", r.Devices)
	}
	// A device with a model only is a standalone row too.
	r, _ = Build(TypeMembers, []Device{{Name: "a", Model: "M"}}, now)
	if len(r.Rows) != 1 || r.Rows[0][1] != "-" {
		t.Errorf("model only: %v", r.Rows)
	}
	// Members JSON: components is an empty list, never null.
	r, _ = Build(TypeMembers, fixture(), now)
	b, _ := json.Marshal(r.Objects[0])
	if !strings.Contains(string(b), `"components":[]`) {
		t.Errorf("object %s has no empty components", b)
	}
	if p, ok := r.Objects[0]["priority"].(int); !ok || p != 129 {
		t.Errorf("priority = %#v", r.Objects[0]["priority"])
	}
}

func TestMembersKeepComponents(t *testing.T) {
	devs := []Device{{Name: "a", Members: []Member{{ID: "1", Components: []Component{{Kind: "psu", Slot: "0", Serial: "SN000009"}}}}}}
	r, _ := Build(TypeMembers, devs, now)
	b, _ := json.Marshal(r.Objects[0]["components"])
	if !strings.Contains(string(b), `"kind":"psu"`) || !strings.Contains(string(b), "SN000009") {
		t.Errorf("components = %s", b)
	}
	if len(r.Rows[0]) != len(r.Columns) {
		t.Error("components changed the cells")
	}
}

func TestMemberIDOrder(t *testing.T) {
	devs := []Device{{Name: "a", Members: []Member{{ID: "b"}, {ID: "10"}, {ID: "2"}, {ID: "a"}, {ID: "02"}}}}
	r, _ := Build(TypeMembers, devs, now)
	if got := strings.Join(column(r, "member"), ","); got != "02,2,10,a,b" {
		t.Errorf("ids = %s", got)
	}
}

func TestInventoryReport(t *testing.T) {
	r, _ := Build(TypeInventory, fixture(), now)
	counts := strings.Join(column(r, "members"), ",")
	if want := "-,-,3,-,2,-,-"; counts != want {
		t.Errorf("members = %s, want %s", counts, want)
	}
	if got := column(r, "location")[3]; got != "Lab rack 2" {
		t.Errorf("location = %q", got)
	}
	if got := column(r, "description")[2]; got != "core virtual chassis" {
		t.Errorf("description = %q", got)
	}
	// Raw cells: an empty one stays empty.
	if got := column(r, "serial")[0]; got != "" {
		t.Errorf("empty serial = %q", got)
	}
	if v := r.Objects[2]["members"]; v != 3 {
		t.Errorf("json members = %#v", v)
	}
}

func TestDates(t *testing.T) {
	r, _ := Build(TypeConfig, fixture(), now)
	pulled := strings.Join(column(r, "pulled"), "|")
	if want := "2026-11-06 06:00|never|2026-11-06 07:30|2026-11-03 22:10|2026-11-06 07:45|2026-11-05 08:00|2026-11-04 10:00"; pulled != want {
		t.Errorf("pulled = %s", pulled)
	}
	applied := strings.Join(column(r, "applied"), "|")
	if want := "2026-11-06 06:05|-|2026-11-02 09:00|-|2026-11-01 12:00|2026-11-04 07:05|-"; applied != want {
		t.Errorf("applied = %s", applied)
	}
	if r.Objects[1]["pulled"] != nil || r.Objects[1]["applied"] != nil {
		t.Errorf("never is not null in json: %v", r.Objects[1])
	}
	if r.Objects[0]["pulled"] != "2026-11-06T06:00:00Z" {
		t.Errorf("json date = %v", r.Objects[0]["pulled"])
	}
	// A time in another zone is shown in UTC.
	cet := time.FixedZone("CET", 3600)
	r, _ = Build(TypeConfig, []Device{{Name: "a", Pulled: time.Date(2026, 11, 6, 8, 0, 0, 0, cet)}}, now.In(cet))
	if r.Rows[0][3] != "2026-11-06 07:00" || r.Generated.Location() != time.UTC {
		t.Errorf("row %v generated %v", r.Rows[0], r.Generated)
	}
}

func TestOldestData(t *testing.T) {
	r, _ := Build(TypeInventory, fixture(), now)
	if want := at(3, 22, 10); !r.OldestData.Equal(want) {
		t.Errorf("OldestData = %v, want %v", r.OldestData, want)
	}
	r, _ = Build(TypeInventory, []Device{{Name: "a"}, {Name: "b"}}, now)
	if !r.OldestData.IsZero() {
		t.Errorf("OldestData = %v for devices never pulled", r.OldestData)
	}
	r, _ = Build(TypeInventory, nil, now)
	if len(r.Rows) != 0 || r.Devices != 0 || !r.OldestData.IsZero() {
		t.Errorf("empty: %+v", r)
	}
}

func TestSoftwareAndConfig(t *testing.T) {
	r, _ := Build(TypeSoftware, fixture(), now)
	if got := strings.Join(r.Rows[2], "|"); got != "jsw1|junos|EX4300-48T|21.4R3-S5.4|2026-11-06 07:30" {
		t.Errorf("software row = %s", got)
	}
	r, _ = Build(TypeConfig, fixture(), now)
	if got := strings.Join(r.Rows[1], "|"); got != "fw1|lab|never|never|-" {
		t.Errorf("config row = %s", got)
	}
}

func TestDeviceMarshalNoNull(t *testing.T) {
	b, err := json.Marshal(Device{Name: "a"})
	if err != nil || !strings.Contains(string(b), `"members":[]`) {
		t.Errorf("%s %v", b, err)
	}
	b, err = json.Marshal(Member{ID: "1"})
	if err != nil || !strings.Contains(string(b), `"components":[]`) {
		t.Errorf("%s %v", b, err)
	}
}
