package devconf

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The chassis members a pull reads (D319) are kept in the record, not in the
// sections file: an older release's record decoder (encoding/json, no
// DisallowUnknownFields, in every release since the store exists) ignores a
// key it does not know, so the rollback has nothing to undo (a pull repeats
// the key).
func TestRecordMembersRoundTrip(t *testing.T) {
	dir := t.TempDir()
	st := Store{Records: filepath.Join(dir, "devices-config.json"), Dir: filepath.Join(dir, "device-config")}
	recs := NewRecords()
	members := []Member{
		{ID: "0", Role: "master", Model: "ex4300-48t", Serial: "SN000001", Release: "21.4R3", Status: "Prsnt", Priority: 129},
		{ID: "1", Role: "backup", Model: "ex4300-48t", Serial: "SN000002", Status: "Prsnt", Priority: 129,
			Components: []Component{{Kind: "fan", Slot: "0"}}},
	}
	recs.Put("jsw1", Record{Vendor: "juniper", Result: ResultOK, Members: members})
	// Put keeps a copy
	members[0].Serial = "changed"
	members[1].Components[0].Kind = "changed"
	if err := st.Save(recs); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(st.Records)
	if !strings.Contains(string(data), `"members"`) || !strings.Contains(string(data), "SN000002") || strings.Contains(string(data), "changed") {
		t.Fatalf("the record file:\n%s", data)
	}
	back, err := st.Load()
	if err != nil {
		t.Fatal(err)
	}
	rec, _ := back.Of("jsw1")
	if rec == nil || len(rec.Members) != 2 || rec.Members[0].Serial != "SN000001" || rec.Members[0].Priority != 129 ||
		rec.Members[1].Components[0].Kind != "fan" {
		t.Errorf("record %+v", rec)
	}
	// a record with no members writes no key, and reads back with none
	recs.Put("sw1", Record{Vendor: "cisco", Result: ResultOK})
	if err := st.Save(recs); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		Devices map[string]map[string]json.RawMessage `json:"devices"`
	}
	data, _ = os.ReadFile(st.Records)
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	if _, ok := raw.Devices["sw1"]["members"]; ok {
		t.Errorf("a record with no members writes the key: %s", data)
	}
	if _, ok := raw.Devices["jsw1"]["members"]; !ok {
		t.Errorf("a record with members lacks the key: %s", data)
	}
	back, err = st.Load()
	if err != nil {
		t.Fatal(err)
	}
	if rec, _ := back.Of("sw1"); rec == nil || rec.Members != nil {
		t.Errorf("a record made before 0.2.26: %+v", rec)
	}
	// the sections file does not carry them
	if err := st.SaveSections("jsw1", "juniper", nil); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(st.Dir, "jsw1.yaml")); strings.Contains(string(b), "SN000001") || strings.Contains(string(b), "members") {
		t.Errorf("the sections file:\n%s", b)
	}
}

// A record with members decodes into the shape of an older release's record
// (a struct that lacks the field) with no error, as that release's decoder
// does, and a record without the key decodes with Members nil.
func TestRecordMembersOlderDecoder(t *testing.T) {
	data, err := json.Marshal(Record{Vendor: "juniper", Result: ResultOK, Release: "21.4R3",
		Members: []Member{{ID: "0", Role: "master", Serial: "SN000001"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"members":[{"id":"0"`) || !strings.Contains(string(data), `"components":[]`) {
		t.Fatalf("the record: %s", data)
	}
	// the record of an older release: the fields it knows, none of members
	var old struct {
		Vendor  string `json:"vendor"`
		Result  string `json:"result"`
		Release string `json:"release"`
	}
	if err := json.Unmarshal(data, &old); err != nil || old.Vendor != "juniper" || old.Release != "21.4R3" {
		t.Errorf("an older decoder: %v %+v", err, old)
	}
	var none Record
	if err := json.Unmarshal([]byte(`{"vendor":"juniper","result":"ok","release":"21.4R3"}`), &none); err != nil || none.Members != nil {
		t.Errorf("a record with no key: %v %+v", err, none)
	}
	var back Record
	if err := json.Unmarshal(data, &back); err != nil || !reflect.DeepEqual(back.Members, []Member{{ID: "0", Role: "master", Serial: "SN000001", Components: []Component{}}}) {
		t.Errorf("the record read back: %v %+v", err, back.Members)
	}
}
