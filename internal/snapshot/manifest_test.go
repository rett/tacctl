package snapshot

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// D256: the manifest names the session, the person and the command, with
// the keys sorted as json.dumps sorts them.
func TestManifestRecordsSessionUserAndCommand(t *testing.T) {
	now := time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC)
	got := string(Manifest(filepath.Join(t.TempDir(), "absent.json"), "v1", now, Who{SID: "k3x9a0bq", User: "alice", Command: "user add"}))
	want := "{\n  \"command\": \"user add\",\n  \"created\": \"2026-10-03T12:00:00Z\",\n  \"rendered\": {},\n  \"sid\": \"k3x9a0bq\",\n  \"tacctl_version\": \"v1\",\n  \"user\": \"alice\"\n}\n"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
	// An empty field is left out, not written empty.
	got = string(Manifest(filepath.Join(t.TempDir(), "absent.json"), "v1", now, Who{User: "alice"}))
	want = "{\n  \"created\": \"2026-10-03T12:00:00Z\",\n  \"rendered\": {},\n  \"tacctl_version\": \"v1\",\n  \"user\": \"alice\"\n}\n"
	if got != want {
		t.Fatalf("got  %q\nwant %q", got, want)
	}
}

func TestSnapshotManifestTakesWhoFromTheSnapshotter(t *testing.T) {
	e := newEnv(t)
	e.s.Who = func() Who { return Who{SID: "k3x9a0bq", User: "alice", Command: "group edit"} }
	id := e.take()
	data, err := os.ReadFile(filepath.Join(e.backups(), id, "manifest"))
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatal(err)
	}
	if m["sid"] != "k3x9a0bq" || m["user"] != "alice" || m["command"] != "group edit" {
		t.Fatalf("manifest %s", data)
	}
}
