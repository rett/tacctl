package radius_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
)

// TestContainerStoreRenders runs tests/containers/radius/make-store.py (the
// store of the container check: vendor attributes and tags on 127.0.0.0/8,
// an IPv6 prefix, a user named 007, real bcrypt hashes) and renders what it
// writes for both families. The conf holds no hash, so it must equal the
// committed golden of the snapshot exactly; the users file differs only in
// the hashes (they are salted per run). Needs python3 with bcrypt, as the
// container driver does; without it the snapshot test above still runs.
func TestContainerStoreRenders(t *testing.T) {
	ctx := context.Background()
	var r execx.Runner = execx.Real{}
	if res, err := r.Run(ctx, execx.Cmd{Name: "python3", Args: []string{"-c", "import bcrypt"}}); err != nil || res.Code != 0 {
		t.Skip("python3 with bcrypt is not available; TestGoldenContainerStore covers the committed snapshot")
	}
	dir := t.TempDir()
	res, err := r.Run(ctx, execx.Cmd{Name: "python3", Args: []string{"../../../tests/containers/radius/make-store.py", dir}})
	if err != nil || res.Code != 0 {
		t.Fatalf("make-store.py: %v %d %s", err, res.Code, res.Stderr)
	}
	m := loadModel(t, filepath.Join(dir, "store.yaml"))
	// The render id covers the salted hashes, so it differs from run to run.
	noID := func(text, rid string) string { return strings.ReplaceAll(text, rid, "<id>") }
	// The users file with the hashes taken out.
	noHash := func(text string) string {
		const key = `Crypt-Password := "`
		var keep []string
		for _, l := range lines(text) {
			if i := strings.Index(l, key); i >= 0 {
				j := strings.IndexByte(l[i+len(key):], '"')
				l = l[:i] + "Crypt-Password := <hash>" + l[i+len(key)+j+1:]
			}
			keep = append(keep, l)
		}
		return strings.Join(keep, "\n")
	}
	for _, family := range []string{"debian", "rhel"} {
		out := render(t, m, family)
		snapConf := read(t, "testdata/container."+family+".conf")
		snapID := renderID(t, snapConf)
		if got, want := noID(out.Conf, out.RenderID), noID(snapConf, snapID); got != want {
			t.Errorf("%s: conf differs from the snapshot's golden:\n%s", family, firstDiff(got, want))
		}
		if want := read(t, "testdata/container.dictionary"); out.Dictionary != want {
			t.Errorf("%s: dictionary differs", family)
		}
		got := noHash(noID(out.Users, out.RenderID))
		want := noHash(noID(read(t, "testdata/container."+family+".users"), snapID))
		if got != want {
			t.Errorf("%s: users file differs beyond the hashes:\n%s", family, firstDiff(got, want))
		}
	}
}
