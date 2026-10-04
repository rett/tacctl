package model_test

import (
	"bufio"
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

const fixtures = "../../tests/fixtures/"

func load(t *testing.T, path string) (*store.Store, *model.Model) {
	t.Helper()
	s, m, err := model.LoadStore(path)
	if err != nil {
		t.Fatalf("load %s: %v", path, err)
	}
	return s, m
}

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestModelJSONGoldens is model.bats "store loader: each store fixture
// yields the golden model of its tacquito twin" and store_cli.bats "store
// show --json" (byte for byte): tests/fixtures/model/{minimal,multiscope}
// .json, plus the radius store's model as 0.1.16 printed it.
func TestModelJSONGoldens(t *testing.T) {
	for name, golden := range map[string]string{
		"store.minimal.yaml":    fixtures + "model/minimal.json",
		"store.multiscope.yaml": fixtures + "model/multiscope.json",
		"store.radius.yaml":     "testdata/store.radius.json",
	} {
		s, _ := load(t, fixtures+name)
		got, err := model.ShowJSON(s)
		if err != nil {
			t.Fatal(err)
		}
		if want := readFile(t, golden); got != string(want) {
			t.Errorf("%s: model JSON differs from %s:\n%s", name, golden, got)
		}
	}
}

// TestShowYAML pins 'store show' (YAML) against 0.1.16's output.
func TestShowYAML(t *testing.T) {
	for _, name := range []string{"multiscope", "radius"} {
		s, _ := load(t, fixtures+"store."+name+".yaml")
		got, err := model.ShowYAML(s)
		if err != nil {
			t.Fatal(err)
		}
		if want := readFile(t, "testdata/store."+name+".show.yaml"); !bytes.Equal(got, want) {
			t.Errorf("%s:\n%s", name, got)
		}
	}
}

// TestViewGoldens runs every view and accessor of testdata/views.list on
// four stores and compares with what the python of the 0.1.16 tag printed
// (testdata/views.<store>.txt: stdout, then the error line, then rc=).
// The stores: the multiscope and radius fixtures, a store whose names are
// out of order, and a hand-edited store that does not validate.
//
// The expected files were written once from the 0.1.16 tag, with
// lib/store.sh and lib/model.sh sourced: for each line '<get|view> <args>'
// of views.list, 'm=$(_store_python dump-store <store>); printf %s "$m" |
// _model_python <get|view> <args>' with stdout and stderr, then 'rc=$?'.
// store.radius.json and the *.show.yaml files are '_store_python show
// [json]' of the same model.
func TestViewGoldens(t *testing.T) {
	list := readFile(t, "testdata/views.list")
	for _, st := range []struct{ name, path string }{
		{"store.multiscope", fixtures + "store.multiscope.yaml"},
		{"store.radius", fixtures + "store.radius.yaml"},
		{"store.unsorted", "testdata/store.unsorted.yaml"},
		{"store.handedited", "testdata/store.handedited.yaml"},
	} {
		t.Run(st.name, func(t *testing.T) {
			s, m := load(t, st.path)
			var b strings.Builder
			sc := bufio.NewScanner(bytes.NewReader(list))
			for sc.Scan() {
				f := strings.Fields(sc.Text())
				if len(f) == 0 {
					continue
				}
				b.WriteString("== " + strings.Join(f, " ") + "\n")
				var lines []string
				var code int
				var err error
				if f[0] == "get" {
					lines, code, err = model.Get(s, f[1], f[2:]...)
				} else {
					lines, code, err = m.View(f[1], f[2:]...)
				}
				for _, l := range lines {
					b.WriteString(l + "\n")
				}
				if err != nil {
					b.WriteString(store.Report(err) + "\n")
					code = 1
				}
				b.WriteString("rc=" + string(rune('0'+code)) + "\n")
			}
			want := string(readFile(t, "testdata/views."+st.name+".txt"))
			if got := b.String(); got != want {
				gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
				for i := 0; i < len(gl) && i < len(wl); i++ {
					if gl[i] != wl[i] {
						t.Fatalf("first difference at line %d:\n got: %q\nwant: %q", i+1, gl[i], wl[i])
					}
				}
				t.Fatalf("length differs: %d vs %d lines", len(gl), len(wl))
			}
		})
	}
}
