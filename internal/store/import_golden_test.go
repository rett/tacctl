package store_test

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/model"
	"github.com/rett/tacctl/internal/store"
)

const importData = "testdata/import/"

// TestLegacyLoaderGoldens runs the legacy loader ('dump-legacy') and
// ImportLoad ('import-load', strict and forced) on every case of
// testdata/import/expected/index and compares with what the python of the
// 0.1.16 tag printed (testdata/import/gen.sh): the cases written to reach
// each branch of legacy_load, every tacquito.* and legacy.* fixture, the
// two golden renders, and re-imports over an existing store.
func TestLegacyLoaderGoldens(t *testing.T) {
	index := string(readFile(t, importData+"expected/index"))
	dates, disabled := importData+"side/dates", importData+"side/disabled"
	path := func(p string) string {
		if p == "" {
			return ""
		}
		if rest, ok := strings.CutPrefix(p, "FIXTURES/"); ok {
			return fixtures + rest
		}
		return importData + p
	}
	for _, line := range strings.Split(strings.TrimSpace(index), "\n") {
		f := strings.Split(line, "\t")
		name, src, existing := f[0], path(f[1]), path(f[2])
		t.Run(name, func(t *testing.T) {
			var b strings.Builder
			b.WriteString("== dump-legacy\n")
			s, _, err := store.LegacyLoad(src, dates, disabled)
			rc := 0
			if err != nil {
				b.WriteString(store.Report(err) + "\n")
				rc = 1
			} else {
				js, err := model.StoreJSON(s)
				if err != nil {
					t.Fatal(err)
				}
				b.WriteString(js + "\n")
			}
			fmt.Fprintf(&b, "rc=%d\n", rc)
			for _, force := range []bool{false, true} {
				var stdout, stderr bytes.Buffer
				s, ok, err := store.ImportLoad(&stdout, &stderr, store.ImportLoadOptions{
					Src: src, DatesDir: dates, DisabledDir: disabled, Existing: existing, Force: force,
				})
				if err != nil {
					stderr.WriteString(store.Report(err) + "\n")
				}
				rc := 0
				if err != nil || !ok {
					rc = 1
				}
				fi := 0
				if force {
					fi = 1
				}
				fmt.Fprintf(&b, "== import-load force=%d\n%s-- stderr\n%src=%d\n", fi, stdout.String(), stderr.String(), rc)
				if rc == 0 {
					js, err := model.StoreJSON(s)
					if err != nil {
						t.Fatal(err)
					}
					b.WriteString(js + "\n")
				}
			}
			got := strings.ReplaceAll(b.String(), fixtures, "FIXTURES/")
			got = strings.ReplaceAll(got, importData, "")
			diffLines(t, got, string(readFile(t, importData+"expected/"+name+".out")))
		})
	}
}

// diffLines fails with the first line where got and want differ.
func diffLines(t *testing.T, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	gl, wl := strings.Split(got, "\n"), strings.Split(want, "\n")
	for i := 0; i < len(gl) && i < len(wl); i++ {
		if gl[i] != wl[i] {
			t.Fatalf("first difference at line %d:\n got: %s\nwant: %s", i+1, gl[i], wl[i])
		}
	}
	t.Fatalf("length differs: %d vs %d lines\n got:\n%s", len(gl), len(wl), got)
}
