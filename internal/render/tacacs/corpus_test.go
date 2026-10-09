package tacacs

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/conf"
	"github.com/rett/tacctl/internal/rendered"
	"github.com/rett/tacctl/internal/yamlpy"
)

// corpusCase is one line of testdata/corpus.jsonl (testdata/gen.py has
// the format): a store, a tacctl.yaml and the live files, and what the
// 0.1.16 render-live program made of them.
type corpusCase struct {
	Name    string            `json:"name"`
	Store   string            `json:"store"`
	Tacctl  *string           `json:"tacctl"`
	Log     string            `json:"log"`
	Files   map[string]string `json:"files"`
	RC      int               `json:"rc"`
	Status  string            `json:"status"`
	Stderr  string            `json:"stderr"`
	Config  *string           `json:"config"`
	Index   *string           `json:"index"`
	DropIns map[string]string `json:"dropins"`
}

func loadCorpus(t *testing.T) []corpusCase {
	t.Helper()
	f, err := os.Open(filepath.Join("testdata", "corpus.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	var out []corpusCase
	sc := bufio.NewScanner(f)
	sc.Buffer(nil, 1<<24)
	for sc.Scan() {
		var c corpusCase
		if err := json.Unmarshal(sc.Bytes(), &c); err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func corpusText(t *testing.T, s string) string {
	t.Helper()
	if name, ok := strings.CutPrefix(s, "@fixture:"); ok {
		return string(readFile(t, filepath.Join(fixDir, name)))
	}
	if name, ok := strings.CutPrefix(s, "@golden:"); ok {
		return string(readFile(t, filepath.Join(goldenDir, name)))
	}
	return s
}

// testRenderer is a Renderer over a case directory laid out as the
// generator lays it out.
func testRenderer(t *testing.T, w, logDir string) *Renderer {
	t.Helper()
	return &Renderer{
		Paths: Paths{
			Config:      filepath.Join(w, "etc", "tacquito.yaml"),
			StoreFile:   filepath.Join(w, "state", "store.yaml"),
			Rendered:    filepath.Join(w, "state", "rendered.json"),
			BackupDir:   filepath.Join(w, "state", "backups"),
			LogDir:      logDir,
			AcctLog:     logDir + "/accounting.log",
			OverrideDir: filepath.Join(w, "systemd", "tacquito.service.d"),
			UnitDir:     filepath.Join(w, "systemd"),
		},
		Conf:  conf.Load(filepath.Join(w, "state", "tacctl.yaml"), conf.DefaultBackends),
		Load:  DefaultLoader,
		Chown: func(string) {},
	}
}

// legacyRules are the shipped command rules of operator and readonly as
// 0.1.16 had them: the corpus was written by that release, and the
// shipped rules have changed since (0.2.3, docs/plans/0.2.3-baseline-design.md).
// The replay pins them, and renders the match regexes as stored (noWrap),
// so that everything else stays proven byte for byte; the wrapped output
// and the new defaults have their own goldens.
var legacyRules = map[string][]string{
	"operator": {"show", "ping", "traceroute", "terminal", "*|deny"},
	"readonly": {"show", "ping", "traceroute", "*|deny"},
}

// pinLegacyDefaults gives c the 0.1.16 rules of operator and readonly
// wherever the case's tacctl.yaml does not set its own.
func pinLegacyDefaults(c *conf.Config) {
	view := c.Merged()
	cur, _ := view.Get("commands")
	cm, _ := cur.(*yamlpy.Map)
	cmds := yamlpy.NewMap()
	if cm != nil {
		for k, v := range cm.All() {
			cmds.Set(k, v)
		}
	}
	for group, names := range legacyRules {
		if c.HasOverride("commands." + group) {
			continue
		}
		var rules []any
		for _, n := range names {
			name, action, _ := strings.Cut(n, "|")
			if action == "" {
				action = "permit"
			}
			rules = append(rules, yamlpy.NewMap("name", name, "action", action))
		}
		cmds.Set(group, rules)
	}
	view.Set("commands", cmds)
}

// sum256 is the hex SHA-256 of s, the checksum rendered.json records.
func sum256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// Every case of the corpus renders, stages its drop-ins and judges the
// live files exactly as 0.1.16 did: the same tacquito.yaml, the same
// drop-ins and index, the same word, the same refusal.
func TestCorpusMatchesBash(t *testing.T) {
	defer func() { noWrap = false }()
	cases := loadCorpus(t)
	var dropin string
	for _, c := range cases {
		if c.Name == "store.multiscope.yaml" {
			dropin = c.DropIns["default"]
		}
	}
	golden := string(readFile(t, filepath.Join(goldenDir, "tacquito.multiscope.rendered.yaml")))
	legacyGolden := string(readFile(t, filepath.Join("testdata", "tacquito.multiscope.0.1.16.yaml")))
	if len(cases) < 100 || dropin == "" {
		t.Fatalf("corpus too small (%d cases) or without the multiscope drop-in", len(cases))
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			w := t.TempDir()
			for _, d := range []string{"etc", "state/backups", "systemd/tacquito.service.d", "out"} {
				if err := os.MkdirAll(filepath.Join(w, d), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			writeFile(t, filepath.Join(w, "state", "store.yaml"), corpusText(t, c.Store))
			if c.Tacctl != nil {
				writeFile(t, filepath.Join(w, "state", "tacctl.yaml"), *c.Tacctl)
			}
			// A case whose expected file is the current golden renders with
			// the current rules; every other is 0.1.16's own output, and its
			// live '@CONFIG@' is 0.1.16's golden (testdata/).
			legacy := c.Config == nil || !strings.HasPrefix(*c.Config, "@golden:")
			config := golden
			if legacy {
				config = legacyGolden
			}
			for rel, text := range c.Files {
				text = strings.NewReplacer("@W@", w, "@CONFIG@", config, "@DROPIN@", dropin).Replace(text)
				if !legacy {
					// The recorded checksums are those of 0.1.16's golden;
					// the current golden has its own.
					for _, suffix := range []string{"", "# hand edit\n"} {
						text = strings.ReplaceAll(text, sum256(legacyGolden+suffix), sum256(golden+suffix))
					}
				}
				writeFile(t, filepath.Join(w, rel), text)
			}
			r := testRenderer(t, w, c.Log)
			noWrap = legacy
			if legacy {
				pinLegacyDefaults(r.Conf)
			}
			out, units := filepath.Join(w, "out", "tacquito.yaml"), filepath.Join(w, "out", "units")
			status, err := r.RenderLive(out, units)
			leftovers, _ := filepath.Glob(filepath.Join(w, "out", ".tacquito.*"))
			if len(leftovers) > 0 {
				t.Fatalf("temp files left behind: %v", leftovers)
			}
			if c.RC != 0 {
				if err == nil {
					t.Fatalf("rendered (%s); 0.1.16 failed with %q", status, c.Stderr)
				}
				if got := strings.ReplaceAll(rendered.Report(err)+"\n", w, "@W@"); got != c.Stderr {
					t.Fatalf("message\n got: %q\nwant: %q", got, c.Stderr)
				}
				if _, statErr := os.Stat(out); c.Config == nil && statErr == nil {
					t.Fatal("a config was written although the render failed")
				}
				return
			}
			if err != nil {
				t.Fatalf("failed: %s", rendered.Report(err))
			}
			// The importer reads the render back with nothing to report.
			if back, err := DefaultLoader(out); err != nil || len(back.Errors)+len(back.Dropped) > 0 {
				t.Fatalf("importer: %v %v", back, err)
			}
			if status != c.Status {
				t.Fatalf("status %q, want %q", status, c.Status)
			}
			diffText(t, readFile(t, out), []byte(corpusText(t, *c.Config)), "tacquito.yaml")
			if st, err := os.Stat(out); err != nil || st.Mode().Perm() != 0o640 {
				t.Fatalf("mode of the render: %v %v", st, err)
			}
			if c.Index == nil {
				t.Fatal("corpus case without an index")
			}
			idx := strings.ReplaceAll(string(readFile(t, filepath.Join(units, IndexName))), w, "@W@")
			if idx != *c.Index {
				t.Fatalf("index\n got: %q\nwant: %q", idx, *c.Index)
			}
			for name, want := range c.DropIns {
				diffText(t, readFile(t, filepath.Join(units, name+".conf")), []byte(want), name+".conf")
			}
			entries, _ := os.ReadDir(units)
			if len(entries) != len(c.DropIns)+1 {
				t.Fatalf("units dir holds %d files, want %d", len(entries), len(c.DropIns)+1)
			}
		})
	}
}
