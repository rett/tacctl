package execx

import (
	"context"
	"io"
	"os"
	"strings"
	"testing"
)

// filed is a writer that wraps a file, as ui.Plain does for a stream with
// its colour taken out.
type filed struct {
	io.Writer
	f *os.File
}

func (w filed) File() *os.File { return w.f }

// A program started with such a stream writes to the file itself (and so
// keeps the terminal it is attached to), not to a copy made by a pipe.
func TestRealStartGivesTheFileBehindAStream(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	w := filed{Writer: io.Discard, f: f}
	res, err := Real{}.Run(context.Background(), Cmd{
		Name: "sh", Args: []string{"-c", "readlink /proc/self/fd/1; echo hi"}, Stdout: w,
	})
	if err != nil || res.Code != 0 {
		t.Fatalf("run: %v %+v", err, res)
	}
	b, _ := os.ReadFile(f.Name())
	got := string(b)
	if !strings.HasPrefix(got, f.Name()+"\nhi\n") {
		t.Errorf("the child's stdout was not the file itself: %q", got)
	}
	// A wrapper with no file behind it is written to as it is.
	var sink strings.Builder
	if _, err := (Real{}).Run(context.Background(), Cmd{Name: "echo", Args: []string{"x"}, Stdout: filed{Writer: &sink}}); err != nil || sink.String() != "x\n" {
		t.Errorf("no file behind: %q %v", sink.String(), err)
	}
}
