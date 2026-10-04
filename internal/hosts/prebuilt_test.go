package hosts

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/execx/fake"
)

func TestImageForOS(t *testing.T) {
	for in, want := range map[string]string{
		"ID=neon\nID_LIKE=\"ubuntu debian\"\nVERSION_CODENAME=noble\nUBUNTU_CODENAME=noble": "docker.io/library/ubuntu:noble",
		"ID=ubuntu\nVERSION_CODENAME=jammy":                                                 "docker.io/library/ubuntu:jammy",
		"ID=debian\nVERSION_CODENAME=bookworm":                                              "docker.io/library/debian:bookworm",
		"ID=\"rocky\"\nID_LIKE=\"rhel centos fedora\"\nVERSION_ID=\"9.4\"":                  "docker.io/library/almalinux:9",
		"ID=ol\nVERSION_ID=8.10":                                                            "docker.io/library/almalinux:8",
		"ID=centos\nID_LIKE=rhel fedora\nVERSION_ID=10":                                     "docker.io/library/almalinux:10",
		"ID=fedora\nVERSION_CODENAME=\"\"":                                                  "",
		"ID=ubuntu\nVERSION_CODENAME=noble; rm -rf /":                                       "",
		"ID=debian\nVERSION_CODENAME=trixie\nVERSION_CODENAME=other":                        "docker.io/library/debian:trixie",
		"": "",
	} {
		if got := ImageForOS(in); got != want {
			t.Errorf("ImageForOS(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestPlatform(t *testing.T) {
	e, _, _ := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.On([]string{"ssh"}, execx.Result{Stdout: []byte("ID=debian\nVERSION_CODENAME=bookworm\n\nTACCTL_ARCH=aarch64\n")})
	img, arch, ok := e.Platform(context.Background(), "web1", "22", "/k")
	if !ok || img != "docker.io/library/debian:bookworm" || arch != "aarch64" {
		t.Errorf("%q %q %v", img, arch, ok)
	}
	if a := f.Argvs()[0]; !strings.HasSuffix(a, "-p 22 -i /k -T web1 "+probe) {
		t.Errorf("probe argv %s", a)
	}
	for _, res := range []execx.Result{{Code: 255}, {Stdout: []byte("ID=debian\n")}, {Stdout: []byte("TACCTL_ARCH=\"x86_64\"\n")}} {
		f := &fake.Runner{}
		e.Runner = f
		f.On([]string{"ssh"}, res)
		if _, _, ok := e.Platform(context.Background(), "web1", "", ""); ok {
			t.Errorf("%+v: ok", res)
		}
	}
	f = &fake.Runner{}
	e.Runner = f
	f.On([]string{"bash"}, execx.Result{Stdout: []byte("ID=ubuntu\nVERSION_CODENAME=noble\n\nTACCTL_ARCH=x86_64\n")})
	if img, _, ok := e.Platform(context.Background(), Local, "", ""); !ok || img != "docker.io/library/ubuntu:noble" || f.Argvs()[0] != "bash -c "+probe {
		t.Errorf("local: %q %v %q", img, ok, f.Argvs())
	}
}

func moduleTarGz(t *testing.T, names ...string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		if err := tw.WriteHeader(&tar.Header{Name: n, Mode: 0o644, Size: 3}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte("lib"))
	}
	_ = tw.Close()
	_ = gz.Close()
	return b.Bytes()
}

func TestPrebuilt(t *testing.T) {
	e, out, errb := testEnv(t)
	writeFile(t, e.Paths.Tarball(), "not really a tarball\n")
	f := &fake.Runner{}
	e.Runner = f
	e.AsUser = "admin"
	module := moduleTarGz(t, "pam_tacplus.so", "libtac.so.5.0.0")
	var containerfile string
	f.Func(func(c execx.Cmd) bool { return contains(c.Args, "build") }, func(c execx.Cmd) (execx.Result, error) {
		containerfile = readFile(t, c.Args[len(c.Args)-2])
		return execx.Result{}, nil
	})
	f.Func(func(c execx.Cmd) bool { return contains(c.Args, "run") }, func(c execx.Cmd) (execx.Result, error) {
		if b, _ := io.ReadAll(c.Stdin); string(b) != "not really a tarball\n" {
			t.Errorf("stdin %q", b)
		}
		_, _ = c.Stdout.Write(module)
		return execx.Result{}, nil
	})
	f.Func(func(c execx.Cmd) bool { return contains(c.Args, "inspect") }, func(execx.Cmd) (execx.Result, error) {
		return execx.Result{Stdout: []byte("sha256:feedface\n")}, nil
	})
	dir, err := e.Prebuilt(context.Background(), "docker.io/library/ubuntu:noble")
	if err != nil || dir != e.Paths.Builds()+"/ubuntu-noble-x86_64" {
		t.Fatalf("%q %v %q", dir, err, errb.String())
	}
	if containerfile != "FROM docker.io/library/ubuntu:noble\nRUN "+toolsCommand("x")+"\n" {
		t.Errorf("Containerfile %q", containerfile)
	}
	argvs := f.Argvs()
	if !strings.HasPrefix(argvs[0], "sudo -u admin -H podman build -q -t localhost/tacctl-build:ubuntu-noble-x86_64 -f ") {
		t.Errorf("build %s", argvs[0])
	}
	if argvs[1] != "sudo -u admin -H podman run --rm -i --network none --cap-drop all --security-opt no-new-privileges localhost/tacctl-build:ubuntu-noble-x86_64 sh -c "+buildScript {
		t.Errorf("run %s", argvs[1])
	}
	if f.Calls()[1].Dir != "/" {
		t.Error("podman as the user runs from /")
	}
	info := readFile(t, dir+"/info")
	want := "image=docker.io/library/ubuntu:noble\ndigest=sha256:feedface\narch=x86_64\nsource=" +
		fileSHA256(e.Paths.Tarball()) + "\nbuilt=2026-10-03T12:00:00Z\n"
	if info != want {
		t.Errorf("info %q", info)
	}
	if got := readFile(t, dir+"/module.tar.gz"); got != string(module) {
		t.Error("module")
	}
	for _, p := range []string{e.Paths.Builds(), dir} {
		if st, _ := os.Stat(p); st.Mode().Perm() != 0o755 {
			t.Errorf("%s mode %v", p, st.Mode())
		}
	}
	if !strings.Contains(out.String(), "Building pam_tacplus for ubuntu:noble in a container") || !strings.Contains(out.String(), "Cached in "+dir+".") {
		t.Errorf("out %q", out.String())
	}
	if ents, _ := os.ReadDir(os.TempDir()); len(ents) != 0 {
		t.Errorf("TMPDIR left %v", ents)
	}

	// Cached: no podman at all.
	f.Reset()
	out.Reset()
	if d2, err := e.Prebuilt(context.Background(), "docker.io/library/ubuntu:noble"); err != nil || d2 != dir || len(f.Calls()) != 0 || out.Len() != 0 {
		t.Errorf("cached: %v %q %q", err, f.Argvs(), out.String())
	}
	b := e.Builds()
	if len(b) != 1 || b[0] != (Build{Image: "ubuntu:noble", Arch: "x86_64", Built: "2026-10-03T12:00:00Z", Digest: "sha256:feedface"}) {
		t.Errorf("builds %+v", b)
	}
	if err := e.ClearBuilds(); err != nil || e.Builds() != nil {
		t.Errorf("clear %v", err)
	}
	if err := e.ClearBuilds(); err != nil {
		t.Error(err)
	}
}

func TestPrebuiltFailures(t *testing.T) {
	e, out, errb := testEnv(t)
	writeFile(t, e.Paths.Tarball(), "t\n")
	f := &fake.Runner{}
	e.Runner = f
	f.Missing("podman")
	if _, err := e.Prebuilt(context.Background(), "docker.io/library/almalinux:9"); !errors.Is(err, ErrFailed) ||
		!strings.Contains(out.String(), "podman is not installed here") {
		t.Errorf("no podman: %v %q", err, out.String())
	}

	f = &fake.Runner{}
	e.Runner = f
	f.OnFunc([]string{"podman", "build"}, func(c execx.Cmd) (execx.Result, error) {
		_, _ = io.WriteString(c.Stdout, "1\n2\n3\n4\n5\n6\n")
		return execx.Result{Code: 125}, nil
	})
	out.Reset()
	if _, err := e.Prebuilt(context.Background(), "docker.io/library/almalinux:9"); !errors.Is(err, ErrFailed) {
		t.Fatal(err)
	}
	if errb.String() != "2\n3\n4\n5\n6\n" || !strings.Contains(out.String(), "Could not prepare the build image for docker.io/library/almalinux:9.") {
		t.Errorf("build failed: %q %q", errb.String(), out.String())
	}
	if strings.Contains(f.Argvs()[0], "sudo") {
		t.Error("podman as tacctl's own user when AsUser is empty")
	}

	// The compile writes something that is not the two libraries.
	f = &fake.Runner{}
	e.Runner = f
	f.OnFunc([]string{"podman", "run"}, func(c execx.Cmd) (execx.Result, error) {
		_, _ = c.Stdout.Write(moduleTarGz(t, "pam_tacplus.so"))
		_, _ = io.WriteString(c.Stderr, "make: error\n")
		return execx.Result{}, nil
	})
	out.Reset()
	errb.Reset()
	if _, err := e.Prebuilt(context.Background(), "docker.io/library/almalinux:9"); !errors.Is(err, ErrFailed) {
		t.Fatal(err)
	}
	if errb.String() != "make: error\n" || !strings.Contains(out.String(), "The container build of pam_tacplus for docker.io/library/almalinux:9 failed.") {
		t.Errorf("run failed: %q %q", errb.String(), out.String())
	}
	if _, err := os.Stat(e.Paths.Builds()); !os.IsNotExist(err) {
		t.Error("a failed build left the cache dir")
	}
}

func TestHelpers(t *testing.T) {
	if got := string(lastLines([]byte("a\nb\nc\n"), 2)); got != "b\nc\n" {
		t.Errorf("lastLines %q", got)
	}
	if got := string(lastLines([]byte("a\nb"), 5)); got != "a\nb" {
		t.Errorf("lastLines %q", got)
	}
	if lastLines(nil, 3) != nil {
		t.Error("lastLines nil")
	}
	p := filepath.Join(t.TempDir(), "x")
	writeFile(t, p, "not gz")
	if tarNames(p) != "" || tarNames(p+"nope") != "" {
		t.Error("tarNames of junk")
	}
	writeFile(t, p, "a\n  gl_PREREQ_EXPLICIT_BZERO\nb\n")
	dropLine(p, "  gl_PREREQ_EXPLICIT_BZERO")
	if readFile(t, p) != "a\nb\n" {
		t.Errorf("dropLine %q", readFile(t, p))
	}
	dropLine(p+"nope", "x")
	if infoValues(p+"nope", "x") != "" || fileSHA256(p+"nope") != "" {
		t.Error("missing files")
	}
	if afterLastColon("[::]:49") != "49" || afterLastColon("49") != "49" {
		t.Error("afterLastColon")
	}
	if toolsCommand("docker.io/library/almalinux:9") == toolsCommand("docker.io/library/debian:12") {
		t.Error("tools command")
	}
}

func TestBuildTarball(t *testing.T) {
	e, out, errb := testEnv(t)
	f := &fake.Runner{}
	e.Runner = f
	f.Missing("gnulib-tool")
	if err := e.BuildTarball(context.Background()); !errors.Is(err, ErrFailed) || !strings.Contains(errb.String(), "'gnulib-tool' not found") {
		t.Fatalf("missing tool: %v %q", err, errb.String())
	}

	f = &fake.Runner{}
	e.Runner = f
	f.Fail([]string{"git", "clone"}, 128, "fatal")
	errb.Reset()
	if err := e.BuildTarball(context.Background()); !errors.Is(err, ErrFailed) || !strings.Contains(errb.String(), "Could not clone https://github.com/kravietz/pam_tacplus.git.") {
		t.Fatalf("clone: %v %q", err, errb.String())
	}

	f = &fake.Runner{}
	e.Runner = f
	f.On([]string{"git", "-C"}, execx.Result{Stdout: []byte("deadbeef\n")})
	errb.Reset()
	if err := e.BuildTarball(context.Background()); !errors.Is(err, ErrFailed) ||
		!strings.Contains(errb.String(), "Tag v1.7.0 resolved to deadbeef, expected "+PamTacplusCommit+". Refusing to build.") {
		t.Fatalf("commit: %v %q", err, errb.String())
	}

	// Success: every step runs in the clone; make dist leaves the tarball.
	f = &fake.Runner{}
	e.Runner = f
	f.On([]string{"git", "-C"}, execx.Result{Stdout: []byte(PamTacplusCommit + "\n")})
	f.OnFunc([]string{"git", "clone"}, func(c execx.Cmd) (execx.Result, error) {
		dst := c.Args[len(c.Args)-1]
		if err := os.MkdirAll(dst, 0o755); err != nil {
			return execx.Result{}, err
		}
		return execx.Result{}, os.WriteFile(dst+"/configure.ac", []byte("x\n  gl_PREREQ_EXPLICIT_BZERO\n"), 0o644)
	})
	f.OnFunc([]string{"gnulib-tool"}, func(execx.Cmd) (execx.Result, error) { return execx.Result{Code: 1}, nil })
	f.OnFunc([]string{"make", "dist"}, func(c execx.Cmd) (execx.Result, error) {
		if readFile(t, c.Dir+"/configure.ac") != "x\n" {
			t.Error("configure.ac not edited")
		}
		return execx.Result{}, os.WriteFile(c.Dir+"/pam_tacplus-1.7.0.tar.gz", []byte("tarball\n"), 0o600)
	})
	out.Reset()
	if err := e.BuildTarball(context.Background()); err != nil {
		t.Fatal(err)
	}
	if readFile(t, e.Paths.Tarball()) != "tarball\n" {
		t.Error("tarball")
	}
	if st, _ := os.Stat(e.Paths.Tarball()); st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v", st.Mode())
	}
	if !strings.Contains(out.String(), "Wrote "+e.Paths.Tarball()+" (sha256 "+fileSHA256(e.Paths.Tarball())+").") {
		t.Errorf("out %q", out.String())
	}

	// make dist "succeeds" without a tarball: install's complaint.
	f.OnFunc([]string{"make", "dist"}, func(execx.Cmd) (execx.Result, error) { return execx.Result{}, nil })
	errb.Reset()
	if err := e.BuildTarball(context.Background()); !errors.Is(err, ErrFailed) ||
		!strings.HasPrefix(errb.String(), "install: cannot stat '") || !strings.HasSuffix(errb.String(), "pam_tacplus-1.7.0.tar.gz': No such file or directory\n") {
		t.Errorf("no tarball: %v %q", err, errb.String())
	}

	// A failing last step: the log's tail and the error.
	f.OnFunc([]string{"make", "dist"}, func(c execx.Cmd) (execx.Result, error) {
		_, _ = io.WriteString(c.Stdout, "boom\n")
		return execx.Result{Code: 2}, nil
	})
	errb.Reset()
	if err := e.BuildTarball(context.Background()); !errors.Is(err, ErrFailed) || errb.String() != "boom\n\033[0;31m[ERROR]\033[0m Preparing the pam_tacplus tarball failed.\n" {
		t.Errorf("make dist: %v %q", err, errb.String())
	}
}

// Creating the Linux data directory under VarLib makes VarLib 0711 (users'
// ssh passes through it to VarLib/ssh/known_hosts); outside VarLib the
// parent is not touched.
func TestPathsMkDirVarLib(t *testing.T) {
	w := t.TempDir()
	p := Paths{Dir: filepath.Join(w, "var-lib", "linux"), VarLib: filepath.Join(w, "var-lib")}
	if err := p.mkDir(); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{p.VarLib: 0o711, p.Dir: 0o700} {
		if st, err := os.Stat(path); err != nil || st.Mode().Perm() != mode {
			t.Errorf("%s: %v %v, want %v", path, st.Mode().Perm(), err, mode)
		}
	}
	q := Paths{Dir: filepath.Join(w, "elsewhere", "linux"), VarLib: filepath.Join(w, "var-lib2")}
	if err := q.mkDir(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(q.VarLib); !os.IsNotExist(err) {
		t.Errorf("VarLib made for a Dir outside it: %v", err)
	}
}
