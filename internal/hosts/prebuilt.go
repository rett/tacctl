package hosts

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/rett/tacctl/internal/execx"
	"github.com/rett/tacctl/internal/ui"
)

// The container build of pam_tacplus ('host enroll' for a tacplus host):
// the module is compiled here, in a rootless podman container of the host's
// OS release, cached under LINUX_BUILDS_DIR/<image>-<arch> and shipped in
// the installer, so the host compiles nothing. The tools image (base +
// compiler) is built with network access; the compile itself runs with
// none, reading the source on stdin and writing the two libraries to
// stdout.

// toolsCommand is the RUN line of the tools image.
func toolsCommand(image string) string {
	if strings.Contains(image, "/almalinux:") {
		return "dnf install -y -q gcc make pam-devel tar gzip >/dev/null && dnf clean all >/dev/null"
	}
	return "apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends gcc make libc6-dev libpam0g-dev >/dev/null && rm -rf /var/lib/apt/lists/*"
}

// buildScript runs inside the container (sh -c).
const buildScript = `set -e; w=$(mktemp -d); cd "$w"; tar --no-same-owner -xzf -; cd pam_tacplus-*/
        ma=$(gcc -print-multiarch); if [ -n "$ma" ]; then lib=/usr/lib/$ma; else lib=/usr/lib64; fi
        ./configure --prefix=/usr --libdir="$lib" --enable-pamdir="$lib/security" >&2
        make >&2; make install DESTDIR="$w/stage" >&2
        mkdir "$w/out"; cp "$w/stage$lib/libtac.so.5.0.0" "$w/stage$lib/security/pam_tacplus.so" "$w/out/"
        tar -C "$w/out" -czf - libtac.so.5.0.0 pam_tacplus.so`

// podman is _linux_podman: podman as the user who invoked sudo (rootless,
// from /), never as root unless tacctl itself was started by root.
func (e *Env) podman(args ...string) execx.Cmd {
	c := execx.Cmd{Name: "podman", Args: args}
	if e.AsUser != "" {
		c.AsUser, c.Dir = e.AsUser, "/"
	}
	return c
}

// lastLines is 'tail -<n>' of data.
func lastLines(data []byte, n int) []byte {
	s := string(data)
	trail := strings.HasSuffix(s, "\n")
	lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
	if s == "" {
		return nil
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := strings.Join(lines, "\n")
	if trail {
		out += "\n"
	}
	return []byte(out)
}

// tarNames is "tar -tzf <file> | sort | paste -sd' '": "" when the file is
// not a gzipped tar.
func tarNames(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer func() { _ = f.Close() }()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return ""
	}
	tr := tar.NewReader(gz)
	var names []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return ""
		}
		names = append(names, h.Name)
	}
	sort.Strings(names)
	return strings.Join(names, " ")
}

// BuildKey is the cache key of an image on this machine:
// <image name>-<tag>-<uname -m>.
func (e *Env) BuildKey(image string) string {
	return strings.ReplaceAll(filepath.Base(image), ":", "-") + "-" + e.machine()
}

// Prebuilt is linux_prebuilt_for: the directory of a pam_tacplus module
// built for image on this machine's architecture, building it in a
// container on first use. On failure the reason is printed (as warnings)
// and ErrFailed returned; the caller falls back to compiling on the host.
func (e *Env) Prebuilt(ctx context.Context, image string) (string, error) {
	if _, err := e.Runner.LookPath("podman"); err != nil {
		e.Out.Warn("podman is not installed here (apt install podman uidmap).")
		return "", ErrFailed
	}
	key := e.BuildKey(image)
	dir := e.Paths.Builds() + "/" + key
	srcSHA := fileSHA256(e.Paths.Tarball())
	if st, err := os.Stat(dir + "/module.tar.gz"); err == nil && st.Size() > 0 && infoValues(dir+"/info", "source") == srcSHA {
		return dir, nil
	}

	name := image[strings.LastIndexByte(image, '/')+1:]
	e.Out.InfoE("Building pam_tacplus for " + name + " in a container (once per OS release; takes a minute or two)...")
	tools := "localhost/tacctl-build:" + key
	work, err := TempDir()
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(work) }()
	if err := os.Chmod(work, 0o755); err != nil {
		return "", err
	}
	// The Containerfile goes through a file, not stdin: podman reopens
	// /dev/stdin by path, which a pipe owned by root does not allow.
	if err := os.Mkdir(work+"/ctx", 0o755); err != nil {
		return "", err
	}
	if err := os.Chmod(work+"/ctx", 0o755); err != nil {
		return "", err
	}
	if err := replaceFile(work+"/ctx/Containerfile", []byte("FROM "+image+"\nRUN "+toolsCommand(image)+"\n"), 0o644); err != nil {
		return "", err
	}
	logFile, err := os.Create(work + "/log")
	if err != nil {
		return "", err
	}
	c := e.podman("build", "-q", "-t", tools, "-f", work+"/ctx/Containerfile", work+"/ctx")
	c.Stdout, c.Stderr = logFile, logFile
	res, err := e.Runner.Run(ctx, c)
	_ = logFile.Close()
	if interrupted(ctx) {
		return "", ui.ErrInterrupted
	}
	if err != nil || res.Code != 0 {
		log, _ := os.ReadFile(work + "/log")
		_, _ = e.Out.Stderr.Write(lastLines(log, 5))
		e.Out.WarnE("Could not prepare the build image for " + image + ".")
		return "", ErrFailed
	}

	src, err := os.Open(e.Paths.Tarball())
	if err != nil {
		return "", err
	}
	module, err := os.Create(work + "/module.tar.gz")
	if err != nil {
		_ = src.Close()
		return "", err
	}
	logFile, err = os.Create(work + "/log")
	if err != nil {
		_ = src.Close()
		_ = module.Close()
		return "", err
	}
	c = e.podman("run", "--rm", "-i", "--network", "none", "--cap-drop", "all", "--security-opt", "no-new-privileges",
		tools, "sh", "-c", buildScript)
	c.Stdin, c.Stdout, c.Stderr = src, module, logFile
	res, err = e.Runner.Run(ctx, c)
	_ = src.Close()
	_ = module.Close()
	_ = logFile.Close()
	if interrupted(ctx) {
		return "", ui.ErrInterrupted
	}
	if err != nil || res.Code != 0 || tarNames(work+"/module.tar.gz") != "libtac.so.5.0.0 pam_tacplus.so" {
		log, _ := os.ReadFile(work + "/log")
		_, _ = e.Out.Stderr.Write(lastLines(log, 20))
		e.Out.WarnE("The container build of pam_tacplus for " + image + " failed.")
		return "", ErrFailed
	}

	if err := e.Paths.mkDir(); err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, d := range []string{e.Paths.Builds(), dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			return "", err
		}
	}
	data, err := os.ReadFile(work + "/module.tar.gz")
	if err != nil {
		return "", err
	}
	if err := replaceFile(dir+"/module.tar.gz", data, 0o644); err != nil {
		return "", err
	}
	inspect := e.podman("image", "inspect", "--format", "{{.Digest}}", image)
	inspect.Stderr = io.Discard
	ires, _ := e.Runner.Run(ctx, inspect)
	info := "image=" + image + "\n" +
		"digest=" + strings.TrimRight(string(ires.Stdout), "\n") + "\n" +
		"arch=" + e.machine() + "\n" +
		"source=" + srcSHA + "\n" +
		"built=" + e.now().UTC().Format("2006-01-02T15:04:05Z") + "\n"
	if err := os.WriteFile(dir+"/info", []byte(info), 0o600); err != nil {
		return "", err
	}
	e.Out.InfoE("Cached in " + dir + ".")
	return dir, nil
}

// Build is one cached module, as 'config linux builds' lists it.
type Build struct {
	Image, Arch, Built, Digest string
}

// Builds are the cached modules: every directory of the build cache with
// an info file, in name order.
func (e *Env) Builds() []Build {
	ents, err := os.ReadDir(e.Paths.Builds())
	if err != nil {
		return nil
	}
	var names []string
	for _, d := range ents {
		names = append(names, d.Name())
	}
	sort.Strings(names)
	var out []Build
	for _, n := range names {
		if strings.HasPrefix(n, ".") {
			continue
		}
		p := e.Paths.Builds() + "/" + n
		if st, err := os.Stat(p); err != nil || !st.IsDir() || !isRegular(p+"/info") {
			continue
		}
		var base []string
		for _, l := range strings.Split(infoValues(p+"/info", "image"), "\n") {
			base = append(base, l[strings.LastIndexByte(l, '/')+1:])
		}
		out = append(out, Build{
			Image:  strings.Join(base, "\n"),
			Arch:   infoValues(p+"/info", "arch"),
			Built:  infoValues(p+"/info", "built"),
			Digest: infoValues(p+"/info", "digest"),
		})
	}
	return out
}

// ClearBuilds removes the build cache ('rm -rf').
func (e *Env) ClearBuilds() error {
	err := os.RemoveAll(e.Paths.Builds())
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}
