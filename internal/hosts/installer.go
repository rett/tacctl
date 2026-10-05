package hosts

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/rett/tacctl/internal/assets"
	"github.com/rett/tacctl/internal/backend"
	"github.com/rett/tacctl/internal/shellquote"
)

// Script is the content of a per-scope client installer
// (linux_write_install_script): a header of shell assignments, then
// config/linux/client-install.sh verbatim, then the pam_tacplus source
// tarball after __TARBALL__ and the prebuilt module after __PREBUILT__,
// both base64 (the script reads them back through $0). Up to TAC_USERS the
// bytes are 0.1.16's for the same inputs (installer_test.go holds them
// against a header written by 0.1.16); the lines after it are the account
// lifecycle of 0.2.1 (ScriptProtocol).
type Script struct {
	Scope    string
	Method   string // tacplus or radius
	Server   string
	Port     string
	AcctPort string // radius only
	Secret   string
	Users    string // "name:tier:uid" lines, joined by newlines
	// Range is the server's UID range (TAC_UID_FIRST, TAC_UID_LAST; the
	// zero Range is DefaultRange), Previous the ranges the UID file was
	// numbered for before (TAC_UID_PREVIOUS): the host renumbers the
	// accounts tacctl created there into Range.
	Range    Range
	Previous []Range
	// Inactive are users of the scope that get no login now (disabled, the
	// accounting sink, a group without priv-lvl, a UID outside the range),
	// joined by newlines: a host expires their accounts, never deletes them.
	Inactive string
	// RemoveHomes names the removed users whose home directory the host
	// deletes with the account, space-separated; "*" is every one of them
	// (--remove-home). Any other removed user's home is kept.
	RemoveHomes string
	Generated   time.Time
	// Tarball is the pam_tacplus source tarball to embed, "" for none (an
	// accounts-only or radius script).
	Tarball string
	// Prebuilt is a directory of the build cache whose module.tar.gz is
	// embedded as well ("" for none; only with Tarball).
	Prebuilt string
	// Body is client-install.sh; nil means the embedded copy.
	Body []byte
}

// ScriptProtocol is the contract between the header and client-install.sh
// (TAC_PROTOCOL): 2 was the 0.2.1 account lifecycle (TAC_INACTIVE,
// TAC_REMOVE_HOMES, removed users deleted, UIDs of one range only); 3 adds
// the range to the header (TAC_UID_FIRST, TAC_UID_LAST) with the ranges the
// server numbered for before (TAC_UID_PREVIOUS), whose accounts the host
// renumbers. The body refuses a header of another protocol, and a body of
// an earlier release has no TAC_PROTOCOL check but never sees this header
// (both are written into one file by one tacctl).
const ScriptProtocol = "3"

// fileSHA256 is "sha256sum <f> | awk '{print $1}'": "" when the file
// cannot be read.
func fileSHA256(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// infoValues is "sed -n 's/^<key>=//p' <file>" captured by '$(...)': the
// values of every <key>= line, joined by newlines, trailing newlines
// dropped ("" when the file cannot be read).
func infoValues(path, key string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var vals []string
	for _, l := range awkRecords(string(data)) {
		if v, ok := strings.CutPrefix(l, key+"="); ok {
			vals = append(vals, v)
		}
	}
	return strings.TrimRight(strings.Join(vals, "\n"), "\n")
}

// Header is the script up to client-install.sh.
func (s Script) Header() string {
	var b strings.Builder
	q := func(name, v string) { b.WriteString(name + "=" + shellquote.Q(v) + "\n") }
	b.WriteString("#!/usr/bin/env bash\n")
	b.WriteString("# tacctl Linux client installer for scope '" + s.Scope + "'. Generated " +
		s.Generated.UTC().Format("2006-01-02T15:04:05Z") + ".\n")
	b.WriteString("# CONTAINS THE SCOPE'S SHARED SECRET. Delete after use.\n")
	b.WriteString("set -euo pipefail\n")
	b.WriteString("umask 077\n")
	q("TAC_METHOD", s.Method)
	q("TAC_SERVER", s.Server)
	q("TAC_PORT", s.Port)
	if s.Method == Radius {
		q("TAC_ACCT_PORT", s.AcctPort)
	}
	q("TAC_SECRET", s.Secret)
	q("TAC_SCOPE", s.Scope)
	if s.Tarball != "" {
		q("TARBALL_SHA256", fileSHA256(s.Tarball))
		if s.Prebuilt != "" {
			q("PREBUILT_SHA256", fileSHA256(s.Prebuilt+"/module.tar.gz"))
			q("PREBUILT_FOR", infoValues(s.Prebuilt+"/info", "image"))
		}
	}
	q("TAC_USERS", s.Users)
	q("TAC_INACTIVE", s.Inactive)
	q("TAC_REMOVE_HOMES", s.RemoveHomes)
	r := s.Range
	if r.IsZero() {
		r = DefaultRange
	}
	q("TAC_UID_FIRST", strconv.Itoa(r.Min))
	q("TAC_UID_LAST", strconv.Itoa(r.Max))
	prev := make([]string, len(s.Previous))
	for i, p := range s.Previous {
		prev[i] = p.String()
	}
	q("TAC_UID_PREVIOUS", strings.Join(prev, " "))
	q("TAC_PROTOCOL", ScriptProtocol)
	return b.String()
}

// Bytes is the whole script.
func (s Script) Bytes() []byte {
	var b bytes.Buffer
	b.WriteString(s.Header())
	body := s.Body
	if body == nil {
		body = assets.LinuxInstallScript
	}
	b.Write(body)
	if s.Tarball != "" {
		b.WriteString("__TARBALL__\n")
		writeBase64(&b, s.Tarball)
		if s.Prebuilt != "" {
			b.WriteString("__PREBUILT__\n")
			writeBase64(&b, s.Prebuilt+"/module.tar.gz")
		}
	}
	return b.Bytes()
}

// writeBase64 is 'base64 <file>': lines of 76 characters, each ending in a
// newline; nothing for an empty or unreadable file.
func writeBase64(w io.Writer, path string) {
	data, _ := os.ReadFile(path)
	enc := base64.StdEncoding.EncodeToString(data)
	for len(enc) > 0 {
		n := min(76, len(enc))
		_, _ = io.WriteString(w, enc[:n]+"\n")
		enc = enc[n:]
	}
}

// ScriptRequest is what linux_write_install_script is called with, the
// model and listener reads done by the caller.
type ScriptRequest struct {
	Scope, Server, Method string
	// Output is where the script goes. Temp marks it as tacctl's own
	// scratch file; otherwise it is a path the operator named, written as
	// 'install -m 0600' does (into it when it is a directory).
	Output string
	Temp   bool
	// AccountsOnly leaves the tarball out ('host sync').
	AccountsOnly bool
	// Prebuilt is a build-cache directory to embed ("" for none).
	Prebuilt string
	// Secret is the scope's secret, "" when it has none.
	Secret string
	// Listeners are the method's backend's listeners in effect.
	Listeners []backend.Listener
	// Rows is the scope's linux-users view ('name|priv_lvl').
	Rows []string
	// Inactive are the scope's members that get no login now (disabled,
	// the accounting sink): their accounts are expired, not deleted.
	Inactive []string
	// RemoveHomes are the removed users whose home directories go with
	// their accounts; RemoveAllHomes is --remove-home (every one).
	RemoveHomes    []string
	RemoveAllHomes bool
}

// ScriptResult is what the script was written with (LINUX_SCRIPT_USERS,
// LINUX_SCRIPT_PORT).
type ScriptResult struct {
	Users string
	Port  string
}

var (
	reSecretSafe = regexp.MustCompile(`^[A-Za-z0-9_.+/=-]+$`)
	reServer     = regexp.MustCompile(`^[A-Za-z0-9.:-]+$`)
)

// WriteScript is linux_write_install_script: the checks (tarball, secret,
// server), the port from the listeners, the users (UIDs assigned), and the
// script written with mode 0600. A failed check is printed and ErrFailed
// returned. A failed write to an operator-named path prints install's
// complaint and is not a failure: 0.1.16 returned the status of the
// 'rm -f' after its 'install'.
func (e *Env) WriteScript(req ScriptRequest) (ScriptResult, error) {
	method := req.Method
	if method == "" {
		method = Tacplus
	}
	embed := !req.AccountsOnly && method == Tacplus
	tarball := e.Paths.Tarball()
	if embed && !isRegular(tarball) {
		e.Out.ErrorE("pam_tacplus tarball not found. Run 'tacctl config linux build' first.")
		return ScriptResult{}, ErrFailed
	}
	where := "on a PAM line"
	if method == Radius {
		where = "in pam_radius_auth's server file"
	}
	if !reSecretSafe.MatchString(req.Secret) || strings.HasPrefix(req.Secret, "REPLACE") {
		e.Out.ErrorE("Scope '" + req.Scope + "' has a secret that cannot be written " + where + " (or a placeholder).")
		e.Out.ErrorE("Regenerate it: tacctl scope secret " + req.Scope + " generate")
		return ScriptResult{}, ErrFailed
	}
	if !reServer.MatchString(req.Server) {
		e.Out.ErrorE("Invalid server address '" + req.Server + "'. Give a bare IPv4/IPv6 address or hostname (the port comes from 'tacctl config listen').")
		return ScriptResult{}, ErrFailed
	}

	listen, acctPort := "", ""
	for _, l := range req.Listeners {
		switch {
		case method == Radius && l.Name == "auth":
			listen = l.Address
		case method == Radius && l.Name == "acct":
			acctPort = afterLastColon(l.Address)
		case method != Radius && l.Name == "default":
			listen = l.Address
		}
	}
	if listen == "" {
		listen = ":49"
		if method == Radius {
			listen = ":1812"
		}
	}
	port := afterLastColon(listen)

	users, keep, err := e.ScopeUsers(req.Rows)
	if err != nil {
		return ScriptResult{}, err
	}
	_, previous, err := e.UIDs().Recorded()
	if err != nil {
		return ScriptResult{}, err
	}
	homes := strings.Join(req.RemoveHomes, " ")
	if req.RemoveAllHomes {
		homes = "*"
	}
	s := Script{
		Scope: req.Scope, Method: method, Server: req.Server, Port: port, AcctPort: acctPort,
		Secret: req.Secret, Users: users, Generated: e.now(), Range: e.rng(), Previous: previous,
		Inactive: strings.Join(linuxNames(append(append([]string(nil), req.Inactive...), keep...)), "\n"), RemoveHomes: homes,
	}
	if embed {
		s.Tarball = tarball
		s.Prebuilt = req.Prebuilt
	}
	data := s.Bytes()
	res := ScriptResult{Users: users, Port: port}
	if req.Temp {
		return res, replaceFile(req.Output, data, 0o600)
	}
	if target, err := installAs(tempName(os.TempDir()), data, req.Output, 0o600); err != nil {
		var ie *InstallError
		if !errors.As(err, &ie) {
			return res, err
		}
		e.Out.Error("Cannot write " + target + ": " + strerror(ie.Err))
		return res, ErrFailed
	}
	return res, nil
}

// linuxNames are the names of names that can be Linux accounts, in order,
// each once.
func linuxNames(names []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, n := range names {
		if LinuxName(n) && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// afterLastColon is ${addr##*:}.
func afterLastColon(addr string) string {
	if i := strings.LastIndexByte(addr, ':'); i >= 0 {
		return addr[i+1:]
	}
	return addr
}

// isRegular is '[[ -f <path> ]]'.
func isRegular(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode().IsRegular()
}

// WriteRemoveScript is 'config linux remove-script': client-remove.sh
// copied to output with mode 0644 ('install -m 0644', into output when it
// is a directory). A failed install is an *InstallError carrying the line
// install prints.
func WriteRemoveScript(output string) error {
	_, err := installAs("client-remove.sh", assets.LinuxRemoveScript, output, 0o644)
	return err
}

// WriteRemoveScriptTo writes client-remove.sh to a scratch file of
// tacctl's own (mode 0600), the copy 'host unenroll' pushes.
func WriteRemoveScriptTo(path string) error {
	return replaceFile(path, assets.LinuxRemoveScript, 0o600)
}
