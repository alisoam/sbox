package bwrap

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"sbox/internal/cliutil"
	"sbox/internal/sandbox"
	"sbox/internal/seccomp"
)

func TestParseCaps(t *testing.T) {
	modern := `
      --add-seccomp-fd FD      Load seccomp filter from fd
      --bind-fd FD DEST        Bind mount host fd
      --ro-bind-fd FD DEST     Read-only bind mount host fd
      --disable-userns         Disable nested user namespaces
      --assert-userns-disabled Assert nested user namespaces are disabled`
	legacy := `
      --seccomp FD             Load seccomp filter from fd (deprecated)`
	for _, tc := range []struct {
		name string
		text string
		want sandbox.Caps
	}{
		{"modern", modern, sandbox.Caps{BindFD: true, AddSeccompFD: true, DisableUserns: true}},
		{"legacy 0.4.1", legacy, sandbox.Caps{LegacySeccomp: true}},
		{"legacy + bind-fd backport", legacy + "\n      --bind-fd FD D\n      --ro-bind-fd FD D",
			sandbox.Caps{LegacySeccomp: true, BindFD: true}},
		{"empty", "", sandbox.Caps{}},
		{"--bind-fds is not --bind-fd", "--bind-fds FD", sandbox.Caps{}},
		{"--bind-fd2 is not --bind-fd", "--bind-fd2 FD", sandbox.Caps{}},
		{"prefixed --bind-fd is not an option", "x--bind-fd FD", sandbox.Caps{}},
		{"--ro-bind-fd alone is not enough", "--ro-bind-fd FD D", sandbox.Caps{}},
		{"--bind-fd alone is not enough", "--bind-fd FD D", sandbox.Caps{}},
		{"assert without disable", "--disable-userns\n--assert-userns-disabled-x", sandbox.Caps{}},
		{"disable without assert", "--disable-userns", sandbox.Caps{}},
		{"adjacent dash breaks the word", "--userns-disable --assert-userns-disabled", sandbox.Caps{}},
		{"option list context (leading spaces, trailing newline)",
			"  --add-seccomp-fd FD\n  --seccomp FD\n", sandbox.Caps{AddSeccompFD: true}},
		{"overlay support", "--overlay-src SRC\n--overlay RWSRC WORKDIR DEST", sandbox.Caps{Overlay: true}},
		{"tmp-overlay support", "--overlay-src SRC\n--tmp-overlay DEST", sandbox.Caps{TmpOverlay: true}},
		{"tmp-overlay requires source", "--tmp-overlay DEST", sandbox.Caps{}},
		{"tmp-overlay suffix is not support", "--overlay-src SRC\n--tmp-overlay2 DEST", sandbox.Caps{}},
		{"--overlay alone is not enough", "--overlay RWSRC WORKDIR DEST", sandbox.Caps{}},
		{"--overlay-src alone is not enough", "--overlay-src SRC", sandbox.Caps{}},
		{"--overlay2 is not --overlay", "--overlay-src S\n--overlay2 A B C", sandbox.Caps{}},
		{"ro-bind-data", "--ro-bind-data FD DEST", sandbox.Caps{BindData: true}},
		{"--ro-bind-data2 is not --ro-bind-data", "--ro-bind-data2 FD DEST", sandbox.Caps{}},
		{"--bind-data is not --ro-bind-data", "--bind-data FD DEST", sandbox.Caps{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ParseCaps(tc.text); got != tc.want {
				t.Errorf("ParseCaps = %+v, want %+v", got, tc.want)
			}
		})
	}
}

// fakeBwrap writes an executable shim to dir/bin/bwrap-like name; body
// runs with the shim's argv.
func fakeBwrap(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "bwrap")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProbeWithShim(t *testing.T) {
	shim := fakeBwrap(t, `echo "--add-seccomp-fd FD"
echo "--bind-fd FD DEST --ro-bind-fd FD DEST --disable-userns --assert-userns-disabled" >&2`)
	p := New(shim)
	caps, err := p.Probe()
	if err != nil {
		t.Fatal(err)
	}
	want := sandbox.Caps{BindFD: true, AddSeccompFD: true, DisableUserns: true}
	if caps != want {
		t.Errorf("caps = %+v, want %+v (stderr must count too)", caps, want)
	}
	if p.Caps != want {
		t.Errorf("Probe did not fill the provider's caps: %+v", p.Caps)
	}

	// a failing bwrap --help ⇒ unknown caps, loudly
	broken := fakeBwrap(t, "exit 3")
	p2 := New(broken)
	caps2, err := p2.Probe()
	if err == nil || caps2 != (sandbox.Caps{}) {
		t.Errorf("broken probe: caps = %+v err = %v; want zero caps + error", caps2, err)
	}

	// a missing binary ditto
	p3 := New(filepath.Join(t.TempDir(), "no-such-bwrap"))
	if caps3, err := p3.Probe(); err == nil || caps3 != (sandbox.Caps{}) {
		t.Errorf("missing binary: caps = %+v err = %v", caps3, err)
	}
	// the shim records every invocation's argv; after TWO Probe() calls
	// it must have been invoked once, as exactly "bwrap --help" — the
	// capability cache means no second probe run
	argvFile := filepath.Join(t.TempDir(), "argv")
	recording := fakeBwrap(t, `printf '%s\n' "$@" >> `+argvFile+`
echo "--add-seccomp-fd"`)
	pp := New(recording)
	if _, err := pp.Probe(); err != nil {
		t.Fatal(err)
	}
	if _, err := pp.Probe(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "--help\n" {
		t.Errorf("probe invocations = %q; want exactly one --help (Probe must cache)", string(got))
	}
}

func TestUsernsProbe(t *testing.T) {
	argvFile := filepath.Join(t.TempDir(), "argv")
	recording := fakeBwrap(t, `printf '%s\n' "$@" > `+argvFile)
	p := New(recording)
	if !p.UsernsProbe(false) {
		t.Fatal("recording shim exits 0; probe must report ok")
	}
	want := "--unshare-all\n--die-with-parent\n--new-session\n--as-pid-1\n" +
		"--unshare-user\n--disable-userns\n--assert-userns-disabled\n" +
		"--ro-bind\n/\n/\n--\n/bin/true\n"
	if got, _ := os.ReadFile(argvFile); string(got) != want {
		t.Errorf("probe argv =\n%s\nwant\n%s", string(got), want)
	}

	os.Remove(argvFile)
	if !p.UsernsProbe(true) {
		t.Fatal("probe must report ok")
	}
	wantNet := "--unshare-all\n--die-with-parent\n--new-session\n--as-pid-1\n--share-net\n" +
		"--unshare-user\n--disable-userns\n--assert-userns-disabled\n" +
		"--ro-bind\n/\n/\n--\n/bin/true\n"
	if got, _ := os.ReadFile(argvFile); string(got) != wantNet {
		t.Errorf("share-net probe argv =\n%s\nwant\n%s", string(got), wantNet)
	}

	// a bwrap/kernel that cannot run the combo ⇒ false, never a panic
	if New(fakeBwrap(t, "exit 1")).UsernsProbe(false) {
		t.Error("failing shim must probe false")
	}
	if New(filepath.Join(t.TempDir(), "missing")).UsernsProbe(false) {
		t.Error("missing bwrap must probe false")
	}
}

func plainSpec(t *testing.T) *sandbox.Spec {
	t.Helper()
	t.Setenv("USER", "tester")
	t.Setenv("XDG_RUNTIME_DIR", "")
	dir := t.TempDir()
	cwd := filepath.Join(dir, "proj")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := sandbox.BuildSpec(&cliutil.Options{}, cwd,
		filepath.Join(dir, "sand"), filepath.Join(dir, "sock"), filepath.Join(dir, "home"),
		nil, nil, "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return spec
}

func TestBuildArgvGolden(t *testing.T) {
	spec := plainSpec(t)
	p := New("")
	p.Caps = sandbox.Caps{BindFD: true, AddSeccompFD: true}
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(l.PassFDs) != 0 || len(l.CloseAfterSpawn) != 0 {
		t.Errorf("plain spec names no fds: %d/%d", len(l.PassFDs), len(l.CloseAfterSpawn))
	}
	if l.Argv[0] != "--unshare-all" || l.Argv[1] != "--die-with-parent" ||
		l.Argv[2] != "--new-session" || l.Argv[3] != "--as-pid-1" || l.Argv[4] != "--clearenv" {
		t.Errorf("skeleton prefix = %v", l.Argv[:5])
	}
	joined := strings.Join(l.Argv, " ")
	for _, want := range []string{
		"--setenv HOME ",
		" --proc /proc --dev /dev ",
		" --perms 0755 --tmpfs /run",
		" --chdir ",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("argv missing %q:\n%s", want, joined)
		}
	}
	if !strings.HasSuffix(joined, "--chdir "+lastChdir(spec)) {
		t.Errorf("argv must end with the chdir: ...%s", joined[len(joined)-60:])
	}
}

func lastChdir(spec *sandbox.Spec) string {
	for i := len(spec.Ops) - 1; i >= 0; i-- {
		if c, ok := spec.Ops[i].(sandbox.Chdir); ok {
			return c.Dir
		}
	}
	return ""
}

func TestBuildSeccompFD(t *testing.T) {
	bpf, err := seccomp.BuildBPF("x86_64")
	if err != nil {
		t.Fatal(err)
	}
	spec := plainSpec(t)
	spec.Seccomp = bpf

	p := New("")
	p.Caps = sandbox.Caps{AddSeccompFD: true, BindFD: true}
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	if l.Argv[0] != "--add-seccomp-fd" || l.Argv[1] != "3" {
		t.Errorf("seccomp flag = %v %v, want --add-seccomp-fd 3 (first)", l.Argv[0], l.Argv[1])
	}
	if l.Argv[2] != "--unshare-all" {
		t.Errorf("hardening comes before the skeleton: %v", l.Argv[2])
	}
	if len(l.PassFDs) != 1 {
		t.Fatalf("PassFDs = %d, want the seccomp read end only", len(l.PassFDs))
	}
	got, err := io.ReadAll(l.PassFDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(bpf) {
		t.Errorf("the pipe read end yields %d bytes, want the exact filter (%d)", len(got), len(bpf))
	}

	// legacy spelling when that is all bwrap has
	p2 := New("")
	p2.Caps = sandbox.Caps{LegacySeccomp: true}
	l2, err := p2.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	if l2.Argv[0] != "--seccomp" {
		t.Errorf("legacy flag = %v", l2.Argv[0])
	}

	// fail closed: no seccomp option at all
	p3 := New("")
	p3.Caps = sandbox.Caps{BindFD: true}
	_, err = p3.Build(spec)
	if err == nil || !strings.Contains(err.Error(), "supports neither --add-seccomp-fd nor --seccomp") {
		t.Errorf("fail-closed error = %v", err)
	}
}

func TestBuildDisableUserns(t *testing.T) {
	spec := plainSpec(t)
	spec.DisableUserns = true

	p := New("")
	p.Caps = sandbox.Caps{DisableUserns: true, BindFD: true}
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--unshare-user", "--disable-userns", "--assert-userns-disabled", "--unshare-all"}
	if !reflect.DeepEqual(l.Argv[:4], want) {
		t.Errorf("userns hardening = %v, want %v", l.Argv[:4], want)
	}

	p2 := New("") // caps missing: a launcher bug, loud
	if _, err := p2.Build(spec); err == nil ||
		!strings.Contains(err.Error(), "lacks --disable-userns") {
		t.Errorf("inconsistent spec error = %v", err)
	}
}

func TestBuildFDMountsAndDups(t *testing.T) {
	dir := t.TempDir()
	pin1, err := os.Open(filepath.Join(dir, ".")) // any *os.File stands in for a pin
	if err != nil {
		t.Fatal(err)
	}
	defer pin1.Close()
	pin2, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer pin2.Close()

	spec := &sandbox.Spec{Ops: []sandbox.Op{
		// the same pin named three times: cwd mount + -b of the same
		// path + --home-style re-use — one DISTINCT child fd each
		sandbox.Mount{Src: "/a", Dst: "/a", RW: true, FD: pin1},
		sandbox.Mount{Src: "/b", Dst: "/b", FD: pin1},
		sandbox.Mount{Src: "/c", Dst: "/c", FD: pin1},
		sandbox.Mount{Src: "/d", Dst: "/d", FD: pin2},
	}}
	p := New("")
	p.Caps = sandbox.Caps{BindFD: true}
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"--bind-fd", "3", "/a",
		"--ro-bind-fd", "4", "/b",
		"--ro-bind-fd", "5", "/c",
		"--ro-bind-fd", "6", "/d",
	}
	if !reflect.DeepEqual(l.Argv[5:], want) {
		t.Fatalf("fd argv = %v, want %v", l.Argv[5:], want)
	}
	if len(l.PassFDs) != 4 {
		t.Fatalf("PassFDs = %d, want 4", len(l.PassFDs))
	}
	if len(l.CloseAfterSpawn) != 2 {
		t.Fatalf("CloseAfterSpawn = %d, want the 2 dups", len(l.CloseAfterSpawn))
	}
	if l.PassFDs[0] != pin1 {
		t.Error("first use must pass the ORIGINAL file, not a dup")
	}
	if l.PassFDs[3] != pin2 {
		t.Error("first use of the second pin must pass the original")
	}
	// the dups are real dups: different fd numbers, same object
	for i, d := range l.CloseAfterSpawn {
		if d.Fd() == pin1.Fd() {
			t.Errorf("dup %d reuses the original fd", i)
		}
	}
	// the CVE-2024-21626 invariant: every fd number the argv names is
	// an ExtraFiles slot, and every slot is named
	named := map[string]bool{}
	for i, a := range l.Argv {
		if i > 0 && (l.Argv[i-1] == "--bind-fd" || l.Argv[i-1] == "--ro-bind-fd") {
			named[a] = true
		}
	}
	if len(named) != len(l.PassFDs) {
		t.Errorf("%d argv-named fds vs %d ExtraFiles", len(named), len(l.PassFDs))
	}
	for i := range l.PassFDs {
		if !named[strconv.Itoa(extraFDBase+i)] {
			t.Errorf("ExtraFiles slot %d is named by nothing in the argv", extraFDBase+i)
		}
	}

	// pinned mounts on a backend without --bind-fd: loud, never a
	// silent path fallback
	p2 := New("")
	if _, err := p2.Build(spec); err == nil ||
		!strings.Contains(err.Error(), "lacks --bind-fd") {
		t.Errorf("no-bind-fd error = %v", err)
	}
}

func TestPermsSpelling(t *testing.T) {
	for _, tc := range []struct {
		in   uint32
		want string
	}{
		{0o755, "0755"}, {0o700, "0700"}, {0o1777, "1777"}, {0, "0000"},
	} {
		if got := perms(tc.in); got != tc.want {
			t.Errorf("perms(%o) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// The --env handoff must render as an fd-based --ro-bind-data: the
// VALUE never appears in the backend argv (bwrap's /proc/<pid>/cmdline
// is world-readable), and the pipe read end carries exactly the
// composed records.
func TestBuildEnvHandoffFD(t *testing.T) {
	secret := "s3cr3t-tok3n with spaces\nand=equals"
	spec := plainSpec(t)
	spec.EnvData = []byte("API_TOKEN\x00" + secret + "\x00")

	p := New("")
	p.Caps = sandbox.Caps{BindFD: true, AddSeccompFD: true, BindData: true}
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, f := range l.PassFDs {
			f.Close()
		}
		for _, f := range l.CloseAfterSpawn {
			f.Close()
		}
	}()
	joined := strings.Join(l.Argv, "\x00")
	if strings.Contains(joined, secret) || strings.Contains(joined, "API_TOKEN") {
		t.Fatalf("env handoff leaked into the backend argv:\n%s", joined)
	}
	// --ro-bind-data sits AFTER the /run tmpfs op and names the handoff fd.
	i := indexOfArgv(l.Argv, "--ro-bind-data")
	if i < 0 {
		t.Fatalf("no --ro-bind-data in argv:\n%s", joined)
	}
	if l.Argv[i+2] != sandbox.EnvFileDst {
		t.Errorf("--ro-bind-data destination = %q, want %q", l.Argv[i+2], sandbox.EnvFileDst)
	}
	if l.Argv[i+1] != "3" {
		t.Errorf("--ro-bind-data fd = %q, want the first ExtraFiles slot 3", l.Argv[i+1])
	}
	j := indexOfArgv(l.Argv, "--tmpfs")
	if j >= 0 && j > i {
		t.Error("--ro-bind-data must come after the /run tmpfs it lives under")
	}
	if len(l.PassFDs) != 1 {
		t.Fatalf("PassFDs = %d, want the handoff read end only", len(l.PassFDs))
	}
	got, err := io.ReadAll(l.PassFDs[0])
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(spec.EnvData) {
		t.Fatalf("handoff pipe yields %q, want the exact records", got)
	}

	// fail closed without --ro-bind-data support: never --setenv.
	p2 := New("")
	p2.Caps = sandbox.Caps{BindFD: true, AddSeccompFD: true}
	l2, err := p2.Build(spec)
	if err == nil || l2 != nil {
		t.Fatal("Build must fail closed when bwrap lacks --ro-bind-data")
	}
	if !strings.Contains(err.Error(), "--ro-bind-data") {
		t.Fatalf("unexpected error: %v", err)
	}
}

// The staged overlay launch ferries the handoff through the staging
// sandbox (--file), the staging bridge re-opens it as fd 4 (fd 3 is
// the filter), and the INNER bwrap materializes it with
// --ro-bind-data. The value stays out of every argv.
func TestBuildOverlayEnvHandoffStaged(t *testing.T) {
	spec, _, _, _, _ := overlaySpec(t)
	secret := "staged-s3cr3t '=$(injected)"
	bpf, err := seccomp.BuildBPF("x86_64")
	if err != nil {
		t.Skip("no x86_64 filter table")
	}
	spec.Seccomp = bpf
	spec.EnvData = []byte("API_TOKEN\x00" + secret + "\x00")

	p := New(fakeBwrap(t, "exit 0"))
	p.Caps = overlayCaps()
	p.Caps.BindData = true
	l, err := p.Build(spec)
	if err != nil {
		t.Fatal(err)
	}
	closeOverlayLaunch(t, l)

	joined := strings.Join(l.Argv, "\x00")
	if strings.Contains(joined, secret) || strings.Contains(joined, "API_TOKEN") {
		t.Fatalf("env handoff leaked into the staged argv:\n%s", joined)
	}
	// staging materializes the records next to the filter...
	requireArgv(t, l.Argv, "--perms", "0400", "--file", "3", stageSeccomp)
	requireArgv(t, l.Argv, "--perms", "0400", "--file", "4", stageEnv)
	// ...the bridge opens both descriptors...
	requireArgv(t, l.Argv, "/bin/sh", "-c",
		stageBridgeScript("3", "4"), "sbox-stage", stageBinary,
		"--add-seccomp-fd", "3")
	// ...and the inner bwrap binds them into the real sandbox AFTER /run.
	requireArgv(t, l.Argv, "--ro-bind-data", "4", sandbox.EnvFileDst)
	if len(l.PassFDs) != 4 { // filter, env, the bind pin, the overlay pin
		t.Fatalf("PassFDs = %d, want 4", len(l.PassFDs))
	}
	got, err := io.ReadAll(l.PassFDs[1]) // the env fd is named second
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(spec.EnvData) {
		t.Fatalf("staged handoff pipe yields %q", got)
	}
}
