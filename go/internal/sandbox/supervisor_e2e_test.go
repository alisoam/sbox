package sandbox_test

// The full-stack supervisor e2e (external test package: the REAL bwrap
// provider imports sandbox, which an in-package test cannot): the
// supervisor drives bwrap.Build against a shim backend and the recorded
// launch argv must be exactly run_sandbox's assembly — hardening
// skeleton, rendered ops, "--", bridge shell, payload — plus the $WORK
// layout (0700 dir, tmp/ subdir, ssh_config) captured at Build time.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/cliutil"
	"sbox/internal/sandbox"
	"sbox/internal/sandbox/bwrap"
)

func writeShimE2E(t *testing.T, path, body string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func argvContains(rec string, want ...string) bool {
	return strings.Contains("\n"+rec+"\n", "\n"+strings.Join(want, "\n")+"\n")
}

func requireEmptyDirE2E(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Errorf("%s not cleaned: %v", dir, entries)
	}
}

// newBwrapSupervisor wires a Supervisor around the REAL bwrap provider
// pointed at a shim that answers --help (modern seccomp caps only, so
// no userns probe runs), records its launch argv and exits 42. $WORK
// stays under a SHORT root (sun_path caps Unix socket paths at ~108
// bytes). Returns the supervisor and the argv record path.
func newBwrapSupervisor(t *testing.T) (sup *sandbox.Supervisor, rec string) {
	t.Helper()
	t.Setenv("USER", "tester")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("SSH_AUTH_SOCK", "")
	root, err := os.MkdirTemp("", "sboxe2e.")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	rec = filepath.Join(root, "argv")
	shim := writeShimE2E(t, filepath.Join(root, "bwrap"), fmt.Sprintf(`if [ "$1" = "--help" ]; then
    echo "--add-seccomp-fd FD"
    exit 0
fi
printf '%%s\n' "$@" > %s
exit 42
`, rec))

	home := filepath.Join(root, "home")
	cwd := filepath.Join(root, "proj")
	workroot := filepath.Join(root, "work")
	for _, d := range []string{home, cwd, workroot} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	sup = &sandbox.Supervisor{
		Opts:     &cliutil.Options{NoSeccomp: true}, // the seccomp gate has its own tests
		Command:  []string{"echo", "hi"},
		Provider: bwrap.New(shim),
		Warn:     func(string) {},
		SigCh:    make(chan os.Signal, 8),
		Home:     home,
		TempRoot: workroot,
		Getwd:    func() (string, error) { return cwd, nil },
	}
	return sup, rec
}

func TestSupervisorRunEndToEnd(t *testing.T) {
	sup, rec := newBwrapSupervisor(t)
	var notes []string
	sup.Warn = func(w string) { notes = append(notes, w) }
	cwd, _ := sup.Getwd()

	rc := sup.Run()
	if rc != 42 {
		t.Fatalf("rc = %d, want 42 (the shim's exit code)", rc)
	}
	requireEmptyDirE2E(t, sup.TempRoot) // $WORK removed

	data, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	for _, want := range [][]string{
		// hardening skeleton first, exactly as run_sandbox assembles
		{"--unshare-all", "--die-with-parent", "--new-session", "--as-pid-1", "--clearenv"},
		{"--setenv", "HOME", sup.Home},
		{"--proc", "/proc"},
		{"--perms", "0755", "--tmpfs", "/run"},
		{"--ro-bind", "/usr", "/usr"},
		{"--ro-bind-try", "/etc/ssl", "/etc/ssl"},
		{"--perms", "0700", "--tmpfs", sup.Home}, // no --home: tmpfs $HOME
		{"--bind", cwd, cwd},                     // the rw cwd mount
		{"--chdir", cwd},
		{"--"}, // the payload boundary the supervisor appends
		{"/bin/sh", "-c"},
		{"sbox-sh", "echo", "hi"},
	} {
		if !argvContains(got, want...) {
			t.Errorf("backend argv missing %v:\n%s", want, got)
		}
	}
	for _, want := range []string{
		"socat TCP-LISTEN:1080,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/run/proxy.sock",
		"exec \"$@\"",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("backend argv missing %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "--add-seccomp-fd") {
		t.Errorf("--no-seccomp must keep the filter out of the argv")
	}
	if len(notes) != 0 {
		t.Errorf("unexpected notes: %v", notes)
	}
}

// inspectingProvider wraps the real bwrap provider and snapshots $WORK
// while Build runs (before the teardown removes it).
type inspectingProvider struct {
	*bwrap.Provider
	spec     *sandbox.Spec
	sandDir  string
	sshCfg   string
	workMode os.FileMode
}

func (p *inspectingProvider) Build(spec *sandbox.Spec) (*sandbox.Launch, error) {
	p.spec = spec
	for _, op := range spec.Ops {
		if m, ok := op.(sandbox.Mount); ok {
			switch m.Dst {
			case "/tmp":
				p.sandDir = m.Src
				if st, err := os.Stat(filepath.Dir(m.Src)); err == nil {
					p.workMode = st.Mode().Perm()
				}
			case "/etc/ssh/ssh_config":
				p.sshCfg = m.Src
			}
		}
	}
	return p.Provider.Build(spec)
}

// TestSupervisorWorkDirShape pins the $WORK layout from run_sandbox: a
// 0700 mkdtemp dir whose tmp/ subdir is mounted as the sandbox's /tmp,
// plus the world-readable ssh_config bound at /etc/ssh/ssh_config — all
// of it gone after the run.
func TestSupervisorWorkDirShape(t *testing.T) {
	sup, _ := newBwrapSupervisor(t)
	inner := sup.Provider.(*bwrap.Provider)
	insp := &inspectingProvider{Provider: inner}
	sup.Provider = insp

	if rc := sup.Run(); rc != 42 {
		t.Fatalf("rc = %d", rc)
	}
	if insp.sandDir == "" {
		t.Fatal("no /tmp mount in the spec")
	}
	work := filepath.Dir(insp.sandDir)
	if filepath.Base(insp.sandDir) != "tmp" || !strings.HasPrefix(filepath.Base(work), "sbox.") {
		t.Errorf("sand dir = %q (want <work>/tmp under an sbox.* mkdtemp)", insp.sandDir)
	}
	if insp.workMode != 0o700 {
		t.Errorf("$WORK mode = %o, want 0700", insp.workMode)
	}
	if insp.sshCfg == "" || filepath.Base(insp.sshCfg) != "ssh_config" {
		t.Errorf("ssh_config mount = %q", insp.sshCfg)
	}
	// both lived under the SAME work dir (the socket's mount is asserted
	// by the e2e argv; here the two files just have to be siblings)
	if filepath.Dir(insp.sshCfg) != work {
		t.Errorf("ssh_config %q is not inside $WORK %q", insp.sshCfg, work)
	}
	requireEmptyDirE2E(t, sup.TempRoot)
}
