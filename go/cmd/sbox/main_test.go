package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// captureStderr swaps os.Stderr for a pipe while f runs (errf/die write
// to os.Stderr at call time).
func captureStderr(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	defer func() { os.Stderr = old }()
	f()
	w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEnvFlag(t *testing.T) {
	for _, tc := range []struct {
		val  string
		want bool
	}{
		{"1", true}, {"true", true}, {"TRUE", true}, {" yes ", true}, {"On", true},
		{"0", false}, {"", false}, {"no", false}, {"off", false}, {"2", false},
	} {
		t.Setenv("SBOX_TEST_FLAG", tc.val)
		if got := envFlag("SBOX_TEST_FLAG"); got != tc.want {
			t.Errorf("envFlag(%q) = %v, want %v", tc.val, got, tc.want)
		}
	}
}

func TestFirstNonEmpty(t *testing.T) {
	if got := firstNonEmpty("", "", "x", "y"); got != "x" {
		t.Errorf("firstNonEmpty = %q", got)
	}
	if got := firstNonEmpty(); got != "" {
		t.Errorf("firstNonEmpty() = %q", got)
	}
}

func TestPickShell(t *testing.T) {
	dir := t.TempDir()
	other := t.TempDir()
	local := filepath.Join(dir, "myshell")
	if err := os.WriteFile(local, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	t.Run("unset SHELL defaults to bash", func(t *testing.T) {
		t.Setenv("SHELL", "")
		var notes []string
		shell := pickShell(false, "/home/u", func(n string) { notes = append(notes, n) })
		if shell != "/bin/bash" && shell != "/bin/sh" {
			t.Errorf("shell = %q", shell)
		}
		wantNote := !isRegularFile("/bin/bash")
		if len(notes) > 0 != wantNote {
			t.Errorf("notes = %v (fallback note only when bash is missing)", notes)
		}
	})

	t.Run("outside /usr and /bin falls back loudly", func(t *testing.T) {
		t.Setenv("SHELL", local)
		var notes []string
		shell := pickShell(false, "/home/u", func(n string) { notes = append(notes, n) })
		if shell != "/bin/bash" && shell != "/bin/sh" {
			t.Errorf("shell = %q", shell)
		}
		if len(notes) != 1 || !strings.Contains(notes[0], "not available inside the sandbox") {
			t.Errorf("notes = %v", notes)
		}
	})

	t.Run("under --home-bound $HOME is kept", func(t *testing.T) {
		t.Setenv("SHELL", local)
		var notes []string
		if got := pickShell(true, dir, func(n string) { notes = append(notes, n) }); got != local {
			t.Errorf("shell = %q, want %q", got, local)
		}
		if len(notes) != 0 {
			t.Errorf("notes = %v", notes)
		}
		// a DIFFERENT home does not cover it
		if got := pickShell(true, other, func(string) {}); got == local {
			t.Errorf("shell under a foreign home must fall back")
		}
	})

	t.Run("missing /bin-prefix shell falls back", func(t *testing.T) {
		t.Setenv("SHELL", "/bin/definitely-not-here-1234")
		var notes []string
		shell := pickShell(false, "/home/u", func(n string) { notes = append(notes, n) })
		if shell != "/bin/bash" && shell != "/bin/sh" {
			t.Errorf("shell = %q", shell)
		}
		if len(notes) != 1 {
			t.Errorf("notes = %v", notes)
		}
	})
}

func TestUsageBlock(t *testing.T) {
	b := usageBlock()
	if !strings.HasPrefix(b, "usage: sbox [-h]") || strings.Contains(b, "Run COMMAND") {
		t.Errorf("usageBlock = %q", b)
	}
}

func TestRunErrors(t *testing.T) {
	t.Run("missing bwrap dies", func(t *testing.T) {
		t.Setenv("PATH", t.TempDir())
		t.Setenv("HOME", t.TempDir())
		var rc int
		out := captureStderr(t, func() { rc = run([]string{"--", "/bin/true"}) })
		if rc != 1 {
			t.Fatalf("rc = %d, want 1", rc)
		}
		if !strings.Contains(out, "sbox: missing dependency: bwrap") {
			t.Errorf("stderr = %q", out)
		}
	})

	t.Run("unknown flag is a parser error", func(t *testing.T) {
		var rc int
		out := captureStderr(t, func() { rc = run([]string{"--bogus", "--", "true"}) })
		if rc != 2 {
			t.Fatalf("rc = %d, want 2", rc)
		}
		if !strings.Contains(out, "usage: sbox") ||
			!strings.Contains(out, "sbox: error: unrecognized arguments: --bogus") {
			t.Errorf("stderr = %q", out)
		}
	})

	t.Run("no command is a parser error", func(t *testing.T) {
		dir := t.TempDir()
		writeShimMain(t, dir, "bwrap", `if [ "$1" = "--help" ]; then echo "--add-seccomp-fd FD"; exit 0; fi
exit 0`)
		t.Setenv("PATH", dir)
		t.Setenv("HOME", dir)
		var rc int
		out := captureStderr(t, func() { rc = run([]string{"--net"}) })
		if rc != 2 {
			t.Fatalf("rc = %d, want 2", rc)
		}
		if !strings.Contains(out, "sbox: error: no command given (or use --shell)") {
			t.Errorf("stderr = %q", out)
		}
	})

	t.Run("shell plus command refused", func(t *testing.T) {
		dir := t.TempDir()
		writeShimMain(t, dir, "bwrap", "exit 0")
		t.Setenv("PATH", dir)
		t.Setenv("HOME", dir)
		var rc int
		out := captureStderr(t, func() { rc = run([]string{"--net", "--shell", "--", "true"}) })
		if rc != 2 || !strings.Contains(out, "--shell takes no command") {
			t.Fatalf("rc = %d stderr = %q", rc, out)
		}
	})

	t.Run("socat required unless --net", func(t *testing.T) {
		dir := t.TempDir()
		writeShimMain(t, dir, "bwrap", `if [ "$1" = "--help" ]; then echo "--add-seccomp-fd FD"; exit 0; fi
exit 0`)
		t.Setenv("PATH", dir)
		t.Setenv("HOME", dir)
		var rc int
		out := captureStderr(t, func() { rc = run([]string{"--", "/bin/true"}) })
		if rc != 1 || !strings.Contains(out, "missing dependency: socat") {
			t.Fatalf("rc = %d stderr = %q", rc, out)
		}
	})

	// The caps warning fires only when the PROBE FAILED. A bwrap whose
	// --help succeeds but lists none of our options stays quiet here
	// (python's parse_bwrap_caps returns a truthy dict); the seccomp
	// gate then dies with its dedicated message.
	t.Run("failed probe warns, optionless bwrap does not", func(t *testing.T) {
		dir := t.TempDir()
		home := filepath.Join(dir, "home")
		if err := os.Mkdir(home, 0o755); err != nil {
			t.Fatal(err)
		}

		broken := filepath.Join(dir, "broken")
		if err := os.MkdirAll(broken, 0o755); err != nil {
			t.Fatal(err)
		}
		writeShimMain(t, broken, "bwrap", "exit 3")
		t.Setenv("PATH", broken)
		t.Setenv("HOME", home)
		var rc int
		out := captureStderr(t, func() { rc = run([]string{"--net", "--", "/bin/true"}) })
		if rc != 1 {
			t.Fatalf("broken probe: rc = %d stderr = %q", rc, out)
		}
		if !strings.Contains(out, "warning: cannot determine this bwrap's capabilities") ||
			!strings.Contains(out, "supports neither --add-seccomp-fd nor --seccomp") {
			t.Errorf("broken probe stderr = %q", out)
		}

		optionless := filepath.Join(dir, "optionless")
		if err := os.MkdirAll(optionless, 0o755); err != nil {
			t.Fatal(err)
		}
		writeShimMain(t, optionless, "bwrap", `if [ "$1" = "--help" ]; then echo "usage: ancient"; exit 0; fi
exit 0`)
		t.Setenv("PATH", optionless)
		out = captureStderr(t, func() { rc = run([]string{"--net", "--", "/bin/true"}) })
		if rc != 1 {
			t.Fatalf("optionless: rc = %d stderr = %q", rc, out)
		}
		if strings.Contains(out, "cannot determine this bwrap's capabilities") {
			t.Errorf("optionless bwrap must not trip the probe warning: %q", out)
		}
		if !strings.Contains(out, "supports neither --add-seccomp-fd nor --seccomp") {
			t.Errorf("optionless stderr = %q", out)
		}
	})

	t.Run("HOME must be set", func(t *testing.T) {
		dir := t.TempDir()
		writeShimMain(t, dir, "bwrap", "exit 0")
		t.Setenv("PATH", dir)
		t.Setenv("HOME", "")
		if err := os.Unsetenv("HOME"); err != nil {
			t.Fatal(err)
		}
		var rc int
		out := captureStderr(t, func() { rc = run([]string{"--net", "--", "/bin/true"}) })
		if rc != 1 || !strings.Contains(out, "HOME is not set") {
			t.Fatalf("rc = %d stderr = %q", rc, out)
		}
	})
}

// TestRunWithShims drives the WHOLE launcher — CLI parse, caps probe,
// supervisor, spawn, teardown — with a fake bwrap on $PATH (phase 6's
// wire-everything check, no real bwrap needed).
func TestRunWithShims(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	rec := filepath.Join(dir, "argv")
	writeShimMain(t, dir, "bwrap", fmt.Sprintf(`if [ "$1" = "--help" ]; then
    echo "--add-seccomp-fd FD"
    exit 0
fi
printf '%%s\n' "$@" >> %s
exit 0
`, rec))
	t.Setenv("PATH", dir)
	t.Setenv("HOME", home)
	t.Setenv("USER", "tester")
	t.Setenv("XDG_RUNTIME_DIR", "")

	var rc int
	out := captureStderr(t, func() { rc = run([]string{"--net", "--no-seccomp", "--", "/bin/echo", "hi"}) })
	if rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, out)
	}
	if len(out) != 0 {
		t.Errorf("unexpected stderr: %q", out)
	}
	data, err := os.ReadFile(rec)
	if err != nil {
		t.Fatal(err)
	}
	got := string(data)
	contains := func(want ...string) bool {
		return strings.Contains("\n"+got+"\n", "\n"+strings.Join(want, "\n")+"\n")
	}
	for _, want := range [][]string{
		{"--unshare-all"}, {"--die-with-parent"}, {"--new-session"}, {"--as-pid-1"},
		{"--clearenv"}, {"--setenv", "HOME", home}, {"--share-net"},
		{"--"}, {"/bin/sh", "-c"}, {"sbox-sh", "/bin/echo", "hi"},
	} {
		if !contains(want...) {
			t.Errorf("bwrap argv missing %v:\n%s", want, got)
		}
	}
	if !strings.Contains(got, "exec \"$@\"") {
		t.Errorf("bwrap argv missing the bridge's exec:\n%s", got)
	}
	if strings.Contains(got, "--add-seccomp-fd") {
		t.Errorf("--no-seccomp must keep the filter out of the argv")
	}
}

func TestRunHelp(t *testing.T) {
	var rc int
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	rc = run([]string{"-h"})
	w.Close()
	os.Stdout = old
	b, _ := io.ReadAll(r)
	if rc != 0 {
		t.Fatalf("rc = %d", rc)
	}
	if !strings.HasPrefix(string(b), "usage: sbox") || !strings.Contains(string(b), "Examples:") {
		t.Errorf("help output malformed")
	}
}

func writeShimMain(t *testing.T, dir, name, body string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
}

// captureStdout mirrors captureStderr for the filtered output stream.
func captureStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	defer func() { os.Stdout = old }()
	f()
	w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRunWithShimsFilterOutput drives the WHOLE launcher under
// --filter-output: the fake bwrap prints an OSC 52 clipboard write, a
// private-mode query and safe SGR to its stdout (the pty slave); only
// the sanitized bytes may reach the launcher's stdout (phase 7's
// wire-everything check).
func TestRunWithShimsFilterOutput(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o755); err != nil {
		t.Fatal(err)
	}
	writeShimMain(t, dir, "bwrap", `if [ "$1" = "--help" ]; then
    echo "--add-seccomp-fd FD"
    exit 0
fi
printf 'ok\033]52;c:aGk=\a\033[?25l\033[31m!\033[0m\n'
exit 0`)
	t.Setenv("PATH", dir)
	t.Setenv("HOME", home)
	t.Setenv("USER", "tester")
	t.Setenv("XDG_RUNTIME_DIR", "")

	var rc int
	var stdout string
	stderr := captureStderr(t, func() {
		stdout = captureStdout(t, func() {
			rc = run([]string{"--net", "--no-seccomp", "--filter-output", "--", "/bin/true"})
		})
	})
	if rc != 0 {
		t.Fatalf("rc = %d stderr = %q", rc, stderr)
	}
	if want := "ok\x1b[31m!\x1b[0m\r\n"; stdout != want { // ONLCR: \n → \r\n
		t.Errorf("filtered stdout = %q, want %q", stdout, want)
	}
	if strings.Contains(stdout, "52;c") || strings.Contains(stdout, "?25l") {
		t.Errorf("unsafe escape leaked: %q", stdout)
	}
}
