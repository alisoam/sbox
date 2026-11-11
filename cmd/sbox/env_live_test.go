package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Exercise environment handoff through the real launcher and bwrap, including
// the proxy bridge and both overlay modes. Host policy can skip staged mode.
func TestRealBwrapEnvironment(t *testing.T) {
	for _, mode := range []string{"bind", "single", "staged"} {
		t.Run(mode, func(t *testing.T) {
			overlayModePreflight(t, mode != "staged")
			dir := t.TempDir()
			home, proj := filepath.Join(dir, "home"), filepath.Join(dir, "project")
			for _, p := range []string{home, proj} {
				if err := os.Mkdir(p, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("SBOX_ENV_FORWARDED", "host value=with newline\nnext")
			t.Setenv("SBOX_ENV_HOST_ONLY", "not selected")
			literal := "literal ' $(touch injected) `touch injected` $HOME =\nnext"
			flags := []string{
				"--env", "SBOX_ENV_FORWARDED", "--env", "SBOX_ENV_LITERAL=" + literal,
				"--env", "SBOX_ENV_EMPTY=", "--env", "SBOX_ENV_ORDER=first", "--env=SBOX_ENV_ORDER=last",
				"--env", "PATH=/usr/bin:/bin", "--env", "HOME=/tmp/custom-home",
			}
			if mode == "bind" {
				flags = append(flags, "-r", proj)
			} else {
				flags = append(flags, "--overlay", proj, "--overlay-mode", mode)
			}
			out, rc := overlayLaunch(t, proj, home, 30*time.Second, flags,
				"/bin/sh", "-eu", "-c", `
test "$SBOX_ENV_FORWARDED" = "$1"
test "$SBOX_ENV_LITERAL" = "$2"
test "${SBOX_ENV_EMPTY+x}" = x
test -z "$SBOX_ENV_EMPTY"
test "$SBOX_ENV_ORDER" = last
test "${SBOX_ENV_HOST_ONLY+x}" = ''
test "$HOME" = /tmp/custom-home
test "$PATH" = /usr/bin:/bin
test ! -e injected
printf 'environment passed\n'
`, "env-test", os.Getenv("SBOX_ENV_FORWARDED"), literal)
			if rc != 0 || !strings.Contains(out, "environment passed") {
				t.Fatalf("rc %d output %q", rc, out)
			}
			if os.Getenv("HOME") == "/tmp/custom-home" {
				t.Fatal("sandbox changed host environment")
			}
		})
	}
}

// Exercise the production apply-and-exec handoff path without bwrap:
// the test binary --_test-envexec entry reads NUL-framed records,
// exports them over its inherited environment, and execs /bin/sh,
// which must observe the exact bytes (and the last-wins order).
func TestEnvExecHandoffChain(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	value := "line1\nline2 'quoted' $(not-run) =sign\ttab"
	handoff := t.TempDir() + "/env"
	var b bytes.Buffer
	for _, p := range [][2]string{
		{"SBOX_HAND_ORDER", "first"}, {"SBOX_HAND_ORDER", "last"},
		{"SBOX_HAND_VALUE", value}, {"SBOX_HAND_EMPTY", ""},
		{"SBOX_HAND_DEFAULT", "overridden"},
	} {
		b.WriteString(p[0])
		b.WriteByte(0)
		b.WriteString(p[1])
		b.WriteByte(0)
	}
	if err := os.WriteFile(handoff, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(exe, "--_test-envexec", handoff, "/bin/sh", "-c",
		`test "$SBOX_HAND_ORDER" = last && test "$SBOX_HAND_VALUE" = "$1" &&
		 test "${SBOX_HAND_EMPTY+x}" = x && test -z "$SBOX_HAND_EMPTY" &&
		 test "$SBOX_HAND_DEFAULT" = overridden && printf chain-ok`,
		"envexec-test", value)
	cmd.Env = append(os.Environ(), "SBOX_HAND_DEFAULT=default", "SBOX_HAND_ORDER=default")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "chain-ok") {
		t.Fatalf("rc %v output %q", err, out)
	}
}
