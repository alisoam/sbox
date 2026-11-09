package bindpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/cliutil"
)

// The path-mode contract also applies on hosts whose bwrap cannot mount
// pinned descriptors. Every refusal remains enforced without that feature.
func TestValidateBindSourceContract(t *testing.T) {
	dir := t.TempDir()
	home, rt := filepath.Join(dir, "home"), filepath.Join(dir, "rt")
	clean, bear := filepath.Join(dir, "clean"), filepath.Join(dir, "bear")
	sock := filepath.Join(dir, "sock")
	for _, p := range []string{clean, rt, filepath.Join(rt, "sub"),
		filepath.Join(home, ".local", "bin"), filepath.Join(bear, ".git")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	tool := filepath.Join(home, ".local", "bin", "tool")
	if err := os.WriteFile(tool, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, sock)
	mustSocketAt(t, filepath.Join(bear, ".git", "fsmonitor--daemon.ipc"))
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", rt)
	chdirForTest(t, clean)

	for _, tc := range []struct {
		label, path string
		home, roCwd bool
		explicit    []string
		refusal     string
		warning     string
	}{
		{"--bind", clean, false, false, nil, "", ""},
		{"--bind", home, false, false, nil, "covers protected path(s)", ""},
		{"--bind", home, true, false, nil, "", ""},
		{"--bind", filepath.Dir(tool), false, false, nil, "", "host persistence path(s)"},
		{"--bind", tool, false, false, nil, "", "host persistence path(s)"},
		{"--ro-bind", filepath.Join(home, ".bashrc"), false, false, nil, "", ""},
		{"--bind", "/etc", false, false, nil, "covers protected path(s)", ""},
		{"--bind", "/tmp", false, false, nil, "covers protected path(s)", ""},
		{"--ro-bind", "/proc/1", false, false, nil, "kernel/pseudo-fs ground", ""},
		{"--bind-socket", "/proc/self", false, false, nil, "kernel/pseudo-fs ground", ""},
		{"--bind", "/run/docker.sock", false, false, nil, "host control socket(s)", ""},
		{"--ro-bind", filepath.Join(rt, "sub"), false, false, nil, "control-socket territory", ""},
		{"--bind-socket", filepath.Join(rt, "sub"), false, false, nil, "control-socket territory", ""},
		{"--bind-socket", filepath.Join(rt, "nosock"), false, false, nil, "control-socket territory", ""},
		{"--bind", sock, false, false, nil, "connect-only ground never mounts read-write", ""},
		{"--bind-socket", sock, false, false, []string{sock}, "", ""},
		{"--bind", bear, false, false, nil, "contains a Unix socket", ""},
		{"--bind-socket", bear, false, false, []string{bear}, "", ""},
		{"--bind", "/tmp/.X11-unix", false, false, nil, "host control socket(s)", ""},
		{"--bind", filepath.Join(home, ".colima", "default", "docker.sock"),
			false, false, nil, "host control socket(s)", ""},
		{"cwd", bear, false, false, nil, "contains a Unix socket", ""},
		{"cwd", bear, false, true, nil, "contains a Unix socket", ""},
		{"cwd", filepath.Join(rt, "sub"), false, true, []string{filepath.Join(rt, "sub")}, "", ""},
		{"--bind", "", false, false, nil, "", ""},
	} {
		t.Run(tc.label+" "+tc.path, func(t *testing.T) {
			opts := &cliutil.Options{Home: tc.home, RoCwd: tc.roCwd, BindSocket: tc.explicit}
			refusal, warning, rp, fd, err := ValidateBindSource(nil, tc.label, tc.path, opts, home, nil)
			if err != nil || fd != nil {
				t.Fatalf("path mode: fd = %v, error = %v", fd, err)
			}
			if !filepath.IsAbs(rp) {
				t.Errorf("resolved source is not absolute: %q", rp)
			}
			for _, check := range []struct{ name, got, want string }{
				{"refusal", refusal, tc.refusal}, {"warning", warning, tc.warning},
			} {
				if (check.want == "" && check.got != "") || !strings.Contains(check.got, check.want) {
					t.Errorf("%s = %q, want %q", check.name, check.got, check.want)
				}
			}
		})
	}
}

func chdirForTest(t *testing.T, path string) {
	t.Helper()
	old := mustCwd(t)
	if err := os.Chdir(path); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Errorf("restore cwd: %v", err)
		}
	})
}
