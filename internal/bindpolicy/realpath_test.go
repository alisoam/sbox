package bindpolicy

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"sbox/internal/cliutil"
)

func TestRealPathResolution(t *testing.T) {
	dir := t.TempDir()
	for _, p := range []string{"work", "target/child"} {
		if err := os.MkdirAll(filepath.Join(dir, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		"work/link": "../target/child", "work/dangling": "../target/missing",
		"work/absolute": filepath.Join(dir, "target", "child"), "work/loop": "loop",
		"work/cycle-a": "cycle-b", "work/cycle-b": "cycle-a",
	} {
		if err := os.Symlink(target, filepath.Join(dir, link)); err != nil {
			t.Fatal(err)
		}
	}
	chdirForTest(t, filepath.Join(dir, "work"))
	for _, tc := range []struct{ input, want string }{
		{"", filepath.Join(dir, "work")},
		{".", filepath.Join(dir, "work")},
		{"../target", filepath.Join(dir, "target")},
		{"link", filepath.Join(dir, "target", "child")},
		{"link/..", filepath.Join(dir, "target")},
		{"link/../missing/file", filepath.Join(dir, "target", "missing", "file")},
		{"absolute/../missing", filepath.Join(dir, "target", "missing")},
		{"dangling/file", filepath.Join(dir, "target", "missing", "file")},
		{"dangling/../other", filepath.Join(dir, "target", "other")},
		{"missing/../other", filepath.Join(dir, "work", "other")},
		{filepath.Join(dir, "work") + "/link/../missing", filepath.Join(dir, "target", "missing")},
	} {
		if got := RealPath(tc.input); got != tc.want {
			t.Errorf("RealPath(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
	pinner := NewPinner(true)
	defer pinner.Close()
	for _, input := range []string{"loop", "loop/../target", "cycle-a"} {
		loop := RealPath(input)
		if _, err := pinner.Pin(loop, false); err == nil {
			t.Errorf("symlink loop %q became pinnable", loop)
		}
		// Without fd-bind support, bwrap opens the path directly. It must
		// still see the loop instead of a cleaned path outside it.
		if _, err := os.Stat(loop); !errors.Is(err, syscall.ELOOP) {
			t.Errorf("path-mode loop %q: error = %v, want ELOOP", loop, err)
		}
	}
}

func TestRelativeBindPaths(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	for _, p := range []string{home, filepath.Join(dir, "project"), filepath.Join(dir, "runtime")} {
		if err := os.MkdirAll(p, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(dir, "protected")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("runtime/later.sock", filepath.Join(dir, "alias.sock")); err != nil {
		t.Fatal(err)
	}
	relativeSystem, err := filepath.Rel(dir, "/etc")
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "runtime"))
	chdirForTest(t, dir)
	for _, pinned := range []bool{false, true} {
		for _, tc := range []struct {
			name, path, flag, refusal string
			opts                      *cliutil.Options
		}{
			{"directory", "project", "--bind", "", &cliutil.Options{Bind: []string{"./project"}}},
			{"file", "README.md", "--ro-bind", "", &cliutil.Options{RoBind: []string{"README.md"}}},
			{"missing socket", "runtime/later.sock", "--ro-bind", "",
				&cliutil.Options{BindSocket: []string{"runtime/later.sock"}}},
			{"dangling socket alias", "runtime/later.sock", "--ro-bind", "",
				&cliutil.Options{BindSocket: []string{"alias.sock"}}},
			{"protected", "", "", "covers protected path(s): /etc",
				&cliutil.Options{Bind: []string{"protected"}}},
			{"relative protected", "", "", "covers protected path(s): /etc",
				&cliutil.Options{Bind: []string{relativeSystem}}},
			{"home", "", "", "covers protected path(s)", &cliutil.Options{Bind: []string{"home"}}},
		} {
			t.Run(tc.name+map[bool]string{false: "/path", true: "/pinned"}[pinned], func(t *testing.T) {
				pinner := NewPinner(pinned)
				defer pinner.Close()
				binds, err := CheckBindPaths(tc.opts, home, pinner, nil)
				if tc.refusal != "" {
					if err == nil || !strings.Contains(err.Error(), tc.refusal) {
						t.Fatalf("error = %v, want %q", err, tc.refusal)
					}
					return
				}
				if err != nil || len(binds) != 1 {
					t.Fatalf("binds = %v, error = %v", binds, err)
				}
				b := binds[0]
				want := filepath.Join(dir, tc.path)
				if b.Path != want || b.Flag != tc.flag {
					t.Fatalf("bind = %s %q, want %s %q", b.Flag, b.Path, tc.flag, want)
				}
				wantFD := pinned && tc.path != "runtime/later.sock"
				if (b.FD != nil) != wantFD || (b.FD != nil && !FdReaches(b.FD, want)) {
					t.Fatalf("pin does not identify the validated path %q: %v", want, b.FD)
				}
			})
		}
	}
	// An absent explicit bind never silently falls back to a path mount
	// when descriptor pinning is supported.
	pinner := NewPinner(true)
	defer pinner.Close()
	if _, err := CheckBindPaths(&cliutil.Options{Bind: []string{"missing"}}, home, pinner, nil); err == nil {
		t.Fatal("missing relative bind did not fail closed")
	}
}
