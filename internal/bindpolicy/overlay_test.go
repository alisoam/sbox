package bindpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/cliutil"
)

// overlayFixture builds a home + a plain overlayable project dir, with
// XDG_RUNTIME_DIR neutralized so runtime-ground rules don't shadow the
// cases under test.
func overlayFixture(t *testing.T) (home, proj string) {
	t.Helper()
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("USER", "tester")
	dir := t.TempDir()
	home = filepath.Join(dir, "home")
	proj = filepath.Join(dir, "proj")
	for _, d := range []string{home, proj} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	return home, proj
}

func TestCheckOverlaysValidSource(t *testing.T) {
	home, proj := overlayFixture(t)
	pinner := NewPinner(true)
	defer pinner.Close()
	var warns []string
	ovs, err := CheckOverlays(&cliutil.Options{Overlay: []string{proj}},
		home, pinner, nil, func(w string) { warns = append(warns, w) })
	if err != nil {
		t.Fatalf("CheckOverlays: %v (warns %q)", err, warns)
	}
	if len(ovs) != 1 || ovs[0].Path != proj {
		t.Fatalf("overlays = %+v, want the resolved %s once", ovs, proj)
	}
	if ovs[0].FD == nil {
		t.Fatal("overlay source must be pinned (nil fd refuses in the backend)")
	}
	if !FdReaches(ovs[0].FD, proj) {
		t.Errorf("pin does not reach %s", proj)
	}
	// a trailing slash resolves to the same object: a duplicate, refused
	if _, err := CheckOverlays(&cliutil.Options{Overlay: []string{proj, proj + "/"}},
		home, pinner, nil, func(string) {}); err == nil ||
		!strings.Contains(err.Error(), "already overlaid") {
		t.Errorf("trailing-slash duplicate: err = %v, want \"already overlaid\"", err)
	}
}

func TestCheckOverlaysRefusals(t *testing.T) {
	home, proj := overlayFixture(t)
	dir := filepath.Dir(proj)

	// a socket-bearing directory: refused, and NO opt-in exists
	sockdir := filepath.Join(dir, "sockdir")
	if err := os.Mkdir(sockdir, 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, filepath.Join(sockdir, "puma.sock"))

	// a regular file: not a directory
	notdir := filepath.Join(dir, "afile")
	if err := os.WriteFile(notdir, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	// under $XDG_RUNTIME_DIR: runtime ground
	rt := filepath.Join(dir, "runtime")
	t.Setenv("XDG_RUNTIME_DIR", rt)
	if err := os.MkdirAll(filepath.Join(rt, "app"), 0o755); err != nil {
		t.Fatal(err)
	}

	// a bind to conflict with
	boundDir := filepath.Join(dir, "bound")
	if err := os.Mkdir(boundDir, 0o755); err != nil {
		t.Fatal(err)
	}
	insideBound := filepath.Join(boundDir, "sub")
	if err := os.Mkdir(insideBound, 0o755); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		{"missing source", filepath.Join(dir, "nope"), "cannot pin bind source"},
		{"not a directory", notdir, "is not a directory"},
		{"protected system dir", "/usr", "covers protected path"},
		{"inside /proc", "/proc/1", "is inside /proc"},
		{"control socket dir", "/run/docker.sock", "overlaps host control socket"},
		{"runtime dir ground", filepath.Join(rt, "app"), "lives under a runtime dir"},
		{"contains a socket", sockdir, "contains a Unix socket"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pinner := NewPinner(true)
			defer pinner.Close()
			_, err := CheckOverlays(&cliutil.Options{Overlay: []string{tc.path}},
				home, pinner, nil, func(string) {})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	pinner := NewPinner(true)
	defer pinner.Close()
	binds := []Bind{{Flag: "--bind", Path: boundDir}}
	// a project inside another overlay candidate (both plain dirs)
	inner := filepath.Join(proj, "module")
	if err := os.Mkdir(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	// and one inside $HOME for the --home conflict
	homeProj := filepath.Join(home, "homeproj")
	if err := os.Mkdir(homeProj, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		overlay []string
		opts    *cliutil.Options
		want    string
	}{
		{"duplicate overlays", []string{proj, proj}, nil, "already overlaid"},
		{"nested overlays", []string{proj, inner}, nil, "nested overlays"},
		{"conflicting bind", []string{insideBound}, nil, "overlaps the --bind mount"},
		{"conflicting --home", []string{homeProj}, &cliutil.Options{Home: true}, "overlaps $HOME under --home"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.opts
			if opts == nil {
				opts = &cliutil.Options{}
			}
			opts.Overlay = tc.overlay
			_, err := CheckOverlays(opts, home, pinner, binds, func(string) {})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}

	// The same path through a symlink resolves to the realpath and is
	// still recognized as a duplicate.
	link := proj + "-link"
	if err := os.Symlink(proj, link); err != nil {
		t.Fatal(err)
	}
	_, err := CheckOverlays(&cliutil.Options{Overlay: []string{proj, link}},
		home, pinner, nil, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "already overlaid") {
		t.Errorf("symlinked duplicate: err = %v, want \"already overlaid\"", err)
	}
}

func TestCheckOverlaysRequiresPinner(t *testing.T) {
	home, proj := overlayFixture(t)
	pinner := NewPinner(false) // old bwrap: pins are no-ops
	defer pinner.Close()
	_, err := CheckOverlays(&cliutil.Options{Overlay: []string{proj}},
		home, pinner, nil, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "no pinned descriptor") {
		t.Fatalf("err = %v, want the no-pin refusal (overlays never fall back to paths)", err)
	}
}

// The hostile-socket-name quoting fix must hold for overlays too.
func TestCheckOverlaysQuotesSocketNames(t *testing.T) {
	home, _ := overlayFixture(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "evil\x1b]777;pwn"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, filepath.Join(dir, "evil\x1b]777;pwn", "s.sock"))
	pinner := NewPinner(true)
	defer pinner.Close()
	_, err := CheckOverlays(&cliutil.Options{Overlay: []string{dir}},
		home, pinner, nil, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "contains a Unix socket") {
		t.Fatalf("err = %v, want the socket refusal", err)
	}
	if strings.Contains(err.Error(), "\x1b") {
		t.Errorf("refusal leaked a raw ESC byte: %q", err)
	}
}
