package bindpolicy

// The differential cross-check for the bind-policy layer: identical
// (label, path, opts, home) inputs to this port's ValidateBindSource (in
// path mode — a disabled Pinner, exactly Python's pinner=None) and to
// sbox.py's validate_bind_source, comparing the refusal, the persistence
// warning and the resolved path byte for byte. The messages ARE the spec
// here (users match them against the epilog), so no normalization.
//
// Everything skips cleanly when python3 or sbox.py is missing ($SBOX_PY /
// $SBOX_PYTHON override), so the suite stays green without the oracle.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"sbox/internal/cliutil"
	"sbox/internal/oracle"
)

func requireOracle(t *testing.T) {
	t.Helper()
	if !oracle.Available() {
		t.Skip("differential oracle unavailable: python3 + sbox.py not found (set $SBOX_PY / $SBOX_PYTHON)")
	}
}

func TestDifferentialValidateBindSource(t *testing.T) {
	requireOracle(t)

	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	rt := filepath.Join(dir, "rt")
	t.Setenv("XDG_RUNTIME_DIR", rt)

	clean := filepath.Join(dir, "clean")
	bear := filepath.Join(dir, "bear")
	sock := filepath.Join(dir, "sock")
	for _, d := range []string{clean, rt, filepath.Join(rt, "sub"), filepath.Join(home, ".local", "bin"), filepath.Join(bear, ".git")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".local", "bin", "tool"), []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, sock)
	mustSocketAt(t, filepath.Join(bear, ".git", "fsmonitor--daemon.ipc"))

	type req struct {
		Label      string   `json:"label"`
		P          string   `json:"p"`
		Home       string   `json:"home"`
		HomeOpt    bool     `json:"home_opt"`
		RoCwd      bool     `json:"ro_cwd"`
		BindSocket []string `json:"bind_socket"`
	}
	reqs := []req{
		{"--bind", clean, home, false, false, nil},
		{"--bind", home, home, false, false, nil},                                 // $HOME without --home
		{"--bind", home, home, true, false, nil},                                  // exempt with --home
		{"--bind", filepath.Join(home, ".local", "bin"), home, false, false, nil}, // persistence warning
		{"--bind", filepath.Join(home, ".local", "bin", "tool"), home, false, false, nil},
		{"--ro-bind", filepath.Join(home, ".bashrc"), home, false, false, nil}, // missing source, path mode
		{"--bind", "/etc", home, false, false, nil},
		{"--bind", "/tmp", home, false, false, nil},
		{"--ro-bind", "/proc/1", home, false, false, nil},
		{"--bind-socket", "/proc/self", home, false, false, nil},
		{"--bind", "/run/docker.sock", home, false, false, nil},
		{"--ro-bind", filepath.Join(rt, "sub"), home, false, false, nil},
		{"--bind-socket", filepath.Join(rt, "sub"), home, false, false, nil},
		{"--bind-socket", filepath.Join(rt, "nosock"), home, false, false, nil},
		{"--bind", sock, home, false, false, nil},
		{"--bind-socket", sock, home, false, false, []string{sock}},
		{"--bind", bear, home, false, false, nil},
		{"--bind-socket", bear, home, false, false, []string{bear}},
		{"--bind", "/tmp/.X11-unix", home, false, false, nil},
		{"--bind", filepath.Join(home, ".colima", "default", "docker.sock"), home, false, false, nil},
		{"cwd", bear, home, false, false, nil},
		{"cwd", bear, home, false, true, nil},
		{"cwd", filepath.Join(rt, "sub"), home, false, true, []string{filepath.Join(rt, "sub")}},
		// realpath("") is the cwd on CPython >= 3.13 — both sides run in
		// the same working directory, so the resolution must agree.
		{"--bind", "", home, false, false, nil},
	}

	expr := `(lambda o: list(m.validate_bind_source(None, req["label"], req["p"], o, req["home"])))(
		type("O", (), {"home": req["home_opt"], "ro_cwd": req["ro_cwd"],
			"bind_socket": req["bind_socket"] or [], "verbose": False})())`
	var sb strings.Builder
	for _, r := range reqs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	out, err := oracle.RunBatch(oracle.DriverFor(expr), sb.String())
	if err != nil {
		t.Fatalf("oracle batch: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(reqs) {
		t.Fatalf("oracle returned %d lines, want %d", len(lines), len(reqs))
	}

	pinner := NewPinner(false) // path mode == pinner None
	defer pinner.Close()
	for i, r := range reqs {
		var resp [2]any
		if err := json.Unmarshal([]byte(lines[i]), &resp); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if resp[0] != "OK" {
			t.Fatalf("%s %s: oracle error: %v", r.Label, r.P, resp[1])
		}
		py, ok := resp[1].([]any)
		if !ok || len(py) != 4 {
			t.Fatalf("%s %s: unexpected oracle shape %v", r.Label, r.P, resp[1])
		}
		opts := &cliutil.Options{Home: r.HomeOpt, RoCwd: r.RoCwd, BindSocket: r.BindSocket}
		refusal, warning, rp, fd, fatal := ValidateBindSource(pinner, r.Label, r.P, opts, r.Home, nil)
		if fatal != nil {
			t.Fatalf("%s %s: fatal: %v", r.Label, r.P, fatal)
		}
		if fd != nil {
			t.Fatalf("%s %s: path mode must not pin", r.Label, r.P)
		}
		// /proc/self resolves to a different pid in each process —
		// the one legitimate divergence; normalize both sides.
		got := []string{normalizePids(refusal), normalizePids(warning), normalizePids(rp)}
		want := []string{normalizePids(str(py[0])), normalizePids(str(py[1])), normalizePids(str(py[2]))}
		for j := range got {
			if got[j] != want[j] {
				t.Errorf("%s %s: field %d\n  go = %q\n  py = %q", r.Label, r.P, j, got[j], want[j])
			}
		}
	}
}

// normalizePids folds /proc/<pid> spellings so /proc/self comparisons
// (each side resolving to its own pid) stay meaningful.
func normalizePids(s string) string {
	return pidRE.ReplaceAllString(s, "/proc/N")
}

var pidRE = regexp.MustCompile(`/proc/\d+`)

func str(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
