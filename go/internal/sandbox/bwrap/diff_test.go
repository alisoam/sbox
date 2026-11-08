package bwrap

// The differential cross-check for the sandbox layer: identical inputs
// (CLI options, cwd, fixtures, environment, user binds, agent/ssh
// paths) to this port's BuildSpec + Build and to sbox.py's
// build_bwrap, comparing the full bwrap argv and the inner bridge
// script. The argv SHAPE is part of the observable behavior this port
// keeps faithful (mount order is load-bearing: the cwd mount before the
// user binds, later binds shadowing earlier ones), so it is compared
// token by token. The one legitimate divergence is fd NUMBERING:
// python passes parent fd numbers, this port owns the child numbering
// via cmd.ExtraFiles — both sides' fd tokens (the argument after
// --bind-fd/--ro-bind-fd) are canonicalized to FD1, FD2, … in order of
// first appearance, and both sides emit the same sequence of uses.
// The other is the bridge's self-name in the not-ready warning
// ("sbox.py:" → "sbox:", the documented binary-name delta).
//
// Everything skips cleanly when python3 or sbox.py is missing ($SBOX_PY
// / $SBOX_PYTHON override), so the suite stays green without the oracle.

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/bindpolicy"
	"sbox/internal/cliutil"
	"sbox/internal/oracle"
	"sbox/internal/sandbox"
)

func requireOracle(t *testing.T) {
	t.Helper()
	if !oracle.Available() {
		t.Skip("differential oracle unavailable: python3 + sbox.py not found (set $SBOX_PY / $SBOX_PYTHON)")
	}
}

type diffCase struct {
	name   string
	cwd    string
	net    bool
	home   bool
	gui    bool
	roCwd  bool
	binds  []bindpolicy.Bind
	agent  string
	sshCfg string
	pinner bool
}

// caseEnv is the per-case environment slice build_bwrap reads. One
// python child serves the whole batch, so the varying variables travel
// inside each request (the fixed ones — HOME, USER — are inherited).
func caseEnv(rt string, gui bool, xauth string) map[string]string {
	env := map[string]string{
		"XDG_RUNTIME_DIR": rt,
		"WAYLAND_DISPLAY": "",
		"DISPLAY":         "",
		"XAUTHORITY":      "",
	}
	if gui {
		env["WAYLAND_DISPLAY"] = "wayland-0"
		env["DISPLAY"] = ":0"
		env["XAUTHORITY"] = xauth
	}
	return env
}

func setEnv(t *testing.T, env map[string]string) {
	t.Helper()
	for k, v := range env {
		t.Setenv(k, v)
	}
}

func TestDifferentialBuildBwrap(t *testing.T) {
	requireOracle(t)

	dir := t.TempDir()
	neutral := filepath.Join(dir, "neutral-home")
	home := filepath.Join(dir, "home")
	rt := filepath.Join(dir, "rt")
	proj := filepath.Join(dir, "proj")
	bear := filepath.Join(dir, "bear")
	sand := filepath.Join(dir, "work", "tmp")
	sock := filepath.Join(dir, "work", "net.sock")
	sshCfg := filepath.Join(dir, "work", "ssh_config")
	xauth := filepath.Join(dir, "xauth")
	projFile := filepath.Join(dir, "proj.txt")
	for _, d := range []string{neutral, home, filepath.Join(home, "sub"), rt,
		filepath.Join(rt, "sub"), proj, filepath.Join(bear, "inner"), filepath.Join(dir, "work")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{sshCfg, xauth, projFile} {
		if err := os.WriteFile(f, []byte("x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	agentL, err := net.Listen("unix", filepath.Join(dir, "agent.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer agentL.Close()
	bearL, err := net.Listen("unix", filepath.Join(bear, "puma.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer bearL.Close()
	agent := filepath.Join(dir, "agent.sock")

	t.Setenv("HOME", neutral) // the ~ control-socket entries resolve neutrally
	t.Setenv("USER", "tester")

	cases := []diffCase{
		{name: "plain pinned", cwd: dir, pinner: true},
		{name: "plain unpinned (old bwrap)", cwd: dir},
		{name: "net + gui + agent", cwd: dir, net: true, gui: true, agent: agent},
		{name: "home + ro-cwd + binds", cwd: proj, home: true, roCwd: true, pinner: true,
			binds: []bindpolicy.Bind{{Flag: "--bind", Path: proj}, {Flag: "--ro-bind", Path: projFile}}},
		{name: "ssh config in proxied mode", cwd: dir, pinner: true, sshCfg: sshCfg},
		{name: "cwd inside home, no --home", cwd: filepath.Join(home, "sub"), pinner: true},
		{name: "refused cwd (runtime ground)", cwd: filepath.Join(rt, "sub"), pinner: true},
		{name: "cwd covered by socket-bearing bind", cwd: filepath.Join(bear, "inner"), pinner: true,
			binds: []bindpolicy.Bind{{Flag: "--bind", Path: bear}}},
	}

	// python side: one batch; the driver sets the per-case environment
	// (the eval scope has no os binding — sbox.py's own module import
	// provides it), chdirs to the case cwd, and runs build_bwrap with
	// the same parameters this port's BuildSpec takes.
	expr := `(lambda o, p: (lambda r: [r[0], r[1]])(
		(m.os.environ.update(req["env"]),
		 m.os.chdir(req["cwd"]),
		 m.build_bwrap(o, req["sand"], req["sock"], req["home"],
			[(b["flag"], b["rp"], None) for b in req["binds"]],
			req["agent"] or None, req["ssh_cfg"] or None, p))[2]))(
		type("O", (), {"net": req["net"], "home": req["home_opt"], "gui": req["gui"],
			"ro_cwd": req["ro_cwd"], "bind_socket": [], "verbose": False})(),
		m.BindPinner(True) if req["pinner"] else None)`

	var in strings.Builder
	enc := json.NewEncoder(&in)
	for _, tc := range cases {
		binds := []map[string]string{}
		for _, b := range tc.binds {
			binds = append(binds, map[string]string{"flag": b.Flag, "rp": b.Path})
		}
		if err := enc.Encode(map[string]any{
			"cwd": tc.cwd, "net": tc.net, "home_opt": tc.home, "gui": tc.gui,
			"ro_cwd": tc.roCwd, "binds": binds, "agent": tc.agent,
			"ssh_cfg": tc.sshCfg, "pinner": tc.pinner,
			"sand": sand, "sock": sock, "home": home,
			"env": caseEnv(rt, tc.gui, xauth),
		}); err != nil {
			t.Fatal(err)
		}
	}
	out, err := oracle.RunBatch(oracle.DriverFor(expr), in.String())
	if err != nil {
		t.Fatalf("oracle batch: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != len(cases) {
		t.Fatalf("oracle returned %d lines, want %d", len(lines), len(cases))
	}

	prov := New("")
	prov.Caps = sandbox.Caps{BindFD: true} // pinner-on cases emit fd mounts
	for i, tc := range cases {
		var resp [2]any
		if err := json.Unmarshal([]byte(lines[i]), &resp); err != nil {
			t.Fatalf("line %d: %v", i, err)
		}
		if resp[0] != "OK" {
			t.Fatalf("%s: oracle error: %v", tc.name, resp[1])
		}
		py, ok := resp[1].([]any)
		if !ok || len(py) != 2 {
			t.Fatalf("%s: unexpected oracle shape %v", tc.name, resp[1])
		}
		pyArgv := jsonStrings(py[0])
		pyInner, _ := py[1].(string)

		setEnv(t, caseEnv(rt, tc.gui, xauth))
		pinner := bindpolicy.NewPinner(tc.pinner)
		opts := &cliutil.Options{Net: tc.net, Home: tc.home, Gui: tc.gui, RoCwd: tc.roCwd}
		spec, err := sandbox.BuildSpec(opts, tc.cwd, sand, sock, home, tc.binds,
			tc.agent, tc.sshCfg, pinner, func(string) {})
		if err != nil {
			t.Fatalf("%s: BuildSpec: %v", tc.name, err)
		}
		pinner.Close()
		l, err := prov.Build(spec)
		if err != nil {
			t.Fatalf("%s: Build: %v", tc.name, err)
		}

		gotArgv := canonicalArgv(l.Argv)
		wantArgv := canonicalArgv(pyArgv)
		if strings.Join(gotArgv, "\x00") != strings.Join(wantArgv, "\x00") {
			t.Errorf("%s: argv diverges from sbox.py\n  go = %s\n  py = %s",
				tc.name, strings.Join(gotArgv, " "), strings.Join(wantArgv, " "))
		}
		wantInner := strings.ReplaceAll(pyInner, "sbox.py: warning:", "sbox: warning:")
		if spec.Bridge != wantInner {
			t.Errorf("%s: bridge diverges\n  go = %q\n  py = %q", tc.name, spec.Bridge, wantInner)
		}
	}
}

func jsonStrings(v any) []string {
	items, _ := v.([]any)
	out := make([]string, 0, len(items))
	for _, it := range items {
		s, _ := it.(string)
		out = append(out, s)
	}
	return out
}

// canonicalArgv replaces every fd NUMBER the argv names (the token
// after --bind-fd/--ro-bind-fd) with FD1, FD2, … in order of first
// appearance: parent-fd numbers (python) and ExtraFiles numbers (this
// port) are both arbitrary, but the SEQUENCE of uses is the spec.
func canonicalArgv(argv []string) []string {
	out := make([]string, len(argv))
	ids := map[string]string{}
	next := 0
	for i, a := range argv {
		if i > 0 && (argv[i-1] == "--bind-fd" || argv[i-1] == "--ro-bind-fd") {
			if _, ok := ids[a]; !ok {
				next++
				ids[a] = fmt.Sprintf("FD%d", next)
			}
			out[i] = ids[a]
		} else {
			out[i] = a
		}
	}
	return out
}
