package bwrap

// Exercise complete launch construction across mount and network modes.

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/bindpolicy"
	"sbox/internal/cliutil"
	"sbox/internal/sandbox"
)

type launchCase struct {
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

// caseEnv supplies the GUI environment for each launch.
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

func TestBuildLaunchMatrix(t *testing.T) {
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

	cases := []launchCase{
		{name: "plain pinned", cwd: proj, pinner: true},
		{name: "plain unpinned (old bwrap)", cwd: proj},
		{name: "net + gui + agent", cwd: proj, net: true, gui: true, agent: agent},
		{name: "home + ro-cwd + binds", cwd: proj, home: true, roCwd: true, pinner: true,
			binds: []bindpolicy.Bind{{Flag: "--bind", Path: proj}, {Flag: "--ro-bind", Path: projFile}}},
		{name: "ssh config in proxied mode", cwd: proj, pinner: true, sshCfg: sshCfg},
		{name: "cwd inside home, no --home", cwd: filepath.Join(home, "sub"), pinner: true},
		{name: "refused cwd (runtime ground)", cwd: filepath.Join(rt, "sub"), pinner: true},
		{name: "cwd covered by socket-bearing bind", cwd: filepath.Join(bear, "inner"), pinner: true,
			binds: []bindpolicy.Bind{{Flag: "--bind", Path: bear}}},
	}

	bridge, err := os.ReadFile("testdata/bridge.sh")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEnv(t, caseEnv(rt, tc.gui, xauth))
			pinner := bindpolicy.NewPinner(tc.pinner)
			defer pinner.Close()
			opts := &cliutil.Options{Net: tc.net, Home: tc.home, Gui: tc.gui, RoCwd: tc.roCwd}
			spec, err := sandbox.BuildSpec(opts, tc.cwd, sand, sock, home, tc.binds,
				nil, tc.agent, tc.sshCfg, pinner, func(string) {})
			if err != nil {
				t.Fatal(err)
			}
			prov := New("")
			prov.Caps = sandbox.Caps{BindFD: tc.pinner}
			launch, err := prov.Build(spec)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				for _, fd := range launch.CloseAfterSpawn {
					fd.Close()
				}
			}()
			argv := strings.Join(launch.Argv, "\x00")
			contains := func(tokens ...string) bool {
				return strings.Contains("\x00"+argv+"\x00", "\x00"+strings.Join(tokens, "\x00")+"\x00")
			}
			for _, flag := range []string{"--unshare-all", "--die-with-parent", "--new-session", "--as-pid-1", "--clearenv"} {
				if !contains(flag) {
					t.Errorf("missing hardening flag %s", flag)
				}
			}
			if contains("--share-net") != tc.net || contains("--ro-bind", sock, "/run/proxy.sock") == tc.net {
				t.Errorf("wrong network mode: %v", launch.Argv)
			}
			wantBridge := string(bridge)
			if tc.net {
				wantBridge = "exec \"$@\"\n"
			}
			if spec.Bridge != wantBridge {
				t.Errorf("bridge = %q, want %q", spec.Bridge, wantBridge)
			}
			if contains("--tmpfs", home) == tc.home {
				t.Errorf("wrong home mode: %v", launch.Argv)
			}
			wantCwd := tc.cwd
			if tc.name == "cwd inside home, no --home" || tc.name == "refused cwd (runtime ground)" {
				wantCwd = "/tmp"
			}
			if !strings.HasSuffix(argv, "--chdir\x00"+wantCwd) {
				t.Errorf("cwd = %q, want %q", lastChdir(spec), wantCwd)
			}
			if contains("--ro-bind", agent, "/run/ssh-agent.sock") != (tc.agent != "") {
				t.Error("wrong agent forwarding")
			}
			if contains("--ro-bind", sshCfg, "/etc/ssh/ssh_config") != (tc.sshCfg != "" && !tc.net) {
				t.Error("wrong SSH configuration mount")
			}
			if tc.gui && (!contains("--setenv", "WAYLAND_DISPLAY", "wayland-0") ||
				!contains("--setenv", "DISPLAY", ":0") || !contains("--ro-bind-try", xauth, xauth)) {
				t.Error("missing GUI environment or Xauthority mount")
			}
			// Explicit binds follow the automatic cwd mount, so their mode wins.
			last := -1
			for _, b := range tc.binds {
				at := strings.Index(argv, strings.Join([]string{b.Flag, b.Path, b.Path}, "\x00"))
				if at < 0 || at <= last {
					t.Errorf("missing or reordered user bind: %+v", b)
				}
				last = at
			}
			if tc.home && tc.roCwd && !contains("--ro-bind-fd", "4", proj) {
				t.Error("read-only automatic cwd must precede explicit writable bind")
			}
			if !tc.pinner && len(launch.PassFDs) != 0 {
				t.Errorf("path-based launch leaked %d descriptors", len(launch.PassFDs))
			}
			for _, fd := range launch.PassFDs {
				if _, err := fd.Stat(); err != nil {
					t.Errorf("launch contains closed fd: %v", err)
				}
			}
		})
	}
}
