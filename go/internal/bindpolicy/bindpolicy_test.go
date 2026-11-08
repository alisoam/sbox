package bindpolicy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/cliutil"
)

func TestCovers(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"/run", "/run", true},
		{"/run", "/run/user/1000", true},
		{"/run", "/runaway", false}, // component boundary, not prefix
		{"/", "/anything", true},    // the rstrip quirk: "" + "/" prefixes every abs path
		{"/", "/", true},
		{"/a/b", "/a/b/c", true},
		{"/a/b/c", "/a/b", false},
		{"/a//b", "/a/b/c", false}, // b is compared verbatim (realpaths)
	} {
		if got := Covers(tc.a, tc.b); got != tc.want {
			t.Errorf("Covers(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
}

func TestProtectedPaths(t *testing.T) {
	home := "/home/tester"
	t.Setenv("XDG_RUNTIME_DIR", "/xdg/runtime")
	got := map[string]bool{}
	for _, p := range ProtectedPaths(home) {
		got[p] = true
	}
	for _, want := range append([]string{"/etc", "/usr", "/run", "/tmp", "/var", "/"},
		home, "/run/user", "/run/user/1000", "/xdg/runtime") {
		if !got[want] {
			t.Errorf("ProtectedPaths missing %q (have %v)", want, got)
		}
	}
}

func TestControlSocketsTable(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	got := map[string]bool{}
	for _, cs := range ControlSockets() {
		got[cs.Path] = true
	}
	for _, want := range []string{
		"/run/docker.sock", "/var/run/docker.sock",
		"/run/containerd", // daemon DIRECTORY
		"/run/systemd/private", "/run/systemd/journal/socket",
		"/run/snapd.socket", "/run/tailscale/tailscaled.sock",
		"/run/incus/unix.socket", "/var/snap/lxd/common/lxd/unix.socket",
		"/tmp/.X11-unix", "/tmp/.ICE-unix",
		"/tmp/tmux-1000",
		"/run/user/1000/bus", "/run/user/1000/pipewire-0",
		"/run/user/1000/gnupg/S.gpg-agent", "/run/user/1000/keyring",
		"/home/tester/.1password/agent.sock", // $HOME expanded, NOT resolved
		"/home/tester/.docker/run/docker.sock",
		"/home/tester/.colima/default/docker.sock",
	} {
		if !got[want] {
			t.Errorf("ControlSockets missing %q", want)
		}
	}

	// no $HOME ⇒ the ~ entries drop entirely
	t.Setenv("HOME", "")
	for _, cs := range ControlSockets() {
		if strings.HasPrefix(cs.Path, "~/") || strings.Contains(cs.Path, "/home/") {
			t.Errorf("ControlSockets with empty $HOME still carries a ~ entry: %q", cs.Path)
		}
	}
}

func TestRuntimeRootsResolveXDG(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(dir, "link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "link"))
	roots := RuntimeRoots()
	found := false
	for _, r := range roots {
		if r == real {
			found = true
		}
	}
	if !found {
		t.Errorf("RuntimeRoots must carry the RESOLVED $XDG_RUNTIME_DIR: %v", roots)
	}
	if !IsRuntimeGround(filepath.Join(real, "x")) {
		t.Error("path under the resolved runtime root must be runtime ground")
	}
}

func TestPersistencePathsAndWarning(t *testing.T) {
	home := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	got := map[string]bool{}
	for _, p := range PersistencePaths(home) {
		got[p] = true
	}
	for _, want := range []string{
		filepath.Join(home, ".bashrc"), filepath.Join(home, ".bash_profile"),
		filepath.Join(home, ".zshrc"), filepath.Join(home, ".kshrc"),
		filepath.Join(home, ".gitconfig"), filepath.Join(home, ".emacs"),
		filepath.Join(home, ".vimrc"), filepath.Join(home, ".pam_environment"),
		filepath.Join(home, ".xsessionrc"),
		filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(home, ".local", "bin"), filepath.Join(home, ".cargo", "bin"),
		filepath.Join(home, "go", "bin"),
		filepath.Join(home, ".config", "git", "config"),
		filepath.Join(home, ".config", "nvim"),
		filepath.Join(home, ".config", "systemd", "user"),
		filepath.Join(home, ".config", "autostart"),
		filepath.Join(home, ".config", "environment.d"),
		filepath.Join(home, ".local", "share", "systemd", "user"),
		filepath.Join(home, ".local", "share", "applications"),
		filepath.Join(home, ".config", "fish", "config.fish"),
	} {
		if !got[want] {
			t.Errorf("PersistencePaths missing %q", want)
		}
	}

	w := PersistenceWarning("--bind", home+"/.local/bin", home+"/.local/bin", home)
	if !strings.HasPrefix(w, "note: --bind ") || !strings.Contains(w, "covers host persistence path(s): "+filepath.Join(home, ".local/bin")) {
		t.Errorf("warning = %q", w)
	}
	// both directions: a single tool INSIDE ~/.local/bin warns the same way
	w = PersistenceWarning("--bind", home+"/.local/bin/mytool", home+"/.local/bin/mytool", home)
	if !strings.Contains(w, filepath.Join(home, ".local/bin")) {
		t.Errorf("descendant warning = %q", w)
	}
	if PersistenceWarning("--ro-bind", home+"/.local/bin", home+"/.local/bin", home) == "" {
		t.Error("the helper is label-agnostic; the rw/ro gating lives in the callers")
	}
}

// TestCheckBindPaths pins the mount-mode promises: flags, refusals and
// warnings of check_bind_paths, row for row.
func TestCheckBindPaths(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	rt := filepath.Join(dir, "rt")
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("HOME", home) // the ~/.docker, ~/.colima control entries expand from it

	clean := filepath.Join(dir, "clean")
	homeLocal := filepath.Join(home, ".local", "bin")
	tool := filepath.Join(homeLocal, "mytool")
	homeProj := filepath.Join(home, "proj")
	bear := filepath.Join(dir, "bear")
	sock := filepath.Join(dir, "sock")
	bashrc := filepath.Join(home, ".bashrc")
	nvimCfg := filepath.Join(home, ".config", "nvim") // a persistence path that is a dir
	for _, d := range []string{clean, rt, filepath.Join(rt, "sub"), homeLocal, homeProj,
		filepath.Join(bear, ".git"), nvimCfg} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(tool, []byte("x"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bashrc, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustSocketAt(t, sock)
	mustSocketAt(t, filepath.Join(bear, ".git", "fsmonitor--daemon.ipc"))
	mustSocketAt(t, filepath.Join(homeProj, "puma.sock"))
	mustSocketAt(t, filepath.Join(nvimCfg, "server.sock"))
	if err := os.Symlink(clean, filepath.Join(dir, "cleanlink")); err != nil {
		t.Fatal(err)
	}

	run := func(t *testing.T, opts *cliutil.Options) ([]Bind, []string, string) {
		t.Helper()
		pinner := NewPinner(true)
		defer pinner.Close()
		var warns []string
		binds, err := CheckBindPaths(opts, home, pinner, func(w string) { warns = append(warns, w) })
		if err != nil {
			return nil, warns, err.Error()
		}
		return binds, warns, ""
	}
	flags := func(binds []Bind) []string {
		out := []string{}
		for _, b := range binds {
			out = append(out, b.Flag+" "+b.Path)
		}
		return out
	}

	for _, tc := range []struct {
		name      string
		opts      *cliutil.Options
		wantFlags []string
		refusal   string // substring of the fatal error, when refused
		warnSub   string // substring expected in some warning
		noWarn    bool
		fdWanted  bool
	}{
		{
			name:      "clean dir -b mounts rw with a pin",
			opts:      &cliutil.Options{Bind: []string{clean}},
			wantFlags: []string{"--bind " + clean},
			fdWanted:  true,
		},
		{
			name:      "clean dir -r mounts ro",
			opts:      &cliutil.Options{RoBind: []string{clean}},
			wantFlags: []string{"--ro-bind " + clean},
			fdWanted:  true,
		},
		{
			name:      "symlinked spelling resolves to the real path",
			opts:      &cliutil.Options{Bind: []string{filepath.Join(dir, "cleanlink")}},
			wantFlags: []string{"--bind " + clean},
			fdWanted:  true,
		},
		{
			name:    "missing -b source is fatal",
			opts:    &cliutil.Options{Bind: []string{filepath.Join(dir, "missing")}},
			refusal: "cannot pin bind source",
		},
		{
			name:    "system dir -b refused (covers protected)",
			opts:    &cliutil.Options{Bind: []string{"/etc"}},
			refusal: "covers protected path(s): /etc",
		},
		{
			name:    "/tmp itself refused (in SYSTEM_DIRS)",
			opts:    &cliutil.Options{Bind: []string{"/tmp"}},
			refusal: "covers protected path(s): /tmp",
		},
		{
			name:    "$HOME -b refused without --home",
			opts:    &cliutil.Options{Bind: []string{home}},
			refusal: "use --home to bind $HOME itself",
		},
		{
			name:      "-b $HOME with --home is exempt from socket rules",
			opts:      &cliutil.Options{Bind: []string{home}, Home: true},
			wantFlags: []string{"--bind " + home},
			fdWanted:  true,
		},
		{
			name:    "inside /proc refused for every label",
			opts:    &cliutil.Options{BindSocket: []string{"/proc/1"}},
			refusal: "is inside /proc — kernel/pseudo-fs ground",
		},
		{
			name:    "/proc/self realpath'd and refused (the bind-socket case)",
			opts:    &cliutil.Options{BindSocket: []string{"/proc/self"}},
			refusal: "is inside /proc",
		},
		{
			name:    "runtime ground rw refused, read-only recipe given",
			opts:    &cliutil.Options{Bind: []string{filepath.Join(rt, "sub")}},
			refusal: "read-only works: -r PATH --bind-socket PATH",
		},
		{
			name:    "runtime ground -r needs the explicit opt-in",
			opts:    &cliutil.Options{RoBind: []string{filepath.Join(rt, "sub")}},
			refusal: "pass --bind-socket to bind it anyway",
		},
		{
			name:      "runtime ground --bind-socket mounts ro in path form when missing",
			opts:      &cliutil.Options{BindSocket: []string{filepath.Join(rt, "nosock")}},
			wantFlags: []string{"--ro-bind " + filepath.Join(rt, "nosock")},
		},
		{
			name:      "existing runtime dir --bind-socket stays connect-only ro",
			opts:      &cliutil.Options{BindSocket: []string{filepath.Join(rt, "sub")}},
			wantFlags: []string{"--ro-bind " + filepath.Join(rt, "sub")},
			fdWanted:  true,
		},
		{
			name:    "socket file -b refused (never read-write)",
			opts:    &cliutil.Options{Bind: []string{sock}},
			refusal: "is a socket or lives under a runtime dir — connect-only ground",
		},
		{
			name:    "socket file -r refused without opt-in",
			opts:    &cliutil.Options{RoBind: []string{sock}},
			refusal: "pass --bind-socket to bind it anyway",
		},
		{
			name:      "socket file --bind-socket mounts ro",
			opts:      &cliutil.Options{BindSocket: []string{sock}},
			wantFlags: []string{"--ro-bind " + sock},
			fdWanted:  true,
		},
		{
			name:    "socket-bearing dir -b refused by the scan",
			opts:    &cliutil.Options{Bind: []string{bear}},
			refusal: "contains a Unix socket",
		},
		{
			name:      "socket-bearing dir --bind-socket opts in READ-WRITE",
			opts:      &cliutil.Options{BindSocket: []string{bear}},
			wantFlags: []string{"--bind " + bear},
			fdWanted:  true,
		},
		{
			name:      "-r + --bind-socket of a socket dir stays read-only",
			opts:      &cliutil.Options{RoBind: []string{bear}, BindSocket: []string{bear}},
			wantFlags: []string{"--ro-bind " + bear},
			fdWanted:  true,
		},
		{
			name:    "known control socket dir refused even with --bind-socket",
			opts:    &cliutil.Options{BindSocket: []string{"/tmp/.X11-unix"}},
			refusal: "overlaps host control socket(s): /tmp/.X11-unix",
		},
		{
			name:    "X11 socket inside the listed dir refused bidirectionally",
			opts:    &cliutil.Options{Bind: []string{"/tmp/.X11-unix/X0"}},
			refusal: "overlaps host control socket(s)",
		},
		{
			name:    "$HOME control socket (docker desktop) refused",
			opts:    &cliutil.Options{Bind: []string{filepath.Join(home, ".docker", "run", "docker.sock")}},
			refusal: "overlaps host control socket(s)",
		},
		{
			name:      "rw -b of ~/.local/bin warns",
			opts:      &cliutil.Options{Bind: []string{homeLocal}},
			wantFlags: []string{"--bind " + homeLocal},
			warnSub:   "covers host persistence path(s): " + homeLocal,
			fdWanted:  true,
		},
		{
			name:      "rw -b of a single tool inside ~/.local/bin warns too",
			opts:      &cliutil.Options{Bind: []string{tool}},
			wantFlags: []string{"--bind " + tool},
			warnSub:   filepath.Join(home, ".local", "bin"),
			fdWanted:  true,
		},
		{
			name:      "ro -r of a persistence path never warns",
			opts:      &cliutil.Options{RoBind: []string{filepath.Join(home, ".bashrc")}},
			wantFlags: []string{"--ro-bind " + filepath.Join(home, ".bashrc")},
			noWarn:    true,
			fdWanted:  true,
		},
		{
			name:      "rw --bind-socket dir over a persistence path warns",
			opts:      &cliutil.Options{BindSocket: []string{nvimCfg}},
			wantFlags: []string{"--bind " + nvimCfg},
			warnSub:   "covers host persistence path(s): " + nvimCfg,
			fdWanted:  true,
		},
		{
			// sbox.py's flag re-seed regression: a plain dir set the
			// --bind-socket group's flag to rw, and the stale decision
			// carried into the NEXT path — a runtime-dir socket then
			// mounted READ-WRITE, exactly the impersonation the rules
			// refuse. The flag must re-seed per path.
			name:      "flag re-seeds: plain dir then runtime dir",
			opts:      &cliutil.Options{BindSocket: []string{bear, filepath.Join(rt, "sub")}},
			wantFlags: []string{"--bind " + bear, "--ro-bind " + filepath.Join(rt, "sub")},
			fdWanted:  true,
		},
		{
			// realpath("") is the CURRENT DIRECTORY (CPython >= 3.13; the
			// oracle pins it): -b '' validates the cwd like any path.
			name:      "empty -b path resolves to the cwd",
			opts:      &cliutil.Options{Bind: []string{""}},
			wantFlags: []string{"--bind " + mustCwd(t)},
			fdWanted:  true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			binds, warns, refusal := run(t, tc.opts)
			if tc.refusal != "" {
				if refusal == "" {
					t.Fatalf("want refusal containing %q, got mounts %v", tc.refusal, flags(binds))
				}
				if !strings.Contains(refusal, tc.refusal) {
					t.Fatalf("refusal %q does not contain %q", refusal, tc.refusal)
				}
				return
			}
			if refusal != "" {
				t.Fatalf("unexpected refusal: %s", refusal)
			}
			if got := flags(binds); len(got) != len(tc.wantFlags) {
				t.Fatalf("mounts = %v, want %v", got, tc.wantFlags)
			} else {
				for i := range got {
					if got[i] != tc.wantFlags[i] {
						t.Fatalf("mounts = %v, want %v (mismatch at %d)", got, tc.wantFlags, i)
					}
				}
			}
			if tc.fdWanted {
				for _, b := range binds {
					if b.FD == nil {
						t.Errorf("mount %v carries no pinned fd", b)
					}
				}
			}
			if tc.warnSub != "" {
				found := false
				for _, w := range warns {
					if strings.Contains(w, tc.warnSub) {
						found = true
					}
				}
				if !found {
					t.Errorf("no warning contains %q (warnings: %v)", tc.warnSub, warns)
				}
			}
			if tc.noWarn && len(warns) > 0 {
				t.Errorf("unexpected warnings: %v", warns)
			}
		})
	}
}

// TestCwdLabel: the automatic cwd mount reuses ValidateBindSource with
// label "cwd" — rw default refuses runtime ground with the --ro-cwd
// recipe, --ro-cwd downgrades to the plain opt-in demand, a socket-
// bearing cwd is caught by the scan, and --bind-socket opts back in.
func TestCwdLabel(t *testing.T) {
	dir := t.TempDir()
	rt := filepath.Join(dir, "rt")
	t.Setenv("XDG_RUNTIME_DIR", rt)
	bear := filepath.Join(dir, "bear")
	for _, d := range []string{rt, filepath.Join(rt, "sub"), bear} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mustSocketAt(t, filepath.Join(bear, "puma.sock"))

	check := func(p string, opts *cliutil.Options) string {
		pinner := NewPinner(true)
		defer pinner.Close()
		refusal, _, _, _, fatal := ValidateBindSource(pinner, "cwd", p, opts, filepath.Join(dir, "home"), func(string) {})
		if fatal != nil {
			t.Fatal(fatal)
		}
		return refusal
	}
	rtdir := filepath.Join(rt, "sub")

	if r := check(rtdir, &cliutil.Options{}); !strings.Contains(r, "read-only works: --ro-cwd --bind-socket \"$PWD\"") {
		t.Errorf("cwd rw refusal = %q", r)
	}
	// connect-only ground never mounts rw even WITH --bind-socket: the
	// auto cwd mount needs --ro-cwd (that is what the recipe says).
	if r := check(rtdir, &cliutil.Options{BindSocket: []string{rtdir}}); !strings.Contains(r, "never mounts read-write") {
		t.Errorf("--bind-socket alone must not rw-mount a runtime cwd: %q", r)
	}
	if r := check(rtdir, &cliutil.Options{RoCwd: true, BindSocket: []string{rtdir}}); r != "" {
		t.Errorf("--ro-cwd --bind-socket must be allowed, got %q", r)
	}
	// --ro-cwd without the opt-in downgrades to the plain demand
	if r := check(rtdir, &cliutil.Options{RoCwd: true}); !strings.Contains(r, "pass --bind-socket to bind it anyway") {
		t.Errorf("ro-cwd refusal = %q", r)
	}
	// a socket-bearing cwd (not runtime ground) is caught by the scan
	if r := check(bear, &cliutil.Options{}); !strings.Contains(r, "contains a Unix socket") {
		t.Errorf("socket-bearing cwd refusal = %q", r)
	}
	if r := check(bear, &cliutil.Options{BindSocket: []string{bear}}); r != "" {
		t.Errorf("--bind-socket of the socket-bearing cwd must be allowed, got %q", r)
	}
}

// TestHomeNote: --home surfaces known control sockets living inside $HOME.
func TestHomeNote(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Join(home, ".docker", "run"), 0o755); err != nil {
		t.Fatal(err)
	}
	dockerSock := filepath.Join(home, ".docker", "run", "docker.sock")
	if err := os.WriteFile(dockerSock, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	var warns []string
	pinner := NewPinner(true)
	defer pinner.Close()
	if _, err := CheckBindPaths(&cliutil.Options{Home: true}, home, pinner,
		func(w string) { warns = append(warns, w) }); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, w := range warns {
		if strings.Contains(w, "--home carries known control socket(s)") && strings.Contains(w, dockerSock) {
			found = true
		}
	}
	if !found {
		t.Errorf("no --home control-socket note: %v", warns)
	}
}
