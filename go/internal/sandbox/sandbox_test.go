package sandbox

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/bindpolicy"
	"sbox/internal/cliutil"
	"sbox/internal/oracle"
)

// fmtOps renders ops compactly for goldens: setenv NAME=VALUE,
// proc/dev paths, rw|ro[|-try] src->dst[ fd], tmpfs/dir path perms,
// share-net, chdir path.
func fmtOps(ops []Op) []string {
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		switch o := op.(type) {
		case Setenv:
			out = append(out, "setenv "+o.Name+"="+o.Value)
		case ProcFS:
			out = append(out, "proc "+o.Path)
		case DevFS:
			out = append(out, "dev "+o.Path)
		case ShareNet:
			out = append(out, "share-net")
		case Tmpfs:
			out = append(out, "tmpfs "+o.Path)
		case Mkdir:
			out = append(out, "dir "+o.Path)
		case Chdir:
			out = append(out, "chdir "+o.Dir)
		case Mount:
			mode := "ro"
			if o.RW {
				mode = "rw"
			}
			if o.Try {
				mode += "-try"
			}
			s := mode + " " + o.Src + "->" + o.Dst
			if o.FD != nil {
				s += " fd"
			}
			out = append(out, s)
		}
	}
	return out
}

func requireOps(t *testing.T, got []string, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("ops =\n  %s\nwant\n  %s\n(len %d vs %d)",
			strings.Join(got, "\n  "), strings.Join(want, "\n  "), len(got), len(want))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("ops[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestBuildSpecPlain(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("USER", "tester")
	t.Setenv("TERM", "")
	t.Setenv("LANG", "")
	t.Setenv("PATH", "")
	t.Setenv("XDG_RUNTIME_DIR", "")

	home := filepath.Join(dir, "home")
	cwd := filepath.Join(dir, "proj")
	sand := filepath.Join(dir, "work", "tmp")
	sock := filepath.Join(dir, "work", "net.sock")
	sshCfg := filepath.Join(dir, "work", "ssh_config")
	for _, d := range []string{home, cwd, filepath.Join(dir, "work")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(sshCfg, []byte("Host *\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var warns []string
	spec, err := BuildSpec(&cliutil.Options{}, cwd, sand, sock, home,
		nil, "", sshCfg, nil, func(w string) { warns = append(warns, w) })
	if err != nil {
		t.Fatal(err)
	}
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
	requireOps(t, fmtOps(spec.Ops), []string{
		"setenv HOME=" + home,
		"setenv USER=tester",
		"setenv TERM=xterm-256color",
		"setenv PATH=/usr/local/bin:/usr/bin:/bin",
		"setenv LANG=C.UTF-8",
		"proc /proc",
		"dev /dev",
		"rw " + sand + "->/tmp",
		"ro /usr->/usr",
		"ro-try /lib->/lib",
		"ro-try /lib64->/lib64",
		"ro-try /bin->/bin",
		"ro-try /sbin->/sbin",
		"ro-try /etc/ssl->/etc/ssl",
		"ro-try /etc/pki->/etc/pki",
		"ro-try /etc/ca-certificates->/etc/ca-certificates",
		"ro-try /etc/hosts->/etc/hosts",
		"ro-try /etc/localtime->/etc/localtime",
		"ro-try /etc/passwd->/etc/passwd",
		"ro-try /etc/group->/etc/group",
		"ro-try /etc/alternatives->/etc/alternatives",
		"ro-try /etc/ld.so.cache->/etc/ld.so.cache",
		"tmpfs /run",
		"setenv all_proxy=socks5h://127.0.0.1:1080",
		"setenv ALL_PROXY=socks5h://127.0.0.1:1080",
		"setenv http_proxy=http://127.0.0.1:1080",
		"setenv https_proxy=http://127.0.0.1:1080",
		"setenv HTTP_PROXY=http://127.0.0.1:1080",
		"setenv HTTPS_PROXY=http://127.0.0.1:1080",
		"setenv no_proxy=localhost,127.0.0.1,::1",
		"setenv NO_PROXY=localhost,127.0.0.1,::1",
		"ro " + sock + "->/run/proxy.sock",
		"ro " + sshCfg + "->/etc/ssh/ssh_config",
		"tmpfs " + home,
		"rw " + cwd + "->" + cwd, // the cwd mount, AFTER everything else
		"chdir " + cwd,
	})
	if spec.Bridge != InnerProxy+"exec \"$@\"\n" {
		t.Errorf("bridge = %q", spec.Bridge)
	}
	if spec.Seccomp != nil || spec.DisableUserns {
		t.Error("launcher fills Seccomp/DisableUserns; BuildSpec must not")
	}
}

func TestBuildSpecNetBranch(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("USER", "tester")
	cwd := filepath.Join(dir, "proj")
	if err := os.MkdirAll(cwd, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := BuildSpec(&cliutil.Options{Net: true}, cwd,
		filepath.Join(dir, "sand"), filepath.Join(dir, "sock"), filepath.Join(dir, "home"),
		nil, "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := fmtOps(spec.Ops)
	// no proxy env, no sock mount, no ssh_config; --share-net + the
	// resolver files instead
	for _, bad := range []string{"all_proxy", "/run/proxy.sock", "ssh_config"} {
		for _, g := range got {
			if strings.Contains(g, bad) {
				t.Errorf("%q present in the --share-net branch: %q", bad, g)
			}
		}
	}
	i := indexOf(got, "share-net")
	if i != indexOf(got, "tmpfs /run")+1 {
		t.Errorf("--share-net must directly follow the /run tmpfs: %v", got)
	}
	requireOps(t, got[i:i+5], []string{
		"share-net",
		"ro-try /etc/resolv.conf->/etc/resolv.conf",
		"ro-try /etc/nsswitch.conf->/etc/nsswitch.conf",
		"ro-try /etc/services->/etc/services",
		"ro-try /etc/protocols->/etc/protocols"})
	requireOps(t, got[i+5:], []string{
		"tmpfs " + filepath.Join(dir, "home"),
		"rw " + cwd + "->" + cwd,
		"chdir " + cwd})
	if spec.Bridge != "exec \"$@\"\n" {
		t.Errorf("bridge = %q, want the direct (empty) bridge + exec", spec.Bridge)
	}
}

func indexOf(xs []string, s string) int {
	for i, x := range xs {
		if x == s {
			return i
		}
	}
	return -1
}

func TestBuildSpecHomeGuiAgent(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("USER", "tester")
	home := filepath.Join(dir, "home")
	cwd := filepath.Join(home, "proj")
	rt := filepath.Join(dir, "rt")
	xauth := filepath.Join(dir, "xauth")
	agentSock := mustSocket(t, filepath.Join(dir, "agent.sock"))
	for _, d := range []string{filepath.Join(home, ".config"), cwd, rt} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(xauth, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_RUNTIME_DIR", rt)
	t.Setenv("WAYLAND_DISPLAY", "wayland-0")
	t.Setenv("DISPLAY", ":0")
	t.Setenv("XAUTHORITY", xauth)

	pinner := bindpolicy.NewPinner(true)
	defer pinner.Close()
	var warns []string
	spec, err := BuildSpec(&cliutil.Options{Home: true, Gui: true}, cwd,
		filepath.Join(dir, "sand"), filepath.Join(dir, "sock"), home,
		nil, agentSock, "", pinner, func(w string) { warns = append(warns, w) })
	if err != nil {
		t.Fatal(err)
	}
	got := fmtOps(spec.Ops)
	requireOps(t, got[len(got)-13:], []string{
		// --home: the RESOLVED home, fd-pinned, before the gui block
		"rw " + home + "->" + home + " fd",
		// gui: XDG setenv+dir, wayland (relative -> joined), X11, xauth
		"setenv XDG_RUNTIME_DIR=" + rt,
		"dir " + rt,
		"setenv WAYLAND_DISPLAY=wayland-0",
		"ro-try " + filepath.Join(rt, "wayland-0") + "->" + filepath.Join(rt, "wayland-0"),
		"setenv DISPLAY=:0",
		"ro-try /tmp/.X11-unix->/tmp/.X11-unix",
		"setenv XAUTHORITY=" + xauth,
		"ro-try " + xauth + "->" + xauth,
		// agent: ro socket + fixed in-sandbox path
		"ro " + agentSock + "->/run/ssh-agent.sock",
		"setenv SSH_AUTH_SOCK=/run/ssh-agent.sock",
		// cwd (inside $HOME + --home): pinned, last mount before chdir
		"rw " + cwd + "->" + cwd + " fd",
		"chdir " + cwd,
	})
	if len(warns) != 0 {
		t.Errorf("unexpected warnings: %v", warns)
	}
}

func TestBuildSpecCwdCases(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("USER", "tester")
	t.Setenv("XDG_RUNTIME_DIR", "")
	home := filepath.Join(dir, "home")
	inHome := filepath.Join(home, "proj")
	rt := filepath.Join(dir, "rt")
	bear := filepath.Join(dir, "bear")
	clean := filepath.Join(dir, "clean")
	for _, d := range []string{home, inHome, filepath.Join(rt, "sub"), bear, clean} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	l, err := netListen(filepath.Join(bear, "puma.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	t.Run("cwd inside home without --home", func(t *testing.T) {
		var warns []string
		spec, err := BuildSpec(&cliutil.Options{}, inHome,
			filepath.Join(dir, "sand"), filepath.Join(dir, "sock"), home,
			nil, "", "", nil, func(w string) { warns = append(warns, w) })
		if err != nil {
			t.Fatal(err)
		}
		got := fmtOps(spec.Ops)
		if got[len(got)-1] != "chdir /tmp" || got[len(got)-2] != "tmpfs "+home {
			t.Errorf("tail = %v", got[len(got)-2:])
		}
		if len(warns) != 1 || !strings.Contains(warns[0], "cwd is inside $HOME and $HOME is a tmpfs") {
			t.Errorf("warnings = %v", warns)
		}
	})

	t.Run("refused cwd warns loudly and lands in /tmp", func(t *testing.T) {
		t.Setenv("XDG_RUNTIME_DIR", rt)
		var warns []string
		pinner := bindpolicy.NewPinner(true)
		defer pinner.Close()
		spec, err := BuildSpec(&cliutil.Options{}, filepath.Join(rt, "sub"),
			filepath.Join(dir, "sand"), filepath.Join(dir, "sock"), home,
			nil, "", "", pinner, func(w string) { warns = append(warns, w) })
		if err != nil {
			t.Fatal(err)
		}
		got := fmtOps(spec.Ops)
		if got[len(got)-1] != "chdir /tmp" {
			t.Errorf("tail = %v", got[len(got)-3:])
		}
		for _, g := range got {
			if strings.Contains(g, rt) {
				t.Errorf("refused cwd still mounted: %v", g)
			}
		}
		found := false
		for _, w := range warns {
			if strings.Contains(w, "NOT mounting the cwd; the command runs with the sandbox's /tmp") {
				found = true
			}
		}
		if !found {
			t.Errorf("no NOT-mounting warning: %v", warns)
		}
	})

	t.Run("cwd covered by a user bind is silent and chdirs there", func(t *testing.T) {
		t.Setenv("XDG_RUNTIME_DIR", "")
		var warns []string
		cwd := filepath.Join(bear, "inner")
		if err := os.MkdirAll(cwd, 0o755); err != nil {
			t.Fatal(err)
		}
		spec, err := BuildSpec(&cliutil.Options{}, cwd,
			filepath.Join(dir, "sand"), filepath.Join(dir, "sock"), home,
			[]bindpolicy.Bind{{Flag: "--bind", Path: bear}},
			"", "", nil, func(w string) { warns = append(warns, w) })
		if err != nil {
			t.Fatal(err)
		}
		got := fmtOps(spec.Ops)
		requireOps(t, got[len(got)-2:], []string{
			"rw " + bear + "->" + bear, // the explicit bind, no automatic cwd mount
			"chdir " + cwd,
		})
		// the refusal is silent: the user bind lands the cwd exactly
		// where the user asked
		for _, w := range warns {
			if strings.Contains(w, "NOT mounting the cwd") {
				t.Errorf("covered cwd must not warn: %v", warns)
			}
		}
	})

	t.Run("ro-cwd and user binds order", func(t *testing.T) {
		spec, err := BuildSpec(&cliutil.Options{RoCwd: true}, clean,
			filepath.Join(dir, "sand"), filepath.Join(dir, "sock"), home,
			[]bindpolicy.Bind{{Flag: "--ro-bind", Path: clean}, {Flag: "--bind", Path: bear}},
			"", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		got := fmtOps(spec.Ops)
		requireOps(t, got[len(got)-4:], []string{
			"ro " + clean + "->" + clean, // the automatic cwd mount, FIRST
			"ro " + clean + "->" + clean, // -r of the same path: shadows to ro
			"rw " + bear + "->" + bear,
			"chdir " + clean,
		})
	})
}

func TestAgentSocketPath(t *testing.T) {
	t.Setenv("SSH_AUTH_SOCK", "")
	if _, err := AgentSocketPath(); err == nil ||
		!strings.Contains(err.Error(), "SSH_AUTH_SOCK is not set") {
		t.Errorf("unset: err = %v", err)
	}

	notSock := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(notSock, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSH_AUTH_SOCK", notSock)
	if _, err := AgentSocketPath(); err == nil ||
		!strings.Contains(err.Error(), "is not a Unix socket") {
		t.Errorf("non-socket: err = %v", err)
	}

	sock := mustSocket(t, filepath.Join(t.TempDir(), "agent.sock"))
	t.Setenv("SSH_AUTH_SOCK", "  "+sock+"  ") // trimmed like python's .strip()
	got, err := AgentSocketPath()
	if err != nil {
		t.Fatal(err)
	}
	if got != sock {
		t.Errorf("agent path = %q, want %q", got, sock)
	}

	missing := filepath.Join(t.TempDir(), "gone")
	t.Setenv("SSH_AUTH_SOCK", missing)
	if _, err := AgentSocketPath(); err == nil ||
		!strings.Contains(err.Error(), "is not usable") {
		t.Errorf("missing: err = %v", err)
	}
}

// netListen creates a real filesystem Unix socket and returns the
// listener (close it to release the name).
func netListen(path string) (interface{ Close() error }, error) {
	return net.Listen("unix", path)
}

func mustSocket(t *testing.T, path string) string {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatalf("socket %s: %v", path, err)
	}
	t.Cleanup(func() { l.Close() })
	return path
}

func TestPayloadArgv(t *testing.T) {
	got := PayloadArgv("echo hi\n", []string{"ls", "-l"})
	want := []string{"/bin/sh", "-c", "echo hi\n", "sbox-sh", "ls", "-l"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Errorf("PayloadArgv = %q, want %q", got, want)
	}
}

func TestCapsSeccompFlag(t *testing.T) {
	if got := (Caps{AddSeccompFD: true}).SeccompFlag(); got != "--add-seccomp-fd" {
		t.Errorf("modern flag = %q", got)
	}
	if got := (Caps{LegacySeccomp: true}).SeccompFlag(); got != "--seccomp" {
		t.Errorf("legacy flag = %q", got)
	}
	if got := (Caps{}).SeccompFlag(); got != "" {
		t.Errorf("no-flag = %q", got)
	}
	if got := (Caps{AddSeccompFD: true, LegacySeccomp: true}).SeccompFlag(); got != "--add-seccomp-fd" {
		t.Errorf("current spelling wins: %q", got)
	}
}

func TestPyJoin(t *testing.T) {
	for _, tc := range []struct{ a, b, want string }{
		{"/run/user/1000", "wayland-0", "/run/user/1000/wayland-0"},
		{"/run/user/1000/", "wayland-0", "/run/user/1000/wayland-0"}, // no double slash
		{"/", ".Xauthority", "/.Xauthority"},
		{"", "x", "x"},     // python: join("", "x") == "x"
		{"/a", "/b", "/b"}, // absolute b discards a
		{"/home/u", ".Xauthority", "/home/u/.Xauthority"},
	} {
		if got := pyJoin(tc.a, tc.b); got != tc.want {
			t.Errorf("pyJoin(%q, %q) = %q, want %q", tc.a, tc.b, got, tc.want)
		}
	}
}

// TestSSHClientConfigMatchesOracle pins the installed ssh_config text
// against sbox.py's SSH_CLIENT_CONFIG, modulo the documented binary-name
// delta in the header comment.
func TestSSHClientConfigMatchesOracle(t *testing.T) {
	if !oracle.Available() {
		t.Skip("differential oracle unavailable: python3 + sbox.py not found (set $SBOX_PY / $SBOX_PYTHON)")
	}
	out, err := oracle.RunBatch(oracle.DriverFor(`m.SSH_CLIENT_CONFIG`), "{}\n")
	if err != nil {
		t.Fatal(err)
	}
	var resp [2]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatal(err)
	}
	if resp[0] != "OK" {
		t.Fatalf("oracle error: %v", resp[1])
	}
	py, _ := resp[1].(string)
	want := strings.Replace(py, "Generated by sbox.py:", "Generated by sbox:", 1)
	if SSHClientConfig != want {
		t.Errorf("SSHClientConfig diverges from sbox.py (beyond the name delta)\n  go = %q\n  py = %q", SSHClientConfig, py)
	}
}
