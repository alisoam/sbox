// Package sandbox is the backend-neutral core of the launcher: the Spec
// (everything the launcher decided, validated, in the exact order the
// sandbox must see it), the Provider interface (one implementation per
// sandboxing backend — only internal/sandbox/bwrap knows bwrap's flag
// spellings; swapping bwrap for a pure-Go clone() backend later means
// writing that one package), and BuildSpec, which defines launch policy: the cleared environment, the system
// mounts, the proxy-env branch vs the --share-net branch, --home's
// pinned realpath, gui, ssh-agent, the fd-validated cwd mount emitted
// BEFORE the user binds, --chdir, and the in-sandbox bridge script.
//
// supervisor.go is the launch owner: the 0700
// $WORK, the in-process proxy goroutine with readiness checks and the
// fail-closed self-test, the seccomp gate, the userns-hardening probe,
// the spawn (ONLY argv-named fds cross the exec boundary), the signal
// lifecycle (early_signal → forward → SIG_IGN during cleanup),
// exit-code propagation, and RmTreeWritable teardown. cmd/sbox is the
// CLI front end that drives it.
//
// The Spec is an ordered op list, not a bag of sections: bwrap applies
// argv order (a later bind shadows an earlier mount at or below its
// target). The provider preserves this order. The ops themselves are semantic
// (setenv / mount / tmpfs / dir / proc / dev / share-net / chdir), not
// bwrap flag spellings; any backend must be able to execute the same
// sequence.
//
// The fd invariant (runc CVE-2024-21626, "Leaky Vessels"): ONLY the fds
// the argv actually names may reach the sandbox. bwrap closes the fds
// attached to setup ops (--bind-fd, the seccomp fd), but an O_PATH fd
// attached to NOTHING — e.g. the pin of a REFUSED cwd — would survive
// into the payload, and /proc/self/fd/N/.. from inside walks the HOST
// mount tree. Launch.PassFDs is derived purely from the emitted argv
// and becomes cmd.ExtraFiles, so Go itself guarantees that nothing else
// crosses the exec boundary.
package sandbox

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"

	"sbox/internal/bindpolicy"
	"sbox/internal/cliutil"
)

// Caps is what the backend can do (bwrap_caps). Probed ONCE in main()
// and carried in the provider — never re-probed lazily mid-launch (a
// $PATH test shim must not be asked twice; mirrors opts._bwrap_caps).
// Capability probing, not version parsing: upstream version numbers are
// a poor guide (options have appeared in distro releases ahead of the
// upstream version that introduced them).
type Caps struct {
	BindFD        bool // fd-pinned mounts (--bind-fd / --ro-bind-fd)
	AddSeccompFD  bool // --add-seccomp-fd (current spelling)
	LegacySeccomp bool // --seccomp (bwrap >= 0.4.1, same wire format)
	DisableUserns bool // --disable-userns AND --assert-userns-disabled
}

// SeccompFlag is the option the filter is handed through, "" when this
// backend cannot install filters (seccomp then fails closed).
func (c Caps) SeccompFlag() string {
	switch {
	case c.AddSeccompFD:
		return "--add-seccomp-fd"
	case c.LegacySeccomp:
		return "--seccomp"
	}
	return ""
}

// Op is one ordered sandbox-setup step. See the package comment for why
// the order is load-bearing.
type Op interface{ isOp() }

// Setenv exports one environment variable into the sandbox
// (bwrap --setenv; the environment is cleared first).
type Setenv struct{ Name, Value string }

// Mount is one bind: Src host-side, Dst in-sandbox. RW is the FINAL
// mount mode — bind-policy persistence warnings key on THIS, not on the
// CLI flag that produced the mount. FD, when non-nil, is the pinned
// O_PATH fd from bindpolicy: the VALIDATED object is handed over as a
// fd — never re-resolved (bwrap >= 0.10 --bind-fd/--ro-bind-fd). Nil FD
// means path-based: the deliberately unracy system trees (/usr,
// /etc/ssl, ...), the 0700 $WORK dir and the runtime sockets, plus —
// when fd pinning is unavailable (old bwrap, loud note) — user sources
// another sandbox could race. Try is bwrap's -try spelling (a missing
// source is skipped instead of failing the launch); it never applies to
// fd mounts.
type Mount struct {
	Src string
	Dst string
	RW  bool
	Try bool
	FD  *os.File
}

// Tmpfs mounts a fresh tmpfs at Path with the given octal permissions.
type Tmpfs struct {
	Path  string
	Perms uint32
}

// Mkdir creates Path (with Perms) inside the sandbox before the payload
// runs (bwrap --dir; the dest path of a later bind must exist).
type Mkdir struct {
	Path  string
	Perms uint32
}

// ProcFS mounts a fresh procfs at Path (the sandbox's own /proc — the
// host's, with its /proc/<pid>/root and /proc/<pid>/fd magic links,
// must never be handed over).
type ProcFS struct{ Path string }

// DevFS mounts a fresh device tmpfs at Path.
type DevFS struct{ Path string }

// ShareNet keeps the HOST network namespace (only meaningful with an
// otherwise fully unshared sandbox). NOTE: sharing the netns also
// exposes host loopback services and abstract Unix sockets.
type ShareNet struct{}

// Chdir runs the payload with Dir as its working directory; backends
// apply it after all mounts, wherever it sits in their argv.
type Chdir struct{ Dir string }

func (Setenv) isOp()   {}
func (Mount) isOp()    {}
func (Tmpfs) isOp()    {}
func (Mkdir) isOp()    {}
func (ProcFS) isOp()   {}
func (DevFS) isOp()    {}
func (ShareNet) isOp() {}
func (Chdir) isOp()    {}

// Spec is everything the launcher decided, validated, in emission
// order. Bridge is the in-sandbox sh script (socat bridge + readiness
// loop + `exec "$@"` — backend-neutral text; the supervisor runs it as
// /bin/sh -c BRIDGE sbox-sh CMD...). Seccomp is the raw sock_filter
// bytes for the deny-list filter (a multiple of 8, no length prefix;
// nil ⇒ --no-seccomp, the explicit opt-out). DisableUserns asks for the
// kernel-level nested-userns kill (--disable-userns +
// --assert-userns-disabled); the launcher probes first — hosts where
// the combination cannot work at all keep working on the seccomp
// unshare/setns deny rules alone. (Stdio lands with the output filter:
// plain inherit vs pty slave + chosen stdin fd.)
type Spec struct {
	Ops           []Op
	Bridge        string
	Seccomp       []byte
	DisableUserns bool
}

// Launch is the provider's rendered spawn plan. Bin is the backend
// binary to exec (the provider knows how it was located: a $PATH name
// or an absolute path); Argv is its argv WITHOUT the binary name and
// WITHOUT the payload: the supervisor appends "--" plus
// PayloadArgv(bridge, command). PassFDs holds
// EXACTLY the fds the argv names (bind-fd numbers + the seccomp pipe
// read end) and becomes cmd.ExtraFiles — Go itself then guarantees the
// CVE-2024-21626 invariant (no stray O_PATH pin reaches the payload;
// child fd numbers are 3+len-before, which is why Build owns them).
// CloseAfterSpawn holds the os.Dup copies made for pins named twice in
// one argv (bwrap consumes setup-op fds itself, and whether a later
// --bind-fd N still resolves after an earlier op attached to N must not
// depend on the backend's close ordering); the supervisor closes them
// right after the spawn, together with the parent copies in PassFDs.
type Launch struct {
	Bin             string
	Argv            []string
	PassFDs         []*os.File
	CloseAfterSpawn []*os.File
}

// Provider is the one-backend interface: probe it once in main(), carry
// the caps, ask it to render the spawn plan. Everything else (bind
// policy, seccomp bytes, supervision) is backend-neutral.
type Provider interface {
	Name() string
	Probe() (Caps, error)
	// UsernsProbe runs a throwaway sandbox with the SAME ns/pid/session
	// flags as the real launch (the point is to catch flag INTERACTIONS
	// on some backend version — a probe that runs a different argv than
	// the launch would pass while the launch dies).
	UsernsProbe(shareNet bool) bool
	Build(spec *Spec) (*Launch, error)
}

// InnerProxy is the in-sandbox bridge for the default (proxied) mode:
// socat forwards the sandbox's 127.0.0.1:1080 to the host proxy through
// the ro-bound /run/proxy.sock, and the readiness loop waits for it
// (2.5 s) before exec'ing the payload.
const InnerProxy = `socat TCP-LISTEN:1080,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/run/proxy.sock &
i=0
until socat -u /dev/null TCP:127.0.0.1:1080 >/dev/null 2>&1; do
    i=$((i+1)); [ "$i" -ge 50 ] && { echo "sbox: warning: in-sandbox proxy bridge not ready after 2.5s" >&2; break; }
    sleep 0.05
done
`

// InnerDirect is the --share-net bridge: nothing to set up.
const InnerDirect = ""

// SSHClientConfig is installed read-only at /etc/ssh/ssh_config inside the
// sandbox (proxied mode only). socat is guaranteed to exist in there — the
// bridge itself runs on it. The proxy resolves and allowlist-checks %h
// host-side, exactly like the env-var path for curl etc. Note ssh reads
// ~/.ssh/config first and the first obtained value wins, so a user config
// (e.g. --home) overrides per-option.
const SSHClientConfig = `# Generated by sbox: ssh has no native proxy support, so every host is
# routed through the sandbox's HTTP-CONNECT proxy (destination allowlist is
# enforced host-side). Disable per-invocation with -o ProxyCommand=none.
Host *
	ProxyCommand socat - PROXY:127.0.0.1:%h:%p,proxyport=1080
`

// PayloadArgv is the in-sandbox argv that runs the bridge script and
// then the command (bwrap/the backend installs the seccomp filter, when
// enabled, as the very last step before exec'ing THIS shell, so the
// shell, the bridge AND the command inherit the filter from their first
// instruction; once sh execs the command, the command is the bridge's
// parent, and a Yama-scoped process may ptrace its own descendants — an
// unfiltered bridge would be a syscall-injection escape hatch).
func PayloadArgv(bridge string, command []string) []string {
	return append([]string{"/bin/sh", "-c", bridge, "sbox-sh"}, command...)
}

// AgentSocketPath resolves $SSH_AUTH_SOCK for --ssh-agent
// (agent_socket_path). Fails loudly: an explicit flag must never
// silently forward nothing (or bind a non-socket).
func AgentSocketPath() (string, error) {
	raw := strings.TrimSpace(os.Getenv("SSH_AUTH_SOCK"))
	if raw == "" {
		return "", fmt.Errorf("--ssh-agent: SSH_AUTH_SOCK is not set — no agent to forward")
	}
	path := bindpolicy.RealPath(raw) // agents are often reached via a symlink
	st, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("--ssh-agent: agent socket %q is not usable: %v", raw, err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return "", fmt.Errorf("--ssh-agent: SSH_AUTH_SOCK %q is not a Unix socket", raw)
	}
	return path, nil
}

// userName uses USER or the current uid's account name; lookup failures are fatal.
func userName(uid int) (string, error) {
	if u := os.Getenv("USER"); u != "" {
		return u, nil
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		return "", fmt.Errorf("cannot determine the user name for uid %d (set $USER): %v", uid, err)
	}
	return u.Username, nil
}

func envOr(name, def string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return def
}

// joinPath joins two path components:
// one separator, never two (a trailing separator on a is not doubled),
// an absolute b discards a, and ""+b is b.
func joinPath(a, b string) string {
	if a == "" || strings.HasPrefix(b, "/") {
		return b
	}
	if strings.HasSuffix(a, "/") {
		return a + b
	}
	return a + "/" + b
}

// BuildSpec constructs the ordered launch policy (rendered by the provider): opts is the parsed CLI; cwd the launcher's
// working directory; sand the 0700
// $WORK/tmp dir mounted as the sandbox's /tmp; sock the host-side proxy
// Unix socket path; home the $HOME the launcher resolved; userBinds the
// validated (flag, realpath, fd) triples from bindpolicy.CheckBindPaths;
// agent the resolved agent socket ("" when not forwarding); sshCfg the
// generated ssh_config path (proxied mode only, "" otherwise); pinner
// the bind-policy pin cache (nil ⇒ path-based mounts). warn receives
// advisory notes and warnings. Fatal errors (a
// refused --home pin, a raced cwd) come back as error — the launch
// dies; nothing here ever degrades silently.
func BuildSpec(opts *cliutil.Options, cwd, sand, sock, home string,
	userBinds []bindpolicy.Bind, agent, sshCfg string,
	pinner *bindpolicy.Pinner, warn func(string)) (*Spec, error) {

	if warn == nil {
		warn = func(string) {}
	}
	pin := func(path string) (*os.File, error) {
		if pinner == nil {
			return nil, nil
		}
		return pinner.Pin(path, false)
	}

	uid := os.Getuid()
	user, err := userName(uid)
	if err != nil {
		return nil, err
	}

	ops := []Op{
		Setenv{"HOME", home},
		Setenv{"USER", user},
		Setenv{"TERM", envOr("TERM", "xterm-256color")},
		Setenv{"PATH", envOr("PATH", "/usr/local/bin:/usr/bin:/bin")},
		Setenv{"LANG", envOr("LANG", "C.UTF-8")},
		ProcFS{"/proc"},
		DevFS{"/dev"},
		// /tmp is the 0700 $WORK dir — never the host's /tmp.
		Mount{Src: sand, Dst: "/tmp", RW: true},
		Mount{Src: "/usr", Dst: "/usr"},
		Mount{Src: "/lib", Dst: "/lib", Try: true},
		Mount{Src: "/lib64", Dst: "/lib64", Try: true},
		Mount{Src: "/bin", Dst: "/bin", Try: true},
		Mount{Src: "/sbin", Dst: "/sbin", Try: true},
		// CA stores: Debian/Ubuntu (/etc/ssl), Fedora/RHEL (/etc/pki,
		// where /etc/ssl/certs is often a dangling symlink without
		// this), misc.
		Mount{Src: "/etc/ssl", Dst: "/etc/ssl", Try: true},
		Mount{Src: "/etc/pki", Dst: "/etc/pki", Try: true},
		Mount{Src: "/etc/ca-certificates", Dst: "/etc/ca-certificates", Try: true},
		Mount{Src: "/etc/hosts", Dst: "/etc/hosts", Try: true},
		Mount{Src: "/etc/localtime", Dst: "/etc/localtime", Try: true},
		Mount{Src: "/etc/passwd", Dst: "/etc/passwd", Try: true},
		Mount{Src: "/etc/group", Dst: "/etc/group", Try: true},
		// Debian/Ubuntu: many /usr/bin entries (awk, editor, java, vi,
		// at times python3) are symlinks into /etc/alternatives, which
		// dangle without this; ld.so.cache matters if libs live outside
		// the default loader paths.
		Mount{Src: "/etc/alternatives", Dst: "/etc/alternatives", Try: true},
		Mount{Src: "/etc/ld.so.cache", Dst: "/etc/ld.so.cache", Try: true},
		Tmpfs{Path: "/run", Perms: 0o755},
	}

	var bridge string
	if !opts.Net {
		ops = append(ops,
			Setenv{"all_proxy", "socks5h://127.0.0.1:1080"},
			Setenv{"ALL_PROXY", "socks5h://127.0.0.1:1080"},
			Setenv{"http_proxy", "http://127.0.0.1:1080"},
			Setenv{"https_proxy", "http://127.0.0.1:1080"},
			Setenv{"HTTP_PROXY", "http://127.0.0.1:1080"},
			Setenv{"HTTPS_PROXY", "http://127.0.0.1:1080"},
			Setenv{"no_proxy", "localhost,127.0.0.1,::1"},
			Setenv{"NO_PROXY", "localhost,127.0.0.1,::1"},
			// The socket FILE is bound read-only; connect() works
			// through a ro-bind.
			Mount{Src: sock, Dst: "/run/proxy.sock"},
		)
		if sshCfg != "" {
			// Nothing else mounts /etc/ssh; bwrap creates the dest path.
			ops = append(ops, Mount{Src: sshCfg, Dst: "/etc/ssh/ssh_config"})
		}
		bridge = InnerProxy
	} else {
		// --share-net keeps the host network namespace; resolv.conf
		// makes DNS work, nsswitch.conf/services/protocols keep
		// glibc's resolver and getservbyname() faithful ("https" used
		// to fail to resolve to 443). See ShareNet for the exposure
		// note.
		ops = append(ops, ShareNet{},
			Mount{Src: "/etc/resolv.conf", Dst: "/etc/resolv.conf", Try: true},
			Mount{Src: "/etc/nsswitch.conf", Dst: "/etc/nsswitch.conf", Try: true},
			Mount{Src: "/etc/services", Dst: "/etc/services", Try: true},
			Mount{Src: "/etc/protocols", Dst: "/etc/protocols", Try: true},
		)
		bridge = InnerDirect
	}

	if opts.Home {
		// Pin the RESOLVED $HOME — realpath already removed any symlink
		// ($HOME is often one) and the pin walk refuses symlinks, so a
		// swap of the link's target between realpath and mount dies in
		// Pin instead of redirecting the bind.
		realHomeSrc := bindpolicy.RealPath(home)
		fd, err := pin(realHomeSrc)
		if err != nil {
			return nil, err
		}
		ops = append(ops, Mount{Src: realHomeSrc, Dst: home, RW: true, FD: fd})
	} else {
		ops = append(ops, Tmpfs{Path: home, Perms: 0o700})
	}

	if opts.Gui {
		// X11 allows any client to log keys, capture the screen AND
		// inject input (XTEST/SendEvent) — i.e. type into your
		// terminal: treat X11 passthrough as unsandboxed. Wayland is
		// the preferred path. Keep the sockets themselves read-only.
		xdg := envOr("XDG_RUNTIME_DIR", fmt.Sprintf("/run/user/%d", uid))
		ops = append(ops, Setenv{"XDG_RUNTIME_DIR", xdg}, Mkdir{Path: xdg, Perms: 0o700})
		if wl := os.Getenv("WAYLAND_DISPLAY"); wl != "" {
			path := wl
			if !strings.HasPrefix(wl, "/") {
				path = joinPath(xdg, wl)
			}
			ops = append(ops, Setenv{"WAYLAND_DISPLAY", wl}, Mount{Src: path, Dst: path, Try: true})
		}
		if d := os.Getenv("DISPLAY"); d != "" {
			ops = append(ops, Setenv{"DISPLAY", d},
				Mount{Src: "/tmp/.X11-unix", Dst: "/tmp/.X11-unix", Try: true})
			for _, xauth := range []string{os.Getenv("XAUTHORITY"), joinPath(home, ".Xauthority")} {
				if xauth != "" && pathExists(xauth) {
					ops = append(ops, Setenv{"XAUTHORITY", xauth}, Mount{Src: xauth, Dst: xauth, Try: true})
					break
				}
			}
		}
	}

	if agent != "" {
		// One socket file, read-only — connect() works through a
		// ro-bind (same trick as /run/proxy.sock). Fixed path inside,
		// because the host path is usually under /run/user/<uid>, which
		// stays hidden.
		ops = append(ops,
			Mount{Src: agent, Dst: "/run/ssh-agent.sock"},
			Setenv{"SSH_AUTH_SOCK", "/run/ssh-agent.sock"},
		)
	}

	// Current directory: bind it (rw unless --ro-cwd) through the SAME
	// fd-first validator as -b/-r (bindpolicy.ValidateBindSource):
	// protected paths, CONTROL_SOCKETS, the socket-shape rules and the
	// contains-socket scan all apply — `cd` alone must never hand over
	// runtime state (cd /tmp/.X11-unix, an LXD or tmux socket dir). A
	// refusal is a LOUD warning and the command keeps running with the
	// sandbox's /tmp as its cwd — silent continuation elsewhere is how
	// `make`/`npm install` "succeed" somewhere you did not intend
	// (--bind-socket "$PWD" opts a socket-bearing dir back in,
	// read-write). A cwd at or below an explicitly bound path still
	// exists inside the sandbox, so chdir works.
	realHome := bindpolicy.RealPath(home)
	project := bindpolicy.RealPath(cwd)
	userBound := map[string]bool{}
	for _, b := range userBinds {
		userBound[b.Path] = true
	}
	bind := true
	var cwdFD *os.File
	if project == realHome || strings.HasPrefix(project, realHome+"/") {
		if !opts.Home {
			warn("note: cwd is inside $HOME and $HOME is a tmpfs — using /tmp instead (--home to bind)")
			bind = false
		} else {
			// --home binds the whole tree anyway; its notes cover the
			// persistence and control-socket exposure (mirrors the
			// -b $HOME --home exemption in the bind policy). Still pin
			// the cwd itself so its mount is fd-based like the rest.
			if cwdFD, err = pin(project); err != nil {
				return nil, err
			}
		}
	} else {
		refusal, warning, _, fd, fatal := bindpolicy.ValidateBindSource(pinner, "cwd", project, opts, home, warn)
		if fatal != nil {
			return nil, fatal
		}
		cwdFD = fd
		if refusal != "" {
			// Never keep the pin of a REFUSED cwd: an O_PATH fd for
			// host ground reaching the payload is an escape (the runc
			// CVE-2024-21626 class — /proc/self/fd/N/.. walks the HOST
			// mount tree), so release it unless a user bind of the
			// same path still mounts it.
			if pinner != nil && !userBound[project] {
				pinner.Release(project)
			}
			cwdFD = nil
			if !anyCovers(userBinds, project) {
				warn(fmt.Sprintf("warning: %s — NOT mounting the cwd; the command runs "+
					"with the sandbox's /tmp as its working directory", refusal))
			}
			// else: an explicit user bind covers the cwd, --chdir lands
			// exactly where the user asked — the refusal only means the
			// AUTOMATIC mount is skipped, and a "runs with /tmp" note
			// would be wrong (the --chdir below keys on the same covers
			// test). Silent, like every other explicit bind.
			bind = false
		} else if warning != "" {
			warn(warning)
		}
	}

	// Emit the cwd bind BEFORE the user binds: a later bind shadows
	// earlier mounts at or below its target, so the automatic (rw by
	// default) cwd mount must come first for explicit -r/-b flags to
	// win — `-r "$PWD"` would otherwise silently end up read-write.
	if bind {
		ops = append(ops, Mount{Src: project, Dst: project, RW: !opts.RoCwd, FD: cwdFD})
	}
	for _, b := range userBinds {
		// mount exactly the validated (pinned) object — the fd the
		// bind policy checked, never a re-resolved path.
		ops = append(ops, Mount{Src: b.Path, Dst: b.Path, RW: b.Flag == "--bind", FD: b.FD})
	}

	// Backends apply the chdir after all mounts, wherever it sits in
	// their argv.
	if bind || anyCovers(userBinds, project) {
		ops = append(ops, Chdir{Dir: project})
	} else {
		ops = append(ops, Chdir{Dir: "/tmp"})
	}

	bridge += "exec \"$@\"\n"
	return &Spec{Ops: ops, Bridge: bridge}, nil
}

// anyCovers reports whether any bind's resolved path is equal to or an
// ancestor of p.
func anyCovers(binds []bindpolicy.Bind, p string) bool {
	for _, b := range binds {
		if bindpolicy.Covers(b.Path, p) {
			return true
		}
	}
	return false
}

func pathExists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
