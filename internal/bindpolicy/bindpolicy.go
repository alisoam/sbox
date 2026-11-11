// Package bindpolicy validates -b/-r/--bind-socket sources, --overlay
// sources and the automatic cwd mount, pins their descriptors, scans for
// sockets and warns when writable binds cover host persistence paths.
// Validation rules and mount modes are covered by native contract tests.
// Explicit single-launch overlays share the pinned source validation, but
// knowingly reopen paths at mount time; their validation fds stay host-side.
//
// Security model (fd-first, fail-closed):
//
//   - Whatever these paths really point at is handed to the sandbox. A
//     bind is refused when it COVERS a protected path (SYSTEM_DIRS, the
//     resolved $HOME, /run/user[/<uid>], the resolved $XDG_RUNTIME_DIR —
//     a writable system dir, or ground hiding /run/proxy.sock), lies
//     INSIDE /proc, /sys or /dev (NO_DESCEND_ROOTS: host pseudo-fs ground
//     — /proc/<pid>/root, /proc/<pid>/fd and /dev/pts resolve in the HOST
//     task's context even after a plain bind; no --bind-socket override),
//     overlaps a known host control socket (CONTROL_SOCKETS, matched
//     bidirectionally: is / covers / inside, against realpath'd sources,
//     with realpath'd copies of every entry so $HOME-through-a-symlink
//     spellings still match), or is socket-shaped by rule: any socket
//     file, anything under /run, /var/run or $XDG_RUNTIME_DIR, or a
//     directory containing a Unix socket (bounded scan) — control-socket
//     territory where a name list will always lag reality.
//   - --bind-socket PATH is the explicit per-path opt-in for the
//     socket-shaped rules ONLY, and never for a read-write mount of
//     connect-only ground: socket files and runtime-dir paths would let
//     the sandbox unlink-and-replace the socket and impersonate the host
//     service, so -b of them is refused with or without the opt-in.
//     Plain DIRECTORIES opt in READ-WRITE (socket-bearing project dirs:
//     puma.sock, .s.PGSQL.5432, .git/fsmonitor--daemon.ipc); a preceding
//     -r of the same path keeps them read-only (--bind-socket then acts
//     as the shape opt-in only).
//   - fd-first: every source is realpath()'d, then pinned with a
//     component-by-component openat(O_PATH|O_NOFOLLOW) walk that refuses
//     ANY symlink met after the realpath (a concurrent sandbox swapped a
//     component), and confirmed via /proc/self/fd — the fd you validated
//     IS the fd bwrap mounts (--bind-fd/--ro-bind-fd, bwrap >= 0.10).
//     With pinning unavailable (old bwrap) every check runs on the path
//     instead — the documented TOCTOU fallback. A missing -b/-r source
//     dies; --bind-socket of a not-yet-created runtime path keeps the
//     path form (bwrap's own not-found error preserved). --overlay
//     sources are ALWAYS pinned (nil pin = refusal): bwrap resolves
//     overlay lower paths by NAME, so the pinned object is what a
//     private staging namespace must re-mount for the swap protection to
//     survive (see internal/sandbox/bwrap). Explicit --overlay-mode single
//     keeps fd-first validation but accepts pathname reopening at mount time.
//   - Read-write -b binds covering $HOME persistence paths (shell rc and
//     session files, ~/.ssh/authorized_keys, systemd user units, XDG
//     autostart, environment.d, ~/.local/bin, ~/.cargo/bin, ~/go/bin,
//     .gitconfig, nvim config, ...) are WARNED about (naming the paths,
//     both directions), never refused: these binds are legitimate far
//     more often. Read-only binds are fine. --bind-socket directories
//     that mount read-write warn the same way.
//
// Not safe for concurrent use: the launcher validates binds
// single-threaded before the proxy goroutines exist.
package bindpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// SystemDirs are the paths a user bind (or the cwd bind) must never
// COVER: they would shadow the tmpfs /tmp (exposing the host's /tmp and
// $WORK), hide /run/proxy.sock, or hand the sandbox a writable system
// directory.
var SystemDirs = []string{
	"/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run",
	"/sbin", "/sys", "/tmp", "/usr", "/var",
}

// NoDescendRoots are the roots whose DESCENDANTS are never bindable, by
// any label and with no --bind-socket override. SystemDirs above only
// blocks ANCESTORS (-b /proc itself); the children went through:
// /proc/<pid>/root and /proc/<pid>/fd/* are magic links that resolve in
// the HOST task's context (the ptrace_may_access gate is a kuid
// comparison, so the same uid passes from inside a child user namespace),
// /dev/pts exposes every terminal's slave, /dev/shm is shared IPC ground.
// bwrap already provides a fresh, safe /proc and /dev.
var NoDescendRoots = []string{"/proc", "/sys", "/dev"}

// Covers reports whether a is equal to or an ancestor of b. Callers pass
// realpaths; b is compared verbatim and "/" covers every absolute path.
func Covers(a, b string) bool {
	a = strings.TrimRight(a, "/")
	return b == a || strings.HasPrefix(b, a+"/")
}

// RealPath returns an absolute path with symlinks resolved, including
// dangling links whose targets do not exist yet. Missing components stay
// in the result so runtime sockets can be created after validation. Resolve
// each component before processing "..": cleaning first would make
// "link/../file" refer to the link's parent instead of its target's parent.
// An unavailable cwd returns "", which cannot be pinned for a bind.
func RealPath(p string) string {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return ""
		}
		// Do not use Join or Abs here: both clean away symlink/.. pairs.
		p = wd + "/" + p
	}
	resolved := "/"
	pending := strings.Split(p, "/")
	links := 0
	for len(pending) > 0 {
		part := pending[0]
		pending = pending[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			resolved = filepath.Dir(resolved)
			continue
		}
		next := filepath.Join(resolved, part)
		st, err := os.Lstat(next)
		if err != nil || st.Mode()&os.ModeSymlink == 0 {
			resolved = next
			continue
		}
		target, err := os.Readlink(next)
		if err != nil {
			resolved = next
			continue
		}
		links++
		if links > 255 {
			// Keep the unresolved link in the result: pinning refuses it,
			// and path-based mounts fail on the loop instead of mounting a
			// lexically cleaned path that was never resolved.
			return next + "/" + strings.Join(pending, "/")
		}
		if filepath.IsAbs(target) {
			resolved = "/"
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return resolved
}

// homeDir is $HOME ("" when unset — entries that need it are dropped).
func homeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return h
}

// uid is the real uid for the /run/user/<uid> entries.
func uid() string { return strconv.Itoa(os.Getuid()) }

// ProtectedPaths are the paths a user-supplied bind (or the cwd bind)
// must never cover: the system dirs, the resolved $HOME, and the user
// runtime dir — as a ROOT: when $XDG_RUNTIME_DIR lives outside /run
// (some distros put it in $HOME or /tmp), an ANCESTOR bind of it is not
// caught by the runtime-root shape rule and would otherwise depend on
// the socket scan happening to find a socket in time.
func ProtectedPaths(home string) []string {
	set := map[string]bool{}
	for _, d := range SystemDirs {
		set[d] = true
	}
	set[RealPath(home)] = true
	set["/run/user"] = true
	set["/run/user/"+uid()] = true
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		set[RealPath(xdg)] = true
	}
	out := make([]string, 0, len(set))
	for p := range set {
		out = append(out, p)
	}
	sort.Strings(out)
	return out
}

// ControlSockets are the well-known host control sockets: binding any of
// these hands the sandbox full control of the host (docker/containerd/
// CRI-O/podman/incus/LXD = root via the container daemon; D-Bus/systemd
// = arbitrary privileged services; libvirt = VMs; gnome-keyring/
// gpg-agent/1Password = your identity and ssh keys; snapd/tailscaled =
// service control; X11 = input injection) — a trivial escape, so they
// are refused exactly like protected paths even though they are only
// CHILDREN of them. Matching uses the Covers() ancestor test
// (bidirectionally), so parent dirs (e.g. -b /run/docker, -b ~/.gnupg)
// are refused too, and daemon DIRECTORIES catch differently-named
// sockets (podman-run.sock, systemd/notify, ...) even via
// --bind-socket. This list will always lag reality — the shape rule
// (anything under /run, or any socket file) is what fail-closes it.
//
// RawSpellings expands $HOME-relative entries WITHOUT resolving symlinks
// (the $HOME itself may go through one); ControlSockets() additionally
// carries a realpath'd copy of every entry so refusal still matches when
// the resolved bind source is compared.
type ControlSocket struct{ Path string }

// controlSocketRaw is the raw table; $HOME-relative entries drop when
// $HOME is unset.
var controlSocketRaw = []string{
	"/run/docker.sock", "/var/run/docker.sock",
	"/run/podman/podman.sock", "/var/run/podman/podman.sock",
	"/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock",
	"/run/crio/crio.sock",
	"/run/dbus/system_bus_socket", "/var/run/dbus/system_bus_socket",
	"/run/systemd/private", "/run/systemd/journal/socket",
	"/run/libvirt/libvirt-sock", "/var/run/libvirt/libvirt-sock",
	"/run/libvirt/libvirt-sock-ro", "/var/run/libvirt/libvirt-sock-ro",
	"/run/snapd.socket", "/run/snapd-snap.socket",
	"/run/tailscale/tailscaled.sock",
	"/run/incus/unix.socket", "/var/snap/lxd/common/lxd/unix.socket",
	// Daemon directories as well (see the doc above).
	"/run/podman", "/run/systemd", "/run/containerd", "/run/crio",
	"/run/dbus", "/run/libvirt", "/run/incus",
	"/tmp/.X11-unix", "/tmp/.ICE-unix", "/tmp/tmux-" + uid(),
	"/run/user/" + uid() + "/bus",
	"/run/user/" + uid() + "/gnupg/S.gpg-agent",
	"/run/user/" + uid() + "/pipewire-0",
	"/run/user/" + uid() + "/docker.sock",
	"/run/user/" + uid() + "/podman/podman.sock",
	"/run/user/" + uid() + "/systemd/private",
	"/run/user/" + uid() + "/keyring", // gnome-keyring: secrets + ssh agent
	"~/.1password/agent.sock",
	// Root-equivalent VM/container daemons that live in $HOME (Docker
	// Desktop, colima; lima's sockets move around ~/.lima/*/sock — the
	// socket scan catches those when ~/.lima is bound).
	"~/.docker/desktop/docker.sock",
	"~/.docker/run/docker.sock",
	"~/.colima/default/docker.sock",
}

// ControlSockets returns the control-socket set: every raw spelling
// ($HOME expanded WITHOUT resolving symlinks) plus a realpath'd copy of
// each (refusal compares against realpath'd bind sources). Entries that
// cannot be expanded ($HOME unset) are dropped — they could never match
// a validated absolute path.
func ControlSockets() []ControlSocket {
	out := []ControlSocket{}
	seen := map[string]bool{}
	add := func(p string) {
		if p == "" || seen[p] {
			return
		}
		seen[p] = true
		out = append(out, ControlSocket{p})
	}
	for _, e := range controlSocketRaw {
		p, ok := expandUser(e)
		if !ok {
			continue
		}
		add(p)
		add(RealPath(p))
	}
	return out
}

// expandUser expands a leading "~/" against $HOME (no resolution).
func expandUser(p string) (string, bool) {
	if !strings.HasPrefix(p, "~/") {
		return p, true
	}
	h := homeDir()
	if h == "" {
		return "", false
	}
	return filepath.Join(h, p[2:]), true
}

// IsSocket follows symlinks: a link to a socket is a connectable name too.
func IsSocket(path string) bool {
	st, err := os.Stat(path)
	return err == nil && st.Mode()&os.ModeSocket != 0
}

// RuntimeRoots are the roots whose contents are control-socket ground:
// /run, /var/run and the RESOLVED $XDG_RUNTIME_DIR.
func RuntimeRoots() []string {
	roots := []string{"/run", "/var/run"}
	if xdg := os.Getenv("XDG_RUNTIME_DIR"); xdg != "" {
		roots = append(roots, RealPath(xdg))
	}
	return roots
}

// IsRuntimeGround reports whether path is or lies under a runtime root.
func IsRuntimeGround(path string) bool {
	for _, r := range RuntimeRoots() {
		if Covers(r, path) {
			return true
		}
	}
	return false
}

// InsideNoDescendRoot reports whether path lies inside /proc, /sys or
// /dev (or is one of them — Covers handles equality).
func InsideNoDescendRoot(path string) bool {
	for _, r := range NoDescendRoots {
		if Covers(r, path) {
			return true
		}
	}
	return false
}

// PersistencePaths are the well-known $HOME persistence paths: a
// read-write bind covering any of these is host code execution at the
// next login/session. XDG_CONFIG_HOME / XDG_DATA_HOME are honored
// (relative values resolve under $HOME per the XDG spec) and realpath'd
// with $HOME: they are compared against realpath'd bind sources, and the
// variables (like $HOME) may go through a symlink.
func PersistencePaths(home string) []string {
	h := RealPath(home)
	cfg := os.Getenv("XDG_CONFIG_HOME")
	if cfg == "" {
		cfg = filepath.Join(h, ".config")
	}
	data := os.Getenv("XDG_DATA_HOME")
	if data == "" {
		data = filepath.Join(h, ".local", "share")
	}
	if !filepath.IsAbs(cfg) {
		cfg = filepath.Join(h, cfg)
	}
	if !filepath.IsAbs(data) {
		data = filepath.Join(h, data)
	}
	cfg = RealPath(cfg)
	data = RealPath(data)

	paths := []string{
		filepath.Join(h, ".bashrc"), filepath.Join(h, ".bash_profile"),
		filepath.Join(h, ".bash_login"), filepath.Join(h, ".bash_logout"),
		filepath.Join(h, ".profile"), filepath.Join(h, ".xprofile"),
		filepath.Join(h, ".xsessionrc"), filepath.Join(h, ".pam_environment"),
		filepath.Join(h, ".zprofile"), filepath.Join(h, ".zshrc"),
		filepath.Join(h, ".zshenv"), filepath.Join(h, ".zlogin"),
		filepath.Join(h, ".kshrc"),
		filepath.Join(h, ".emacs"), filepath.Join(h, ".vimrc"),
		filepath.Join(h, ".gitconfig"), filepath.Join(cfg, "git", "config"),
		filepath.Join(h, ".ssh", "authorized_keys"),
		filepath.Join(h, ".local", "bin"),
		filepath.Join(h, ".cargo", "bin"),
		filepath.Join(h, "go", "bin"),
		filepath.Join(cfg, "fish", "config.fish"),
		filepath.Join(cfg, "nvim"),
		filepath.Join(cfg, "systemd", "user"),
		filepath.Join(cfg, "autostart"),
		filepath.Join(cfg, "environment.d"),
		filepath.Join(data, "systemd", "user"),
		filepath.Join(data, "applications"),
	}
	return paths
}

// PersistenceWarning is the rw-bind persistence note for (label, p,
// resolved rp): keyed on the final MOUNT MODE (read-write), never on the
// CLI label — a --bind-socket DIRECTORY mounts rw just like -b, so both
// must warn. Both directions: an ancestor (-b ~/.config) and a
// descendant (-b ~/.local/bin/mytool, a single systemd unit) are equally
// dangerous — the file on PATH / the unit becomes writable. Empty when
// nothing matches (or the bind is read-only — callers only ask for rw).
func PersistenceWarning(label, p, rp, home string) string {
	var hits []string
	for _, q := range PersistencePaths(home) {
		if Covers(rp, q) || Covers(q, rp) {
			hits = append(hits, q)
		}
	}
	if len(hits) == 0 {
		return ""
	}
	sort.Strings(hits)
	return fmt.Sprintf("note: %s %s covers host persistence path(s): %s — "+
		"sandboxed code can plant things there that run as you at next login/session; "+
		"prefer -r or a narrower bind", label, p, strings.Join(hits, ", "))
}
