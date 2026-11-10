// Package cliutil splits launcher options from the sandboxed command and
// parses the options without abbreviation. Clustered short flags are rejected;
// attached values such as -aexample.com remain supported. The hidden
// --_selfprobe flag dispatches the seccomp probe child and takes no value.
//
// OPTS_WITH_VALUE trap: every option that consumes a separate value token
// MUST appear in OptsWithValue below — SplitArgv finds the first
// positional (and therefore the "--" boundary) by counting tokens, so a
// value-taking flag missing from that list silently shifts the split and
// the value ends up inside the sandboxed command. When adding a flag,
// update OptsWithValue, the parser and the help text together (this is the
// single source of truth; ShortWithValue is derived from it).
package cliutil

import (
	"fmt"
	"strconv"
	"strings"
)

// Prog is the program name used in usage and error messages.
const Prog = "sbox"

// OptsWithValue is the OPTS_WITH_VALUE trap list: every option spelled with
// a value as a SEPARATE token. Attached-value spellings ("-b/path",
// "--allow=x") and boolean flags are not listed.
var OptsWithValue = []string{
	"-a", "--allow",
	"-A", "--allow-file",
	"-b", "--bind",
	"-r", "--ro-bind",
	"--bind-socket",
	"--overlay",
	"--overlay-size",
	"--upstream",
}

var optsWithValue = func() map[string]bool {
	m := make(map[string]bool, len(OptsWithValue))
	for _, o := range OptsWithValue {
		m[o] = true
	}
	return m
}()

// ShortWithValue is the set of one-letter value-taking options, derived
// from OptsWithValue.
var ShortWithValue = func() map[byte]bool {
	m := map[byte]bool{}
	for _, o := range OptsWithValue {
		if len(o) == 2 && o[0] == '-' && o[1] != '-' {
			m[o[1]] = true
		}
	}
	return m
}()

// SplitArgv splits argv at the first positional: everything after it
// belongs to the sandboxed command (so `sbox -- cmd -v` works), like the
// shell version. The first "--" is the explicit boundary and is dropped;
// a value token consumed by a value-taking option is NOT treated as a
// boundary (even if it is "--").
func SplitArgv(argv []string) (pre, command []string) {
	i := 0
	for i < len(argv) {
		tok := argv[i]
		switch {
		case tok == "--":
			return argv[:i], rest(argv[i+1:])
		case strings.HasPrefix(tok, "-") && tok != "-":
			// "--allow x" consumes two tokens; "--allow=x" (or any other
			// token — attached short values like -b/path included) one.
			if !strings.Contains(tok, "=") && optsWithValue[tok] {
				i += 2
			} else {
				i++
			}
		default:
			return argv[:i], rest(argv[i:])
		}
	}
	return rest(argv), nil
}

func rest(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// Options is the parsed sbox configuration. Slice fields
// collect repeated flags in order; Upstream distinguishes "not passed"
// (HasUpstream false, env fallback applies) from `--upstream ""` (force
// direct egress).
type Options struct {
	Allow            []string
	AllowFile        []string
	Bind             []string
	RoBind           []string
	BindSocket       []string
	Overlay          []string
	OverlaySize      int64 // parsed bytes; DefaultOverlaySize when unset
	RoCwd            bool
	Home             bool
	Gui              bool
	SSHAgent         bool
	FilterOutput     bool
	StrictCrlf       bool
	Upstream         string
	HasUpstream      bool
	UpstreamInsecure bool
	Net              bool
	NoSeccomp        bool
	Verbose          bool
	Shell            bool
	SelfProbe        bool // hidden: --_selfprobe seccomp probe child re-exec
	Help             bool
}

// display names for option error messages
var (
	longDisplay = map[string]string{
		"allow":        "-a/--allow",
		"allow-file":   "-A/--allow-file",
		"bind":         "-b/--bind",
		"ro-bind":      "-r/--ro-bind",
		"bind-socket":  "--bind-socket",
		"overlay":      "--overlay",
		"overlay-size": "--overlay-size",
		"upstream":     "--upstream",
	}
	shortDisplay = map[byte]string{
		'a': "-a/--allow",
		'A': "-A/--allow-file",
		'b': "-b/--bind",
		'r': "-r/--ro-bind",
	}
)

// ParseCLI splits argv and parses the sbox options in argv[:i]. It returns
// the options and the sandboxed command. Help is reported via
// Options.Help (the caller prints Usage and exits 0); anything else is an
// error message without the "sbox: error: " prefix.
func ParseCLI(argv []string) (*Options, []string, error) {
	pre, command := SplitArgv(argv)
	opts := &Options{}
	for i := 0; i < len(pre); i++ {
		tok := pre[i]
		if tok == "--" {
			// Not produced by SplitArgv (it stops at the first "--");
			// defensively treat any inner "--" as end-of-options.
			command = append(command, pre[i+1:]...)
			break
		}
		if strings.HasPrefix(tok, "--") {
			name := tok[2:]
			inline, hasInline := "", false
			if j := strings.IndexByte(name, '='); j >= 0 {
				inline, hasInline = name[j+1:], true
				name = name[:j]
			}
			switch name {
			case "allow", "allow-file", "bind", "ro-bind", "bind-socket", "overlay", "upstream":
				val, err := takeValue(pre, &i, hasInline, inline, longDisplay[name])
				if err != nil {
					return nil, nil, err
				}
				applyValue(opts, name, val)
			case "overlay-size":
				val, err := takeValue(pre, &i, hasInline, inline, longDisplay[name])
				if err != nil {
					return nil, nil, err
				}
				n, err := ParseSizeBytes(val)
				if err != nil {
					return nil, nil, fmt.Errorf("argument --overlay-size: %v", err)
				}
				opts.OverlaySize = n
			case "ro-cwd", "home", "gui", "ssh-agent", "upstream-insecure", "net", "no-seccomp",
				"filter-output", "strict-crlf", "verbose", "shell", "_selfprobe", "help":
				if hasInline {
					return nil, nil, fmt.Errorf("argument --%s: ignored explicit argument %q", name, inline)
				}
				applyBool(opts, name)
			default:
				return nil, nil, fmt.Errorf("unrecognized arguments: %s", tok)
			}
			continue
		}
		// short option (tok starts with "-", tok != "-" and not "--...")
		c := tok[1]
		if ShortWithValue[c] {
			// Split an attached value at the FIRST '=': "-a=x"
			// is value "x", "-a==x" is "=x", "-b=" is "" — and "-b/path"
			// is "/path" (no '=' involved). TrimPrefix removes exactly one.
			inline := strings.TrimPrefix(tok[2:], "=")
			val, err := takeValue(pre, &i, len(tok) > 2, inline, shortDisplay[c])
			if err != nil {
				return nil, nil, err
			}
			applyValue(opts, valueNameForShort(c), val)
			continue
		}
		if len(tok) > 2 {
			return nil, nil, fmt.Errorf(
				"clustered short flags are not supported: %s (pass each flag as its own argument)", tok)
		}
		switch c {
		case 'v':
			opts.Verbose = true
		case 'h':
			opts.Help = true
		default:
			return nil, nil, fmt.Errorf("unrecognized arguments: %s", tok)
		}
	}
	// --strict-crlf always enables output filtering.
	if opts.StrictCrlf {
		opts.FilterOutput = true
	}
	return opts, command, nil
}

// DefaultOverlaySize is the shared storage budget for --overlay writable
// layers when --overlay-size is not given: 1 GiB, covering all overlays
// combined.
const DefaultOverlaySize = 1 << 30

// Overlay size bounds: smaller than 1 MiB cannot even hold a workdir in
// practice, larger than 16 TiB is meaningless for a tmpfs (bwrap itself
// caps tmpfs sizes at SIZE_MAX>>1; this stays well under).
const (
	minOverlaySize = 1 << 20
	maxOverlaySize = 1 << 44
)

// sizeUnits maps a size suffix to its multiplier. Both spellings ("MB",
// "MiB") are accepted case-insensitively; decimal units are powers of 1000
// and IEC units powers of 1024, matching tools like systemd and GNU.
var sizeUnits = map[string]int64{
	"B":  1,
	"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12, "PB": 1e15,
	"KIB": 1 << 10, "MIB": 1 << 20, "GIB": 1 << 30, "TIB": 1 << 40, "PIB": 1 << 50,
}

// ParseSizeBytes parses a --overlay-size value: an unsigned decimal byte
// count with an optional unit suffix ("1073741824", "1GiB", "500MB",
// "16TiB"). No signs, no fractions (write 1536MiB instead of 1.5GiB). The
// result is clamped to the documented bounds by the caller-facing error.
func ParseSizeBytes(s string) (int64, error) {
	fail := func(why string) (int64, error) {
		return 0, fmt.Errorf("invalid size %q (%s) — expected bytes with an optional unit, "+
			"e.g. 1GiB, 500MB, 1073741824; bounds %d..%d", s, why, minOverlaySize, maxOverlaySize)
	}
	if s == "" {
		return fail("empty")
	}
	digits := 0
	for digits < len(s) && s[digits] >= '0' && s[digits] <= '9' {
		digits++
	}
	if digits == 0 {
		return fail("no leading digits")
	}
	n, err := strconv.ParseInt(s[:digits], 10, 64)
	if err != nil {
		return fail("out of range")
	}
	unit := strings.ToUpper(s[digits:])
	if unit == "" {
		unit = "B"
	}
	mult, ok := sizeUnits[unit]
	if !ok {
		return fail("unknown unit " + strconv.Quote(s[digits:]))
	}
	if n > maxOverlaySize/mult {
		return fail("out of range")
	}
	n *= mult
	if n < minOverlaySize || n > maxOverlaySize {
		return fail("out of range")
	}
	return n, nil
}

// takeValue resolves a value-taking option's value: an attached remainder
// ("-b/path", "--allow=x") or the next token.
func takeValue(pre []string, i *int, attached bool, inline string, display string) (string, error) {
	if attached {
		return inline, nil
	}
	if *i+1 >= len(pre) {
		return "", fmt.Errorf("argument %s: expected one argument", display)
	}
	// Option-like tokens cannot be values. A bare "-" (stdin) and negative
	// numbers are exceptions because this parser has no numeric option names.
	if !valueTokenOK(pre[*i+1]) {
		return "", fmt.Errorf("argument %s: expected one argument", display)
	}
	*i++
	return pre[*i], nil
}

// valueTokenOK accepts: any token not starting with "-",
// a bare "-", or a negative number may serve as a value.
func valueTokenOK(tok string) bool {
	if !strings.HasPrefix(tok, "-") || tok == "-" {
		return true
	}
	return negativeNumber(tok)
}

// negativeNumber accepts signed integer and decimal value tokens
// (^-\d+$|^-\d*\.\d+$).
func negativeNumber(tok string) bool {
	s := tok[1:]
	if digitsOnly(s) {
		return true
	}
	intPart, fracPart, hasFrac := strings.Cut(s, ".")
	if !hasFrac || fracPart == "" || !digitsOnly(fracPart) {
		return false
	}
	if intPart != "" && !digitsOnly(intPart) {
		return false
	}
	return true
}

// digitsOnly reports whether s is one or more ASCII digits.
func digitsOnly(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func valueNameForShort(c byte) string {
	switch c {
	case 'a':
		return "allow"
	case 'A':
		return "allow-file"
	case 'b':
		return "bind"
	case 'r':
		return "ro-bind"
	}
	return ""
}

func applyValue(o *Options, name, val string) {
	switch name {
	case "allow":
		o.Allow = append(o.Allow, val)
	case "allow-file":
		o.AllowFile = append(o.AllowFile, val)
	case "bind":
		o.Bind = append(o.Bind, val)
	case "ro-bind":
		o.RoBind = append(o.RoBind, val)
	case "bind-socket":
		o.BindSocket = append(o.BindSocket, val)
	case "overlay":
		o.Overlay = append(o.Overlay, val)
	case "upstream":
		o.Upstream = val
		o.HasUpstream = true
	}
}

func applyBool(o *Options, name string) {
	switch name {
	case "ro-cwd":
		o.RoCwd = true
	case "home":
		o.Home = true
	case "gui":
		o.Gui = true
	case "ssh-agent":
		o.SSHAgent = true
	case "upstream-insecure":
		o.UpstreamInsecure = true
	case "net":
		o.Net = true
	case "no-seccomp":
		o.NoSeccomp = true
	case "filter-output":
		o.FilterOutput = true
	case "strict-crlf":
		o.StrictCrlf = true
	case "verbose":
		o.Verbose = true
	case "shell":
		o.Shell = true
	case "_selfprobe":
		o.SelfProbe = true
	case "help":
		o.Help = true
	}
}

// Description is the one-line help description.
const Description = "Run COMMAND in a bubblewrap sandbox with an allowlisted network."

// Epilog documents the security model and known limits. Keep it aligned with
// README.md and the package contracts when behavior changes.
const Epilog = `By default the sandbox has no network except a SOCKS5 *and* HTTP-CONNECT
proxy (auto-detected) at 127.0.0.1:1080 — http_proxy/https_proxy/all_proxy
are pre-set. https:// always goes through CONNECT; plain http:// URLs are
forwarded (absolute-form) as exactly ONE request: Host is rewritten from
the checked URL, header names must be valid tokens (no obs-fold),
Transfer-Encoding is refused and only an unambiguous Content-Length body
is forwarded. The origin is half-closed when the transport supports it
(TLS upstreams do not). A pipelined second request cannot smuggle its own
Host upstream. Responses stream concurrently
with uploads, including 100 Continue and early rejections. Tunnel bytes
buffered during upstream handshakes are preserved. The proxy runs in the
launcher; upstream credentials stay in memory. Destinations are denied
BEFORE any DNS lookup happens. Hostnames are resolved host-side; answers in
private, loopback, link-local or CGNAT ranges (including IPv4-mapped IPv6)
are rejected, so allowed names cannot reach host/LAN services
(explicit -a IP/CIDR entries bypass that
guard, as does -a NAME!private for that one name — for internal mirrors;
effectively catch-all networks such as 0.0.0.0/1 are refused).
$NO_PROXY/$no_proxy (lowercase winning, curl semantics) only picks the
route when chaining; entries are host suffixes, IP literals/CIDRs (literal
destinations only) or '*'.
--net drops the proxy and shares the host network namespace instead.

Notes:
  - --net also exposes host loopback services and abstract Unix sockets
    (D-Bus, X11, ...) to the sandbox; only use it for trusted work.
  - --gui passes through Wayland (preferred) and X11. X11 is effectively an
    escape: any client can log keystrokes, capture the screen and inject
    input (XTEST/SendEvent — e.g. type into your terminal = host command
    execution). Treat X11 passthrough as unsandboxed.
  - -b/-r of host control sockets (docker.sock, containerd, D-Bus, systemd,
    libvirt, X11, keyring, gpg-agent, ...) is refused, and so is anything
    socket-shaped by rule: any socket file, and anything under /run,
    /var/run or $XDG_RUNTIME_DIR — each is a trivial full escape. Paths
    inside /proc, /sys and /dev are refused too (host pseudo-fs ground:
    /proc/<pid>/root, /proc/<pid>/fd, /dev/pts, ... are host escapes; the
    sandbox gets a fresh, safe /proc and /dev anyway).
    --bind-socket PATH is the explicit opt-in when you really mean it:
    read-only for socket files and runtime-dir paths (connect-only — NEVER
    read-write, -b PATH --bind-socket PATH is refused like plain -b), and
    READ-WRITE for a plain directory (socket-bearing project dirs —
    puma.sock, .s.PGSQL.5432, .git/fsmonitor--daemon.ipc; combine with
    -r PATH for read-only; rw does let the sandbox replace the sockets
    inside it — the intended trade-off, since such dirs need writes).
  - Overlays (--overlay PATH): the command sees a writable, disposable view
    of PATH — writes land in a bounded private store (1 GiB by default,
    shared by all overlays, --overlay-size) that disappears when the sandbox
    exits; the source tree is never modified. An overlay covering the cwd
    replaces the automatic cwd mount with its merged view; a cwd outside
    every overlay is auto-mounted READ-ONLY while overlays are in use (a
    writable cwd bind would silently persist exactly what --overlay asks to
    avoid — pass an explicit -b "$PWD" to opt back in). Overlays reuse the
    bind validation (protected paths, control sockets, socket-bearing trees,
    runtime dirs: refused, with NO --bind-socket-style opt-in) and are
    rejected when they overlap --home, each other (duplicate or nested), or
    any -b/-r/--bind-socket mount. bwrap resolves overlay sources by PATH,
    so sbox stages them fd-first: a private, unprivileged staging sandbox
    mounts every source at an independent path on a private staging tmpfs.
    Validated sources come from PINNED descriptors; overlay lowers are
    read-only, and ordinary binds keep their requested modes. A separate
    size-bounded tmpfs holds all upper/work directories. Host-side path
    swaps cannot redirect these staged mounts. The launch probe uses the
    same system runtime mounts, network mode, namespace flags and filter. Staging is invisible to the payload: the sandbox gets a
    fresh root, and only the fds the argv names cross any exec boundary.
    Limits: an overlay is NOT a snapshot — host edits inside the source
    tree during the run are visible and behavior for them is undefined, so
    keep the underlying tree stable while the sandbox runs (a renamed or
    deleted source keeps working through its pinned descriptor); readable
    data is still exposed (overlays protect integrity, not
    confidentiality); the storage cap does not limit total process memory,
    CPU or PIDs.
  - With --as-pid-1 your command IS pid 1 of the sandbox: long-lived
    commands that spawn and abandon children will see zombies (nothing
    reaps orphans), and signals sent to pid 1 from inside (kill -TERM 1)
    are ignored unless handled — pid-namespace init semantics. External
    teardown is unaffected.
  - --ssh-agent forwards $SSH_AUTH_SOCK to /run/ssh-agent.sock (read-only,
    $SSH_AUTH_SOCK preset). Combined with the injected ssh config, ssh can
    then authenticate with your keys through the allowlisted proxy. Note
    the read-only bind limits the socket file, not the agent protocol:
    sandboxed code can also remove identities from or lock the shared
    agent (ssh-add -D/-x). Prefer a dedicated agent (ssh-add -c for
    confirmation, -h for destination constraints) for untrusted work.
  - Proxied mode installs /etc/ssh/ssh_config with a ProxyCommand (socat
    HTTP-CONNECT through 127.0.0.1:1080): ssh/scp/sftp/git-over-ssh ride the
    allowlist without extra flags. ~/.ssh/config is read first and wins
    per-option; ssh -o ProxyCommand=none opts out (and usually fails,
    fail-closed). --net installs nothing (direct egress, no allowlist).
    No known_hosts is injected: host-key verification fails closed (tmpfs
    home, no TTY) — pass -r ~/.ssh/known_hosts or pin hosts yourself.
  - The cwd is mounted read-write when it is a normal directory: sandboxed
    code can plant .git/hooks, Makefiles, .envrc or package.json scripts
    that execute on the HOST later — that is the default persistence
    trade-off. --ro-cwd mounts it read-only (combine with -b for a
    build-output dir); -r "$PWD" does the same ad hoc. EXCEPTIONS: a cwd
    inside $HOME is NOT mounted at all unless --home is given (the sandbox
    $HOME is a tmpfs — sbox falls back to /tmp with a note; use --home or
    an explicit -b "$PWD"/-r "$PWD" to have it), and cwds are never
    auto-mounted when they cover protected paths (/etc, /usr, /run, ...),
    lie inside /proc, /sys or /dev, or hit the same control-socket rules
    as -b (cd /tmp/.X11-unix, an LXD
    or tmux socket dir, or a directory containing a Unix socket): a
    WARNING fires and the command runs with the sandbox's /tmp as its
    working directory — not silently somewhere you did not intend.
    --bind-socket "$PWD" opts a socket-bearing cwd back in READ-WRITE
    when it is a plain directory (connect-only ground opts back in
    read-only; -r "$PWD" --bind-socket "$PWD" forces read-only).
  - Explicit -b/-r binds overlay the automatic cwd mount when they cover
    it: -r "$PWD" from inside the directory gives a read-only cwd, and
    likewise -b over --ro-cwd gives read-write (the explicit flag wins).
    Read-write binds covering $HOME persistence paths (shell rc/session
    files, ~/.ssh/authorized_keys, systemd user units, XDG autostart,
    environment.d, ~/.local/bin, ~/.cargo/bin, ~/go/bin, ...) are warned
    about — in BOTH directions, so -b ~/.local/bin/mytool warns just like
    -b ~/.local/bin: each means host code execution at the next
    login/session (a --bind-socket directory that mounts read-write warns
    the same way). Validated bind sources are handed to bwrap
    (>= 0.10) as pinned fds — validation pins first and checks the pinned
    object (relative paths are resolved to absolute paths), so a concurrent sandbox cannot swap a path component between
    check and mount; only the fds the argv names reach the sandbox, and
    a missing -b/-r source is a hard error (no path-form fallback).
  - The sandbox runs in a new session (TIOCSTI protection): Ctrl-C reaches
    sbox, which then tears the whole sandbox down — a hard kill: bwrap
    does not relay signals, so the command itself never sees a catchable
    SIGINT (graceful shutdown inside the sandbox is not supported).
  - Seccomp deny-list: io_uring_*, bpf, perf_event_open, userfaultfd,
    keyring, namespace (unshare/setns/clone3/clone-with-CLONE_NEWUSER),
    admin (mount/pivot_root/chroot/kexec/module loading/open_by_handle_at/
    name_to_handle_at/quotactl/syslog and the new mount API fsopen/fsmount/
    fspick/move_mount/...), process-inspection/injection (ptrace,
    process_vm_readv/writev, kcmp, pidfd_getfd, vmsplice) and personality
    CHANGES (the harmless 0xffffffff persona-query call stays allowed;
    setarch -R et al. still need --no-seccomp), fanotify_init and
    ioctl(TIOCSTI/TIOCLINUX) are refused inside the sandbox; socket() is
    limited to AF_UNIX/AF_INET/AF_INET6/AF_NETLINK (AF_VSOCK bypasses
    netns isolation in VM guests on older kernels) — ENOSYS where runtimes
    have fallbacks, EPERM otherwise; foreign-ABI binaries (e.g. 32-bit
    compat, x32) are killed. Every launch self-probes the compiled filter
    host-side first (installed in a probe child; the unshare(),
    ioctl(TIOCSTI), socket(AF_VSOCK), personality(0) and ptrace calls
    must all come back denied while the personality(0xffffffff) query
    stays allowed — the syscall numbers are verified on
    THIS machine; the probe samples six entries, the full table is
    pinned by the test suite — run it after editing the tables).
    bwrap itself installs the filter right before
    exec'ing the payload (no helper needed inside the sandbox), so
    everything inside is covered from the first process (the socat bridge
    included; the payload runs as pid 1, so no unfiltered bwrap reaper
    init remains). bwrap >= 0.8 additionally gets --disable-userns:
    nested user namespaces die at the kernel level, not just by syscall
    number (probed once per launch with the same namespace/pid flags as
    the real argv; hosts where that combination cannot run — e.g. setuid
    bwrap without unprivileged user namespaces — keep working on the
    deny rules alone, with a note shown at most once a day). FAILS CLOSED:
    without seccomp support (bwrap < 0.4.1) or on an
    unsupported architecture the launcher refuses to run — --no-seccomp is
    the explicit opt-out (needed for perf, io_uring runtimes, unshare-
    based builders, keyring-using kerberos, debuggers (gdb/strace), setarch
    or nested containers).
  - --filter-output sanitizes terminal output host-side: the sandbox
    runs on a pty slave (the host terminal fd never enters the sandbox)
    and everything it prints passes an allowlist — text, \n/\r/\t and
    safe SGR colors pass; OSC strings (clipboard writes, titles,
    hyperlinks), DCS/APC/PM/SOS, non-SGR CSI (cursor moves, screen
    clears, device queries), 2-byte ESC sequences, other C0/C1 controls
    and bidi/zero-width/blank-rendering/variation-selector characters are
    dropped. WITHOUT it, raw sandbox
    bytes reach your terminal unchanged — use it for untrusted work. The
    host tty goes raw (stdin and SIGWINCH forwarded, termios restored on
    exit); NON-tty stdin (a pipe, file, /dev/null) is inherited by the
    sandbox directly, so binary data and long lines round-trip byte-exact
    (tar c . | sbox --filter-output -- tar x). A stdin that IS a
    terminal but raw mode failed for is refused outright — the host tty
    fd is never handed to the sandbox unfiltered. Note the pty merges
    stdout and stderr, so host redirection cannot separate payload stderr;
    redirection inside the sandbox still works.
    ONLCR translates \n to \r\n (also in redirected output). Closed output
    pipes do not terminate the launcher; it continues supervising and restoring
    the terminal during cleanup.
    --strict-crlf (implies --filter-output) additionally drops \r
    not followed by \n: a bare \r lets payload output visually overwrite
    the current line after you read it (progress bars break). Known
    limits: Ctrl-C reaches the sandbox as a byte — a command that never
    reads stdin cannot be interrupted from the keyboard (kill sbox
    from another shell); hidden text is not prevented beyond SGR 8
    conceal (matching fg/bg colors hide text just as well).

Examples:
  sbox -a pypi.org -a files.pythonhosted.org -- pip install requests
  sbox -a github.com -- git clone https://github.com/torvalds/linux
  sbox -a example.com -v -- curl -sI https://example.com
  sbox -a example.com --filter-output -- curl -s https://example.com
  sbox --ssh-agent -a github.com -- git clone git@github.com:me/repo.git
  sbox --overlay "$PWD" --overlay-size 1GiB -- make
`

// Usage is the complete fixed-width help text.
const Usage = `usage: sbox [-h] [-a HOST] [-A FILE] [-b PATH] [-r PATH] [--bind-socket PATH]
            [--overlay PATH] [--overlay-size SIZE] [--ro-cwd] [--home] [--gui]
            [--ssh-agent] [--filter-output] [--strict-crlf] [--upstream URL]
            [--upstream-insecure] [--net] [--no-seccomp] [-v] [--shell]

` + Description + `

options:
  -h, --help            show this help message and exit
  -a, --allow HOST      Allow HOST or any subdomain (suffix match on a dot
                        boundary); IP/CIDR entries match literal IP
                        destinations; optional :port. A trailing !private
                        (mirror.corp!private) lets that one NAME resolve into
                        private ranges (internal mirrors; IP/CIDR entries
                        bypass the guard anyway). Repeatable.
  -A, --allow-file FILE
                        File with allow entries (one per line, '#' comments).
                        Repeatable.
  -b, --bind PATH       Bind PATH read-write at the same location. Repeatable.
  -r, --ro-bind PATH    Bind PATH read-only at the same location. Repeatable.
  --bind-socket PATH    Bind PATH even though it is a socket or lives under
                        /run, /var/run or $XDG_RUNTIME_DIR (refused by
                        default: control sockets there are full host escapes).
                        Read-only for socket files and runtime-dir paths
                        (connect-only ground — never read-write, so -b PATH
                        --bind-socket PATH is refused too); a plain DIRECTORY
                        opts in READ-WRITE — for socket-bearing project dirs
                        (puma.sock, .s.PGSQL.5432, .git/fsmonitor--daemon.ipc)
                        whose cwd the scan refuses; combine with -r PATH for
                        read-only. Known control sockets, protected paths and
                        anything inside /proc, /sys or /dev are still refused.
                        Repeatable.
  --overlay PATH        Mount PATH (an existing directory) at its own
                        resolved path as a DISPOSABLE WRITABLE overlay: reads
                        see the real tree, writes (creates, edits, deletes,
                        renames, chmods, symlinks, hard links) land in a
                        private bounded store that vanishes when the sandbox
                        exits — the source tree itself is never written.
                        Repeatable; all overlays share one --overlay-size
                        budget. Sources are validated like binds (protected
                        paths, control sockets, socket-bearing trees and
                        runtime dirs are refused — no opt-in) and may not
                        overlap --home or any -b/-r/--bind-socket mount. An
                        overlay covering the cwd replaces the automatic cwd
                        mount; a cwd outside every overlay mounts READ-ONLY
                        while overlays are in use. Needs bwrap >= 0.11 with
                        fd binds and a kernel supporting unprivileged
                        overlayfs (>= 5.11); the full arrangement is probed
                        before launch and refused when it cannot run.
  --overlay-size SIZE   Combined storage cap for every overlay writable layer:
                        1GiB (the default), 500MB, 1073741824 ... Bounds
                        1MiB..16TiB. Hitting the cap fails writes (ENOSPC)
                        inside the sandbox — they never fall back to the host
                        tree. The cap bounds the overlay store only, not
                        total process memory, CPU or PIDs.
  --ro-cwd              Mount the current directory read-only (default: rw).
  --home                Bind the real $HOME (default: private tmpfs home).
  --gui                 Pass through Wayland/X11 sockets. X11 is effectively
                        an escape: clients can log keys, capture the screen
                        and inject input (XTEST) — treat it as unsandboxed.
  --ssh-agent           Forward the host SSH agent socket ($SSH_AUTH_SOCK)
                        into the sandbox, read-only, at /run/ssh-agent.sock.
                        Anything in the sandbox can then sign with every key
                        loaded in the agent, and the agent protocol also lets
                        it remove identities or lock the agent (ssh-add -D/-x)
                        — prefer a dedicated agent (ssh-add -c/-h) for
                        untrusted code.
  --filter-output       Sanitize stdout/stderr on the host via a host-side PTY
                        filter. Strips dangerous ANSI escape sequences (OSC 52
                        clipboard writes, terminal queries, invisible text,
                        cursor manipulations) while preserving standard text
                        and safe SGR colors. Recommended for untrusted work;
                        without it raw sandbox bytes reach your terminal
                        unchanged.
  --strict-crlf         With --filter-output (implied): additionally drop \r
                        not immediately followed by \n — a bare \r lets
                        sandbox output visually overwrite the current line
                        after you read it. Breaks progress bars and \r-based
                        redraw.
  --upstream URL        Egress through an upstream proxy: http://, https://,
                        socks5://, socks5h:// (userinfo supported). Default:
                        $SBOX_UPSTREAM, else $https_proxy/$HTTPS_PROXY. Pass
                        an empty string to force direct egress.
                        $NO_PROXY/$no_proxy is honored when chaining — also
                        with an explicit --upstream; lowercase $no_proxy wins;
                        matching hosts egress direct and the allowlist still
                        applies.
  --upstream-insecure   Do not verify the upstream's TLS certificate (https://
                        upstreams). Env: $SBOX_UPSTREAM_INSECURE=1 (only
                        1/true/yes/on count — a bare '0' does NOT disable
                        verification).
  --net                 Share the host network namespace: direct egress, DNS
                        via the host resolver, no proxy/allowlist
                        (-a/-A/--upstream are ignored).
  --no-seccomp          Do not install the seccomp deny-list (otherwise
                        io_uring_*, bpf, perf_event_open, userfaultfd,
                        keyring, unshare/setns/clone3/CLONE_NEWUSER,
                        mount/kexec/module-loading, ptrace/process_vm_* and
                        friends are blocked with ENOSYS/EPERM inside the
                        sandbox). Note the launcher FAILS CLOSED without it:
                        when the filter cannot be installed (bwrap < 0.4.1,
                        unsupported architecture) or fails its startup self-
                        probe (six sampled calls — unshare(0), ioctl(TIOCSTI),
                        socket(AF_VSOCK), personality(0), ptrace must come
                        back denied, and the personality(0xffffffff) query
                        must stay allowed) it refuses to run instead of
                        running unfiltered.
  -v, --verbose         Log allow/deny decisions to stderr.
  --shell               Run an interactive shell ($SHELL if available).

` + Epilog
