#!/usr/bin/env python3
"""sbox.py — run a command in a bubblewrap sandbox with an allowlisted network.

Design:
  - bwrap --unshare-all: the sandbox has NO network stack (no direct TCP/UDP,
    no DNS). The only egress is a Unix socket passed into /run/proxy.sock.
  - The proxy runs on the HOST: this same file re-executes itself as a small
    asyncio SOCKS5 + HTTP-CONNECT server listening on that Unix socket. There
    is no third-party proxy dependency (replaces 3proxy and its AF_UNIX
    sendto()/EISCONN bug, patched builds and the relay self-test workaround).
  - Inside the sandbox a loopback bridge (socat) makes the proxy available at
    127.0.0.1:1080; the listener auto-detects SOCKS5 (first byte 0x05) vs HTTP
    proxy traffic, so http_proxy=http://127.0.0.1:1080 works for tools that
    do not understand socks5h:// (npm, apt, ...).
    all_proxy=socks5h://127.0.0.1:1080 is set as well; http(s)_proxy too.
  - ssh ignores proxy env vars, so proxied mode additionally injects a
    generated /etc/ssh/ssh_config (read-only bind) whose ProxyCommand runs
    socat's HTTP-CONNECT client through the bridge: ssh/scp/sftp and
    git-over-ssh ride the same allowlist-checked proxy. ~/.ssh/config still
    wins per-option (ssh reads the user config first). No known_hosts is
    provided: with a tmpfs home and no TTY (--new-session) host-key
    prompting fails closed, so pass -r ~/.ssh/known_hosts (or pin hosts in
    your own ssh_config) for ssh destinations.
  - Fail-closed: apps that ignore the proxy vars simply get no network.

Security model of the proxy (default-deny):
  - A destination is checked against the allowlist BEFORE anything else; in
    particular hostnames of DENIED destinations are never resolved — there is
    no DNS side channel (no <data>.evil.com exfiltration through lookups).
  - Allowed hostnames are resolved on the host; answers in private, loopback,
    link-local, CGNAT, multicast or reserved ranges are rejected, so an
    allowed name cannot be used to reach host/LAN services (SSRF guard,
    incl. 169.254.169.254). Explicit -a IP/CIDR entries deliberately bypass
    that guard (explicit intent) — use them with care.
  - Suffix match is on dot boundaries: -a example.com allows example.com and
    sub.example.com, but not notexample.com. Entries may carry a port
    (example.com:443); IPs and CIDRs are also accepted. Catch-all entries
    (bare '*', 0.0.0.0/0, ::/0) and CIDRs with host bits set (203.0.113.7/24)
    are rejected loudly instead of being widened or allowed silently.
  - Optional upstream chaining (--upstream, or $SBOX_UPSTREAM / $https_proxy):
    schemes http, https (TLS to the proxy), socks5 and socks5h; userinfo in
    the URL is passed on (Basic auth / RFC 1929). Destinations are still
    resolved and checked host-side before anything is sent upstream. Set
    $SBOX_UPSTREAM_INSECURE (or --upstream-insecure) to skip TLS verification
    of an https:// upstream (e.g. corporate MITM CA).
  - A startup self-test talks to the real socket and verifies that a
    non-allowed destination is refused on both protocols before the sandbox
    starts, so the fail-closed guarantee is checked, not assumed.

  - Seccomp hardening on top of the namespaces: a deny-list cBPF filter is
    installed by bwrap itself, as the very last step before exec'ing the
    payload (--add-seccomp-fd; --seccomp on older bwrap) — after bwrap's own
    namespace setup, but before the payload's first instruction, so the
    shell, the socat bridge, the command and all descendants inherit it and
    nothing inside the sandbox ever runs unfiltered. (An in-sandbox helper
    used to install it; that had a pre-filter window — python3's site.py
    processes user .pth files and usercustomize, so code planted by a
    previous sandbox run under --home could fork an unfiltered child — and
    a fail-open default, because it needed python3 inside the sandbox.
    bwrap needs neither.) The payload also runs as pid 1 (--as-pid-1), so
    there is no unfiltered bwrap reaper init inside the sandbox: on Yama
    ptrace_scope=0 systems that parent could otherwise be /proc/1/mem-
    injected, which the ptrace-syscall ban cannot stop. On bwrap >= 0.8 the
    launcher also passes --disable-userns --assert-userns-disabled: nested
    user namespaces are then blocked at the kernel level
    (max_user_namespaces in a nested user namespace; bwrap verifies it),
    not only by the hand-typed syscall numbers below. The filter blocks
    kernel surface namespaces cannot hide — io_uring_*, bpf,
    perf_event_open, userfaultfd, the (non-namespaced) kernel keyring,
    nested user namespaces (unshare/setns/clone3/clone-with-CLONE_NEWUSER),
    admin ops (mount, umount2, pivot_root, chroot, kexec, module loading,
    open_by_handle_at, name_to_handle_at, quotactl, syslog and the new
    mount API: fsopen/fsconfig/fsmount/move_mount/open_tree/
    mount_setattr), process-injection APIs (ptrace, process_vm_readv/
    writev, kcmp, pidfd_getfd, personality, vmsplice) and ioctl
    TIOCSTI/TIOCLINUX; fanotify_init is denied too; socket() is limited to
    AF_UNIX/AF_INET/AF_INET6/AF_NETLINK (AF_VSOCK bypasses netns isolation
    in VM guests on older kernels). Denied calls return ENOSYS where
    runtimes have fallbacks (io_uring users, glibc clone3) and EPERM
    otherwise; foreign-ABI binaries (e.g. 32-bit compat, x32) are killed,
    whole thread group included. Fail-closed, not fail-open: if the filter
    cannot be installed (unsupported architecture, or a bwrap without
    seccomp support) the launcher refuses to run; --no-seccomp is the
    explicit opt-out. The hand-typed syscall tables are cross-checked
    against kernel headers / scmp_sys_resolver / ausyscall and a live
    filter probe by tests/test_seccomp.py (a wrong number once shipped
    here).

  - --filter-output (terminal output filtering): the sandbox shares the
    host terminal, and output is input to the terminal EMULATOR — OSC 52
    rewrites the clipboard, device queries elicit answerback replies,
    cursor/erase sequences can forge already-reviewed output, SGR 8
    (conceal) hides text from the reader, bidi/zero-width characters
    deceive. --new-session blocks TIOCSTI INPUT injection; this is the
    output counterpart. bwrap's stdin/stdout/stderr become a host-side
    pty SLAVE (the real host terminal fd never enters the sandbox —
    close_fds guarantees bwrap gets nothing else), and everything read
    from the master passes an allowlist filter before reaching the host
    terminal: printable text, \n/\r/\t and SGR color/style sequences
    (parameter string [0-9;]{0,64}, mode-8 conceal stripped) pass;
    OSC/DCS/APC/PM/SOS strings, non-SGR CSI, 2-byte and intermediate ESC
    sequences, remaining C0/C1 controls (incl. U+009B) and bidi/zero-
    width characters are dropped silently. A bare \r is allowed by
    default (progress bars depend on it), which also lets payload output
    VISUALLY overwrite the current line ("curl evil | sh\r" then "ok");
    --strict-crlf (implies --filter-output) drops \r unless it is
    immediately followed by \n. Trailing incomplete sequences
    are held across read() chunk boundaries and dropped past 4096 bytes;
    decoding is stateful UTF-8 with errors="replace". Host stdin is
    forwarded byte-wise into the pty — the host tty runs in raw mode for
    the duration (SIGWINCH forwarded via TIOCGWINSZ/TIOCSWINSZ, termios
    restored in a finally); piped stdin is forwarded too (EOF delivered
    as the pty's VEOF, ^D). Needs no new dependencies
    (pty/tty/termios/select).

  - --net skips all of the above: bwrap then shares the host network
    namespace (--unshare-all --share-net), /etc/resolv.conf is mounted, and
    no proxy is started (direct egress; the allowlist is NOT enforced, and
    host loopback services and abstract Unix sockets — D-Bus, X11, ... —
    become reachable; only use it for trusted work).
  - Lifecycle: one component dies -> everything dies (supervisor loop,
    --die-with-parent on bwrap, PR_SET_PDEATHSIG on the proxy; a SIGKILLed
    launcher therefore still takes the proxy with it).

Dependencies: bwrap, socat and python3 >= 3.8 on the host (stdlib only;
the seccomp filter is installed by bwrap itself — no python3 is needed
INSIDE the sandbox). The deny-list needs bwrap >= 0.4.1 (--seccomp) or any
newer bwrap (--add-seccomp-fd); --disable-userns needs >= 0.8 and
fd-pinned binds (below) need >= 0.10 — older bwrap degrades with a loud
note. --net mode needs bwrap only.

Known limits (design trade-offs, not bugs):
  - -b/--ro-bind paths are refused when they cover a protected path
    (system dirs, $HOME, /run/user/<uid>) or are socket-shaped: a known
    host control socket or its directory (CONTROL_SOCKETS, matched in
    both directions), any socket file, anything under /run, /var/run or
    $XDG_RUNTIME_DIR, or any directory containing a Unix socket (bounded
    scan) (--bind-socket PATH — read-only — opts back into the shape/scan
    rules per path; the list of names would always lag reality, the shape
    rules fail-close it). Anything else you
    bind — the launcher's /tmp/sbox.* work dir, which holds proxy.json and
    any upstream credentials, included — is handed over as requested.
    Validation and mount cannot diverge: the resolved source paths are
    opened O_PATH|O_NOFOLLOW (component-by-component openat walk, inode
    re-checked) and passed to bwrap >= 0.10 as --bind-fd/--ro-bind-fd, so
    a concurrent sandbox sharing a writable directory cannot swap a
    component for a symlink between check and mount (older bwrap: path
    binds, with a note).
  - Read-write binds of $HOME children are host code execution at next
    login/session (shell rc files, ~/.ssh/authorized_keys, systemd user
    units, XDG autostart, ~/.local/bin): a warning names the covered
    PERSISTENCE_PATHS — refusal would just lag reality. The rw cwd mount
    is the same deal by design (.git/hooks et al.); see the epilog.
  - --as-pid-1 makes the command pid 1 of the sandbox: long-lived commands
    that spawn and abandon children accumulate zombies (nothing reaps
    them; a shell as pid 1 reaps via waitpid(-1)), and signals sent to
    pid 1 from inside the sandbox are ignored unless the command handles
    them (pid-namespace init semantics). External teardown (SIGTERM to
    sbox.py, --die-with-parent) works exactly as before.
  - No resource limits (CPU/memory/PID/fds) inside the sandbox; the
    boundary is bwrap's namespaces plus the seccomp deny-list above. That
    deny-list is best-effort hardening against kernel attack surface; it
    is deny-list, so anything unlisted stays allowed, and any kernel bug
    reachable through an allowed syscall is still a full escape. It is
    fail-closed though: an unsupported architecture or a bwrap without
    seccomp support is a hard error, not a silent skip (--no-seccomp opts
    out explicitly).
  - The allowlist is also an exfiltration channel. Suffix matching means
    -a github.com allows pushing to (and gisting from) any repo of yours,
    not just cloning; multi-tenant domains (amazonaws.com, github.io,
    cloudfront.net, pages.dev, ...) allow attacker-controlled hosts under
    the same suffix. With --home, everything in $HOME can leave through
    any allowed host. Ports are unrestricted unless an entry carries
    :port, and there is no domain-fronting protection (an allowed CDN
    host may serve many origins).
  - With --upstream, the destination reaches the upstream as a literal IP:
    it sees CONNECT 1.2.3.4:443, never the hostname. Hostname-based policy
    or logging on that proxy cannot work, and some proxies reject IP
    CONNECT targets.
  - --home exposes the real $HOME: ~/.bashrc, ~/.local/bin and any agent
    sockets in it run with your full identity.
  - --ssh-agent forwards $SSH_AUTH_SOCK (one read-only socket file): any
    code in the sandbox can sign with every key loaded in the agent, i.e.
    authenticate as you wherever the network policy allows. The read-only
    bind limits the socket file, not the agent protocol: sandboxed code can
    equally strip all identities or lock the agent (ssh-add -D / -x) — a
    DoS on your agent, not a key leak. Prefer a dedicated agent holding
    only the needed key, loaded with ssh-add -c (confirm each use) or
    -h (destination constraint) when untrusted code runs.
  - The proxy has no connection caps, idle timeouts or header-count limits,
    tunnels have no TCP half-close, and only the first resolved address is
    tried when chaining through an upstream.
  - --filter-output: the pty slave is an inherited fd and cannot become
    the sandbox's controlling terminal (bwrap --new-session already
    started a fresh session), so job control inside is limited (shells
    report "no job control"). With the host tty raw, Ctrl-C is delivered
    to the sandbox as a byte: a command that never reads stdin cannot be
    interrupted from the keyboard — kill sbox.py from another shell. The
    filter is an allowlist: unusual-but-harmless characters beyond the
    deny ranges (NBSP, soft hyphen, other Unicode format characters) are
    dropped too, an unterminated OSC/DCS swallows following bytes until
    its terminator or the 4096-byte cap (fail-safe: less is displayed,
    never more), and SGR sequences containing conceal are dropped
    wholesale rather than rewritten. Hidden text is NOT prevented beyond
    SGR 8: matching foreground/background colors (black-on-black
    \x1b[30;40m, truecolor fg==bg) hide text just as well, and dropping
    all background colors would break legitimate output — review with
    colors off if it matters. A bare \r passes by default (progress
    bars); --strict-crlf drops it unless followed by \n. If the host
    terminal is not in UTF-8 mode while the sanitizer emits UTF-8,
    continuation bytes 0x80-0x9F of multibyte characters can be read as
    raw C1 controls by the terminal (niche misconfiguration — put the
    host terminal in UTF-8). A SIGKILL of the launcher leaves
    the host tty raw (as with any killed terminal program — run `reset`).

Installed to ~/.local/bin via config/sync.py (Directory("bin", ..., "~/.local/bin")).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import codecs
import ctypes
import errno
import fcntl
import ipaddress
import json
import os
import platform
import pty
import re
import select
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import termios
import time
import traceback
import tty
import urllib.parse

PROG = "sbox.py"
PR_SET_PDEATHSIG = 1
CONNECT_TIMEOUT = 15.0  # seconds; TCP + upstream handshakes

# Networks that an allowlisted *name* must never resolve into (SSRF guard).
# Private/loopback/link-local/multicast/reserved are covered by the
# ipaddress predicates; CGNAT is not is_private on older Pythons, so it is
# listed explicitly. Explicit -a IP/CIDR entries bypass this guard on purpose.
EXTRA_BAD_NETS = (ipaddress.ip_network("100.64.0.0/10"),)

# Paths that user binds (-b/-r) and the automatic cwd bind must never cover
# (they would shadow the tmpfs /tmp — exposing the host's /tmp and $WORK —
# hide /run/proxy.sock, or hand the sandbox a writable system directory).
SYSTEM_DIRS = {
    "/", "/bin", "/boot", "/dev", "/etc", "/lib", "/lib64", "/proc", "/run",
    "/sbin", "/sys", "/tmp", "/usr", "/var",
}

UPSTREAM_SCHEMES = ("http", "https", "socks5", "socks5h")


def covers(a: str, b: str) -> bool:
    """True if path a is equal to or an ancestor of path b (realpaths)."""
    a = a.rstrip("/")
    return b == a or b.startswith(a + "/")


# True while --filter-output holds the host tty in raw mode: the sbox.py
# diagnostics below must CR their own newlines then (OPOST is off).
_raw_term = False


def err(msg: str) -> None:
    line = f"{PROG}: {msg}"
    if _raw_term:
        line = line.replace("\n", "\r\n") + "\r"
    print(line, file=sys.stderr, flush=True)


def die(msg: str) -> None:
    err(msg)
    sys.exit(1)


# --------------------------------------------------------------- allowlist ---

NAME_RE = re.compile(
    r"^[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)*$"
)


def parse_allow_entry(raw: str) -> dict:
    """Parse one allow entry into {"kind": "name"|"net", "value", "port"}.

    Accepts: example.com, *.example.com (same thing), example.com:443,
    203.0.113.7, 203.0.113.0/24, [2001:db8::]/32, [2001:db8::]:443.
    Rejects anything else loudly (this is a fail-closed tool).
    """
    e = raw.split("#", 1)[0].strip().lower()
    while e.startswith("*."):
        e = e[2:]
    e = e.strip(".")
    if not e:
        raise ValueError("empty entry")
    if set(e) <= {"*", "."}:
        raise ValueError("wildcard-only entry would allow everything; use --net for unrestricted egress")

    port = None
    host = e
    if e.startswith("["):
        m = re.fullmatch(r"\[([0-9a-f:.]+)\](?:/(\d{1,3}))?(?::(\d+))?", e)
        if not m or ":" not in m.group(1):  # a bracketed host must be IPv6
            raise ValueError(f"malformed IPv6 entry: {raw!r}")
        host = m.group(1) + ("/" + m.group(2) if m.group(2) else "")
        if m.group(3):
            port = int(m.group(3))
    elif e.count(":") == 1:
        host, _, p = e.rpartition(":")
        if not p.isdigit():
            raise ValueError(f"bad port in allow entry {raw!r} (expected host:port)")
        port = int(p)
    if port is not None and not 1 <= port <= 65535:
        raise ValueError(f"bad port in allow entry {raw!r} (expected 1-65535)")

    if "*" in host:
        raise ValueError(f"wildcards are only supported as a leading '*.' in {raw!r}")

    try:
        # strict: never silently widen "203.0.113.7/24" to the whole /24.
        net = ipaddress.ip_network(host)
    except ValueError:
        # Anything that *looks* like an address must be a valid one — never
        # silently reclassify e.g. "300.1.2.3" or "example.com:443" as a name.
        if re.fullmatch(r"[0-9.]+", host) or ":" in host:
            try:
                widened = ipaddress.ip_network(host, strict=False)
            except ValueError:
                widened = None
            if widened is not None:
                raise ValueError(
                    f"{raw!r}: host bits set — refusing to widen to {widened}; "
                    f"write {widened.network_address}/{widened.prefixlen} instead"
                )
            raise ValueError(f"invalid IP/CIDR entry: {raw!r}")
        if not NAME_RE.fullmatch(host):
            raise ValueError(f"not a valid hostname, IP or CIDR: {raw!r}")
        return {"kind": "name", "value": host, "port": port}
    if net.prefixlen < (8 if net.version == 4 else 16):
        # /0 is an explicit catch-all, but 0.0.0.0/1 + 128.0.0.0/1 (or ::/1)
        # amount to the same thing while silently bypassing the private-range
        # guard for literal-IP destinations. Refuse effectively-global nets.
        raise ValueError(
            f"{raw!r} is an effectively catch-all network (/{net.prefixlen}); "
            f"add narrower entries or use --net for unrestricted egress"
        )
    return {"kind": "net", "value": str(net), "port": port}


def load_allows(opt_allows: list[str], opt_files: list[str]) -> list[dict]:
    entries: list[dict] = []
    for path in opt_files:
        if not os.path.isfile(path):
            die(f"cannot read allow file: {path}")
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for lineno, line in enumerate(fh, 1):
                raw = line.split("#", 1)[0].strip()  # '#' comments, blank lines
                if not raw:
                    continue
                try:
                    entries.append(parse_allow_entry(raw))
                except ValueError as e:
                    die(f"{path}:{lineno}: {e}")
    for raw in opt_allows:
        try:
            entries.append(parse_allow_entry(raw))
        except ValueError as e:
            die(f"--allow: {e}")
    return entries


def destination_allowed(allows: list[dict], host: str, port: int) -> tuple[bool, str]:
    """Allowlist check for a destination. Performs NO DNS and NO connection.

    Literal IPs match only -a IP/CIDR entries; names match name entries by
    exact or dot-boundary suffix comparison. Port-scoped entries additionally
    require the destination port to match.
    """
    h = host.rstrip(".").lower()
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        ip = None
    if ip is not None:
        for a in allows:
            if a["kind"] == "net" and a["port"] in (None, port) and ip in ipaddress.ip_network(a["value"]):
                return True, f"matches allowed network {a['value']}"
        return False, "IP destination not in any allowed network"
    for a in allows:
        if a["kind"] == "name" and a["port"] in (None, port):
            v = a["value"]
            if h == v or h.endswith("." + v):
                return True, f"matches allowed name {v}"
    return False, "hostname not on the allowlist"


def bad_ip(addr: ipaddress._BaseAddress) -> bool:
    if addr.version == 6:
        # Address forms that embed an IPv4 address: judge the embedded IPv4,
        # not the covering prefix.
        #   - NAT64 (RFC 6052, 64:ff9b::/96): ipaddress marks the whole
        #     prefix reserved, but on DNS64 networks legitimate public
        #     IPv4-only hosts come back this way.
        #   - 6to4 (RFC 3056, 2002::/16): the v6 form looks global, but
        #     relays decapsulate to the embedded IPv4 (bits 16..47), which
        #     may be loopback/LAN — SSRF via e.g. a 2002:7f00:1:: answer.
        #   - Teredo (RFC 4380, 2001:0::/32): deprecated — refuse the whole
        #     prefix instead of decoding it (layout: prefix, server IPv4,
        #     flags, obfuscated port, obfuscated client IPv4), and do not
        #     rely on is_private covering 2001::/23 on every Python version.
        try:
            if addr in ipaddress.ip_network("64:ff9b::/96"):
                embedded = addr.ipv4_mapped or ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
                return bad_ip(embedded)
            if addr in ipaddress.ip_network("2002::/16"):
                return bad_ip(ipaddress.IPv4Address((int(addr) >> 80) & 0xFFFFFFFF))
            if addr in ipaddress.ip_network("2001:0::/32"):
                return True
        except ipaddress.AddressValueError:
            pass
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
        or any(addr in n for n in EXTRA_BAD_NETS)
    )


# ------------------------------------------------------------------- proxy ---

class DestinationError(Exception):
    """Denial/connection failure; .rep is the SOCKS5 reply code."""

    def __init__(self, rep: int, why: str):
        super().__init__(why)
        self.rep = rep
        self.why = why


def _parse_ip(host: str):
    try:
        return ipaddress.ip_address(host.rstrip("."))
    except ValueError:
        return None


async def resolve_filtered(host: str, port: int) -> list:
    """Resolve host on the host side and drop blocked (private etc.) answers."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except (socket.gaierror, UnicodeError) as e:
        raise DestinationError(4, f"DNS failure for {host}: {e}")
    good, blocked = [], []
    for info in infos:
        sockaddr = info[4]
        ip = ipaddress.ip_address(sockaddr[0])
        if bad_ip(ip):
            blocked.append(str(ip))
        else:
            good.append(info)
    if blocked and not good:
        raise DestinationError(
            2, f"{host} resolves only to blocked (private/loopback/link-local) addresses: {', '.join(blocked)}"
        )
    if not good:
        raise DestinationError(4, f"no usable addresses for {host}")
    return good


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    try:
        while True:
            buf = await src.read(65536)
            if not buf:
                break
            dst.write(buf)
            await dst.drain()
    except Exception:
        pass  # OSError and anything else: the tunnel is done either way
    finally:
        try:
            dst.close()
        except Exception:
            pass


async def _tunnel(cr, cw, sr, sw) -> None:
    """Bidirectional copy; tear down as soon as one direction ends."""
    t1 = asyncio.create_task(_pipe(cr, sw))
    t2 = asyncio.create_task(_pipe(sr, cw))
    _, pending = await asyncio.wait({t1, t2}, return_when=asyncio.FIRST_COMPLETED)
    for t in pending:
        t.cancel()
    await asyncio.gather(*pending, return_exceptions=True)
    for w in (cw, sw):
        try:
            w.close()
        except Exception:
            pass


def parse_hostport(target: str, default_port: int) -> tuple[str, int]:
    if target.startswith("["):
        host, _, rest = target[1:].partition("]")
        if not host or rest and not rest.startswith(":"):
            raise ValueError(target)
        port = int(rest[1:]) if rest else default_port
        return host, port
    host, _, p = target.rpartition(":")
    if not host:
        return target, default_port
    if not p.isdigit() or not 1 <= int(p) <= 65535:
        raise ValueError(target)
    return host, int(p)


class Proxy:
    """SOCKS5 + HTTP-CONNECT proxy with an allowlist, on a Unix socket."""

    def __init__(self, cfg: dict):
        self.allows = cfg.get("allows", [])
        self.upstream = cfg.get("upstream")
        self.verbose = bool(cfg.get("verbose"))

    def log(self, msg: str) -> None:
        if self.verbose:
            print(f"sbox-proxy: {msg}", file=sys.stderr, flush=True)

    # -- destination handling -------------------------------------------------

    async def connect_destination(self, host: str, port: int):
        """Allowlist -> resolve (SSRF-guarded) -> connect (or chain upstream).

        Returns (reader, writer) of the established tunnel; raises
        DestinationError otherwise. Never resolves denied names.
        """
        if not 1 <= port <= 65535:
            raise DestinationError(1, f"invalid port {port}")
        h = host.rstrip(".").lower()
        ip = _parse_ip(h)
        if ip is None and (
            not NAME_RE.fullmatch(h)
            # getaddrinfo raises bare UnicodeError (a ValueError) for labels
            # over 63 chars — reject here for a clean client error instead.
            or len(h) > 253
            or any(len(label) > 63 for label in h.split("."))
        ):
            # Never hand sandbox-controlled bytes to the resolver: embedded
            # NULs, backslash escapes etc. are rejected before getaddrinfo.
            raise DestinationError(4, f"invalid hostname {host!r}")
        allowed, why = destination_allowed(self.allows, h, port)
        if not allowed:
            # !r: hostnames come from the sandbox and may contain control
            # bytes — never let them reach the terminal raw.
            self.log(f"deny  {h!r}:{port} — {why}")
            raise DestinationError(2, why)

        if self.upstream:
            if ip is None:
                infos = await resolve_filtered(h, port)
                ip = ipaddress.ip_address(infos[0][4][0])
            u = self.upstream
            self.log(f"allow {h!r}:{port} — via {u['scheme']} upstream {u['host']}:{u['port']} to {ip}")
            return await self._open_upstream(str(ip), port)
        if ip is not None:
            # Literal IP allowed explicitly: private ranges are intentional.
            self.log(f"allow {h!r}:{port} — direct (allowed literal IP)")
            try:
                return await asyncio.wait_for(asyncio.open_connection(str(ip), port), CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                raise DestinationError(5, f"connect to {ip}:{port} failed: {e}")
        infos = await resolve_filtered(h, port)
        self.log(f"allow {h!r}:{port} — resolved " + ", ".join(str(i[4][0]) for i in infos))
        last: Exception | None = None
        for info in infos:
            sockaddr = info[4]
            try:
                return await asyncio.wait_for(asyncio.open_connection(sockaddr[0], sockaddr[1]), CONNECT_TIMEOUT)
            except (OSError, asyncio.TimeoutError) as e:
                last = e
        raise DestinationError(5, f"connect to {h}:{port} failed: {last}")

    async def _open_upstream(self, dest_ip: str, dest_port: int):
        u = self.upstream

        async def handshake():
            ssl_ctx = None
            if u["scheme"] == "https":
                ssl_ctx = ssl.create_default_context()
                if not u["tls_verify"]:
                    ssl_ctx.check_hostname = False
                    ssl_ctx.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.open_connection(u["host"], u["port"], ssl=ssl_ctx)
            if u["scheme"] in ("http", "https"):
                req = f"CONNECT {dest_ip}:{dest_port} HTTP/1.1\r\nHost: {dest_ip}:{dest_port}\r\n"
                if u["user"] is not None:
                    token = base64.b64encode(f"{u['user']}:{u['pass'] or ''}".encode()).decode()
                    req += f"Proxy-Authorization: Basic {token}\r\n"
                req += "\r\n"
                writer.write(req.encode("latin-1"))
                status = await reader.readline()
                parts = status.split(None, 2)
                if len(parts) < 2 or not parts[1].startswith(b"2"):
                    raise OSError(f"upstream CONNECT failed: {status.decode('latin-1', 'replace').strip()}")
                while True:
                    line = await reader.readline()
                    if line in (b"\r\n", b"\n", b""):
                        break
            else:  # socks5
                writer.write(b"\x05\x01\x02" if u["user"] is not None else b"\x05\x01\x00")
                resp = await reader.readexactly(2)
                if resp[0] != 5:
                    raise OSError("upstream is not SOCKS5")
                if resp[1] == 0x02:
                    user = (u["user"] or "").encode()
                    pw = (u["pass"] or "").encode()
                    if len(user) > 255 or len(pw) > 255:
                        raise OSError("upstream credentials too long")
                    writer.write(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
                    auth = await reader.readexactly(2)
                    if auth[1] != 0:
                        raise OSError("upstream username/password auth failed")
                elif resp[1] != 0x00:
                    raise OSError("upstream refused our auth methods")
                addr = ipaddress.ip_address(dest_ip)
                if addr.version == 4:
                    writer.write(b"\x05\x01\x00\x01" + socket.inet_aton(dest_ip))
                else:
                    writer.write(b"\x05\x01\x00\x04" + socket.inet_pton(socket.AF_INET6, dest_ip))
                writer.write(struct.pack(">H", dest_port))
                rep = await reader.readexactly(4)
                if rep[1] != 0:
                    raise OSError(f"upstream CONNECT failed with reply code {rep[1]}")
                if rep[3] == 1:
                    await reader.readexactly(4 + 2)
                elif rep[3] == 3:
                    n = (await reader.readexactly(1))[0]
                    await reader.readexactly(n + 2)
                elif rep[3] == 4:
                    await reader.readexactly(16 + 2)
            return reader, writer

        try:
            return await asyncio.wait_for(handshake(), CONNECT_TIMEOUT)
        except DestinationError:
            raise
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError) as e:
            raise DestinationError(1, f"upstream {u['scheme']}://{u['host']}:{u['port']} failed: {e}")

    # -- SOCKS5 ----------------------------------------------------------------

    @staticmethod
    async def _socks_reply(writer: asyncio.StreamWriter, rep: int) -> None:
        writer.write(b"\x05" + bytes([rep]) + b"\x00\x01\x00\x00\x00\x00\x00\x00")
        await writer.drain()

    async def _socks5(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        nmethods = (await reader.readexactly(1))[0]
        methods = await reader.readexactly(nmethods)
        if 0 not in methods:  # only NO-AUTH (the socket is 0600, mode 0)
            writer.write(b"\x05\xff")
            await writer.drain()
            return
        writer.write(b"\x05\x00")
        await writer.drain()
        try:
            ver, cmd, _rsv, atyp = await reader.readexactly(4)
            if ver != 5:
                return
            if atyp == 1:
                host = socket.inet_ntop(socket.AF_INET, await reader.readexactly(4))
            elif atyp == 3:
                length = (await reader.readexactly(1))[0]
                host = (await reader.readexactly(length)).decode("ascii")
            elif atyp == 4:
                host = socket.inet_ntop(socket.AF_INET6, await reader.readexactly(16))
            else:
                return await self._socks_reply(writer, 8)  # address type unsupported
            port = struct.unpack(">H", await reader.readexactly(2))[0]
        except (asyncio.IncompleteReadError, UnicodeDecodeError):
            return
        if cmd != 1:  # only CONNECT
            return await self._socks_reply(writer, 7)
        try:
            sr, sw = await self.connect_destination(host, port)
        except DestinationError as e:
            return await self._socks_reply(writer, e.rep)
        except (OSError, asyncio.TimeoutError):
            return await self._socks_reply(writer, 1)
        await self._socks_reply(writer, 0)
        await _tunnel(reader, writer, sr, sw)

    # -- HTTP (CONNECT + absolute-form) -----------------------------------------

    @staticmethod
    async def _http_error(writer: asyncio.StreamWriter, code: int, text: str, reason: str = "") -> None:
        phrase = {400: "Bad Request", 403: "Forbidden", 502: "Bad Gateway"}.get(code, "Error")
        body = text.encode("utf-8", "replace")
        hdr = f"HTTP/1.1 {code} {phrase}\r\nContent-Length: {len(body)}\r\nConnection: close\r\n"
        if reason:
            # Reasons can embed attacker-controlled hostnames: keep the header
            # single-line and printable.
            safe = "".join(c if "\x20" <= c <= "\x7e" else " " for c in reason)[:200]
            hdr += "X-Sbox-Error: " + safe + "\r\n"
        writer.write(hdr.encode("latin-1") + b"\r\n" + body)
        await writer.drain()

    async def _http_connect(self, reader, writer, target: str) -> None:
        try:
            host, port = parse_hostport(target, 80)
        except ValueError:
            return await self._http_error(writer, 400, "bad CONNECT target\n")
        while True:  # drain request headers up to the blank line
            line = await reader.readline()
            if line in (b"\r\n", b"\n", b""):
                break
        try:
            sr, sw = await self.connect_destination(host, port)
        except DestinationError as e:
            code = 403 if e.rep == 2 else 502
            return await self._http_error(writer, code, f"{code}: {e.why}\n", e.why)
        writer.write(b"HTTP/1.1 200 Connection established\r\n\r\n")
        await writer.drain()
        await _tunnel(reader, writer, sr, sw)

    async def _http_absolute(self, reader, writer, method: str, url: str) -> None:
        try:
            parts = urllib.parse.urlsplit(url)
            host = parts.hostname or ""
            port = parts.port if parts.port is not None else 80  # :0 is NOT 80
            if parts.scheme.lower() != "http" or not host:
                raise ValueError(url)
        except ValueError:  # urlsplit/bad port/unsupported scheme -> 400
            return await self._http_error(
                writer, 400, "only http:// absolute URLs are proxied; https:// must use CONNECT\n"
            )
        headers: list[tuple[str, str]] = []
        try:
            while True:
                line = await reader.readline()
                if line in (b"\r\n", b"\n", b""):
                    break
                name, _, value = line.decode("latin-1").partition(":")
                if name:
                    headers.append((name, value.strip()))
        except UnicodeDecodeError:
            return await self._http_error(writer, 400, "malformed headers\n")
        if not any(n.lower() == "host" for n, _ in headers):
            # Synthesize Host from host[:port]: never copy the netloc, which
            # may carry userinfo (http://user@host/) that must not reach the
            # origin server. IPv6 literals need their brackets back.
            if ":" in host:
                headers.append(("Host", f"[{host}]:{port}"))
            elif port != 80:
                headers.append(("Host", f"{host}:{port}"))
            else:
                headers.append(("Host", host))
        drop = {"proxy-connection", "proxy-authorization", "connection", "keep-alive"}
        head = "".join(f"{n}: {v}\r\n" for n, v in headers if n.lower() not in drop)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        try:
            sr, sw = await self.connect_destination(host, port)
        except DestinationError as e:
            code = 403 if e.rep == 2 else 502
            return await self._http_error(writer, code, f"{code}: {e.why}\n", e.why)
        sw.write(f"{method} {path} HTTP/1.1\r\n{head}Connection: close\r\n\r\n".encode("latin-1"))
        await sw.drain()
        await _tunnel(reader, writer, sr, sw)

    async def _http(self, reader, writer, first: bytes) -> None:
        line = first + await reader.readline()
        parts = line.decode("latin-1", "replace").split()
        if len(parts) < 3 or not parts[2].upper().startswith("HTTP/"):
            return await self._http_error(writer, 400, "bad request line\n")
        method, target = parts[0].upper(), parts[1]
        if method == "CONNECT":
            return await self._http_connect(reader, writer, target)
        if method in ("GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"):
            return await self._http_absolute(reader, writer, method, target)
        return await self._http_error(writer, 400, f"method {method} not supported\n")

    # -- dispatch ----------------------------------------------------------------

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                first = await reader.readexactly(1)
            except (asyncio.IncompleteReadError, OSError):
                return  # client closed immediately (readiness probe) — fine
            if first == b"\x05":  # SOCKS5 greeting always starts with 0x05
                await self._socks5(reader, writer)
            else:
                await self._http(reader, writer, first)
        except Exception:
            if self.verbose:
                traceback.print_exc(file=sys.stderr)
        finally:
            try:
                writer.close()
            except Exception:
                pass


def proxy_main(sock_path: str, cfg_path: str, expected_ppid: int) -> int:
    # Die with the launcher even if it is SIGKILLed.
    try:
        ctypes.CDLL(None, use_errno=True).prctl(PR_SET_PDEATHSIG, signal.SIGTERM, 0, 0, 0)
    except Exception:
        pass
    if os.getppid() != expected_ppid:  # launcher died between fork and prctl
        return 1
    with open(cfg_path, "r", encoding="utf-8") as fh:
        proxy = Proxy(json.load(fh))

    async def serve() -> None:
        server = await asyncio.start_unix_server(proxy.handle, path=sock_path)
        os.chmod(sock_path, 0o600)
        async with server:
            await server.serve_forever()

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        pass
    return 0


# ------------------------------------------------------------------ client ---

def redact_userinfo(url: str) -> str:
    """url with any userinfo (user[:pass]@) removed, so it is safe to print
    (die() output ends up in the terminal and scrollback)."""
    return re.sub(r"//[^/?#]*@", "//", url, count=1)


def parse_upstream(raw: str, insecure: bool) -> dict | None:
    if not raw:
        return None
    url = raw if "://" in raw else "http://" + raw
    # Error messages echo the redacted URL only: --upstream URLs may carry
    # credentials in the userinfo.
    safe = redact_userinfo(url)
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        die(f"cannot parse --upstream URL: {safe}")
    scheme = (parts.scheme or "http").lower()
    if scheme not in UPSTREAM_SCHEMES:
        die(f"unsupported --upstream scheme {scheme!r} (supported: {', '.join(UPSTREAM_SCHEMES)}): {safe}")
    host = parts.hostname
    if not host:
        die(f"cannot parse --upstream URL: {safe}")
    default = 443 if scheme == "https" else 1080 if scheme.startswith("socks5") else 80
    try:
        port = parts.port  # raises ValueError for non-numeric/out-of-range
    except ValueError:
        die(f"bad port in --upstream URL: {safe}")
    if port is None:
        port = default
    elif not 1 <= port <= 65535:  # urlsplit allows :0; that is not a port
        die(f"bad port in --upstream URL: {safe}")
    return {
        # socks5h behaves like socks5 here: resolution stays on our side so
        # the allowlist and the private-IP guard keep applying.
        "scheme": "socks5" if scheme == "socks5h" else scheme,
        "host": host,
        "port": port,
        "user": urllib.parse.unquote(parts.username) if parts.username is not None else None,
        "pass": urllib.parse.unquote(parts.password) if parts.password is not None else None,
        "tls_verify": not insecure,
    }


def self_test(sock_path: str, allows: list[dict]) -> None:
    """Fail-closed gate on the real socket, before the sandbox starts: a
    non-allowed destination must be refused on both SOCKS5 and HTTP CONNECT
    (denied names are never resolved, so this needs no network)."""
    name = f"sbox-selftest-{os.urandom(4).hex()}.invalid"
    if destination_allowed(allows, name, 80)[0]:
        err("note: allowlist covers the self-test destination; skipping enforcement check")
        return
    try:
        # SOCKS5: expect REP=2 (not allowed)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(sock_path)
            s.sendall(b"\x05\x01\x00")
            if s.recv(2) != b"\x05\x00":
                die("self-test: bad SOCKS5 greeting on the proxy socket")
            host = name.encode()
            s.sendall(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + struct.pack(">H", 80))
            rep = s.recv(64)
            if len(rep) < 2 or rep[1] != 0x02:
                die(f"self-test: SOCKS5 denial not enforced (reply={rep[:2].hex() if rep else 'eof'}) — failing closed")
        # HTTP CONNECT: expect 403
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(sock_path)
            s.sendall(f"CONNECT {name}:80 HTTP/1.1\r\nHost: {name}\r\n\r\n".encode())
            status = s.recv(128)
            if not status.startswith(b"HTTP/1.1 403"):
                first = status.split(b"\r\n")[0][:40] if status else b"<eof>"
                die(f"self-test: HTTP denial not enforced ({first!r}) — failing closed")
    except OSError as e:  # wedged proxy, timeouts: fail closed with a clean message
        die(f"self-test: cannot talk to the proxy ({e!r}) — failing closed")


# --------------------------------------------------------- output filter ---
# --filter-output: the sandbox shares the host terminal, and output is
# INPUT to the terminal emulator: OSC 52 rewrites the clipboard, device
# status queries elicit answerback replies, cursor/erase sequences can
# forge already-reviewed output, SGR 8 (conceal) hides text from the
# human reading it, bidi overrides and zero-width characters deceive.
# --new-session (always on) blocks TIOCSTI input injection; this is the
# output-side counterpart: a host-side pty whose slave is the sandbox's
# ONLY stdio (the real host terminal fd never enters the sandbox), and
# everything read from the master passes an allowlist filter before it
# reaches the host terminal.

ESCAPE = "\x1b"
BEL = "\x07"
CAN = "\x18"    # VT parser abort codes for a pending escape sequence
SUB = "\x1a"

# The ONLY escapes the filter lets through: SGR color/style whose
# parameter string is digits and semicolons, at most 64 chars. The regex
# is the whole validity check — every other CSI body (private markers
# like '?', intermediates, ':' subparameters) fails it and is dropped.
SGR_PARAMS_RE = re.compile(r"[0-9;]{0,64}")

# An unterminated escape sequence is dropped wholesale past this many
# bytes, so a malformed stream cannot grow host memory without bound.
# The buffer holds decoded characters but the cap counts bytes (each
# add accounts for the UTF-8 encoding of the character).
MAX_PENDING_SEQ = 4096

# Backlog cap for stdin bytes the sandbox is not reading: the pty buffer
# is small, the pump never blocks, so slow consumers must not make the
# host-side buffer unbounded. Beyond it, newly read input is dropped.
MAX_PENDING_INPUT = 262144

# Filter states: plain text, after ESC, ESC + intermediates, inside CSI,
# inside a string (OSC/DCS/APC/PM/SOS), and the ESC seen inside one.
_F_PLAIN, _F_ESC, _F_ESC_INT, _F_CSI, _F_STR, _F_STR_ESC = range(6)

# ESC ] OSC, ESC P DCS, ESC _ APC, ESC ^ PM, ESC X SOS — all dropped
# wholesale (clipboard writes, titles, hyperlinks, queries, ...).
_STRING_OPENERS = "]P_^X"


def _char_allowed(ch: str) -> bool:
    """Allowlist for a plain (non-escape) character: printable text only.

    \\n \\r \\t are handled by the caller; everything refused here is
    dropped — remaining C0 controls, DEL, C1 controls (U+0080..U+009F,
    including the single-character CSI U+009B and OSC U+009D), bidi
    overrides, zero-width/invisible characters, and anything else
    non-printable (NBSP, soft hyphen, ...). C1 bytes are NOT interpreted
    as sequence initiators — they never start a valid UTF-8 escape.
    """
    o = ord(ch)
    if o < 0x20 or 0x7F <= o <= 0x9F:
        return False
    if 0x200B <= o <= 0x200F:      # ZWSP ZWNJ ZWJ LRM RLM
        return False
    if 0x202A <= o <= 0x202E:      # bidi overrides LRE RLE PDF LRO RLO
        return False
    if o in (0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF):
        return False               # word joiner, LRI RLI FSI PDI, BOM
    return ch.isprintable()        # the general printable-text allowlist


def _sgr_conceals(params: str) -> bool:
    """True if an SGR parameter string sets mode 8 (conceal/invisible).

    38/48 (extended fg/bg color) take subparameters — '38;5;8' selects
    color index 8, not conceal — so their arguments are skipped, walking
    the string exactly like a terminal does. Unknown extended forms
    degrade to scanning every remaining parameter (fail-safe: the whole
    sequence is dropped). Leading zeros count ('08' is 8).
    """
    parts = params.split(";")
    i = 0
    while i < len(parts):
        p = parts[i]
        if p.lstrip("0") == "8":
            return True
        if p in ("38", "48") and i + 1 < len(parts) and parts[i + 1] in ("5", "2"):
            i += 3 if parts[i + 1] == "5" else 5   # 38;5;N / 38;2;R;G;B
            continue
        i += 1
    return False


class OutputSanitizer:
    """Stateful allowlist filter for sandbox terminal output.

    feed() takes raw bytes read from the pty master and returns the text
    that is safe to show on the host terminal. Decoding is stateful
    (incremental UTF-8, errors replaced), so multibyte characters split
    across read() boundaries survive; a trailing incomplete escape
    sequence is held back until its final byte arrives in a later chunk
    (or the byte cap drops it).

    Allowed: printable text, \\n, \\r, \\t, and SGR color/style sequences
    whose parameter string is [0-9;]{0,64} and sets no mode 8. Everything
    else — OSC/DCS/APC/PM/SOS strings, non-SGR CSI (cursor movement,
    screen clears, device queries), 2-byte and intermediate ESC
    sequences, remaining C0/C1 controls, bidi overrides and zero-width
    characters — is dropped silently.

    strict_cr=True additionally drops every \\r that is not immediately
    followed by \\n: a bare \\r moves the cursor to column 0, so payload
    output can visually overwrite the current line after you read it
    ("curl evil | sh\\r" + "ok"). The decision needs one character of
    lookahead, so a trailing \\r is held across feed() boundaries and
    dropped at flush() — chunked delivery filters identically either way.
    This breaks progress bars and any \\r-relying redraw, hence the opt-in.
    """

    def __init__(self, strict_cr: bool = False) -> None:
        self.strict_cr = strict_cr
        self._cr_pending = False  # strict mode: a \r awaiting its next byte
        self._dec = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._state = _F_PLAIN
        self._seq: list[str] = []
        self._seq_len = 0  # bytes (not codepoints) held in _seq

    # -- pending-sequence buffer ------------------------------------------

    def _seq_start(self, ch: str, state: int) -> None:
        self._seq = [ch]
        self._seq_len = len(ch.encode("utf-8"))
        self._state = state

    def _seq_add(self, ch: str) -> None:
        self._seq.append(ch)
        self._seq_len += len(ch.encode("utf-8"))
        if self._seq_len > MAX_PENDING_SEQ:
            self._seq_drop()  # malformed stream: drop, never grow unbounded

    def _seq_drop(self) -> None:
        self._seq = []
        self._seq_len = 0
        self._state = _F_PLAIN

    # -- filtering ------------------------------------------------------------

    def feed(self, data: bytes) -> str:
        """Filter one read() chunk; stateful UTF-8 decoding with
        errors='replace' keeps split multibyte characters intact."""
        return self._filter(self._dec.decode(data))

    def flush(self) -> str:
        """End of stream: decode leftovers (as U+FFFD); a sequence that
        never terminated is dropped — it is malformed by definition."""
        text = self._filter(self._dec.decode(b"", final=True))
        self._seq_drop()
        if self._cr_pending:  # a trailing bare \r never finds its \n
            self._cr_pending = False
        return text

    def _finish_csi(self, final: str, out: list[str]) -> None:
        seq = "".join(self._seq)
        params = seq[2:-1]  # between "\x1b[" and the final byte
        self._seq_drop()    # consumed either way
        if final == "m" and SGR_PARAMS_RE.fullmatch(params) \
                and not _sgr_conceals(params):
            out.append(seq)
        # else: non-SGR CSI (cursor, clears, device queries, private
        # markers) or a malformed/concealing SGR — dropped

    def _filter(self, text: str) -> str:
        out: list[str] = []
        for ch in text:
            if self._cr_pending:
                # strict mode: the previous \r is only emitted when THIS
                # character is \n; anything else means it was a bare \r.
                self._cr_pending = False
                if ch == "\n":
                    out.append("\r")  # then \n flows through the sm below
            st = self._state
            if st == _F_PLAIN:
                if ch == ESCAPE:
                    self._seq_start(ESCAPE, _F_ESC)
                elif ch == "\r" and self.strict_cr:
                    self._cr_pending = True  # decide on the next character
                elif ch in "\n\r\t" or _char_allowed(ch):
                    out.append(ch)
                # else dropped: C0/C1 controls, DEL, bidi overrides,
                # zero-width and other non-printable characters
            elif st == _F_ESC:
                o = ord(ch)
                if ch == "[":
                    self._seq_add(ch)
                    self._state = _F_CSI
                elif ch in _STRING_OPENERS:
                    self._seq_add(ch)
                    self._state = _F_STR
                elif ch == ESCAPE:
                    self._seq_start(ESCAPE, _F_ESC)  # restart on a new ESC
                elif ch in (CAN, SUB):
                    self._seq_drop()
                elif 0x20 <= o <= 0x2F:  # intermediates, e.g. ESC ( B
                    self._seq_add(ch)
                    self._state = _F_ESC_INT
                elif 0x30 <= o <= 0x7E:  # 2-byte escape: never allowed
                    self._seq_drop()
                # anything else (stray C0/C1/DEL): swallowed, keep waiting
                # for the sequence to complete (or the cap to drop it)
            elif st == _F_ESC_INT:
                o = ord(ch)
                if ch == ESCAPE:
                    self._seq_start(ESCAPE, _F_ESC)
                elif ch in (CAN, SUB):
                    self._seq_drop()
                elif 0x20 <= o <= 0x2F:
                    self._seq_add(ch)  # further intermediates
                elif 0x30 <= o <= 0x7E:  # final byte: charset etc. — dropped
                    self._seq_drop()
                # else swallowed
            elif st == _F_CSI:
                o = ord(ch)
                if 0x40 <= o <= 0x7E:  # final byte terminates the sequence
                    self._seq_add(ch)
                    self._finish_csi(ch, out)
                elif ch == ESCAPE:
                    self._seq_start(ESCAPE, _F_ESC)  # abort, restart
                elif ch in (CAN, SUB):
                    self._seq_drop()
                elif 0x20 <= o <= 0x3F:  # parameter bytes + intermediates
                    self._seq_add(ch)
                # else swallowed (stray controls/DEL/non-ASCII in the body)
            elif st == _F_STR:
                if ch == BEL:  # OSC-BEL terminator
                    self._seq_drop()
                elif ch == ESCAPE:
                    self._seq_add(ch)
                    self._state = _F_STR_ESC
                elif ch in (CAN, SUB):
                    self._seq_drop()
                else:  # string content: collected only to be dropped
                    self._seq_add(ch)
            else:  # _F_STR_ESC: ESC inside a string, maybe a ST (ESC \)
                if ch == "\\":
                    self._seq_drop()  # ST: properly terminated — dropped
                elif ch in (CAN, SUB):
                    self._seq_drop()
                elif ch == ESCAPE:
                    pass  # another ESC: still not a terminator
                else:  # not a terminator after all: back to content
                    self._seq_add(ch)
                    self._state = _F_STR
        return "".join(out)


def _emit_filtered(text: str) -> None:
    """Write filtered sandbox output to the host terminal (stdout)."""
    if not text:
        return
    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except UnicodeEncodeError:
        # Non-UTF-8 host locale: show replacement bytes instead of dying.
        buf = sys.stdout.buffer
        buf.write(text.encode("utf-8", "replace"))
        buf.flush()
    except (OSError, ValueError):
        pass  # stdout closed: filtering is moot, keep supervising


def _copy_winsize(src_fd: int, dst_fd: int) -> None:
    """Forward a terminal resize: TIOCGWINSZ on the host tty, TIOCSWINSZ
    on the pty master (which also SIGWINCHes the pty's foreground pgrp)."""
    try:
        packed = fcntl.ioctl(src_fd, termios.TIOCGWINSZ, b"\x00" * 8)
        fcntl.ioctl(dst_fd, termios.TIOCSWINSZ, packed)
    except OSError:
        pass


def _read_maybe(fd: int, n: int = 65536) -> bytes | None:
    """Read from a select-readable fd: data, b"" on EOF (pty master EIO
    included), or None when nothing was readable after all (EAGAIN)."""
    try:
        return os.read(fd, n)
    except BlockingIOError:
        return None
    except OSError:
        return b""  # EIO (pty EOF) or a dead fd: treat as end of stream


def _drain_master(master: int, sanitizer: OutputSanitizer) -> None:
    """After bwrap exited: read the pty master until EOF or a short
    deadline — the payload may still be dying (--die-with-parent runs a
    beat later) with final output in flight, but a daemonized child can
    hold the slave open forever, so the drain is bounded."""
    deadline = time.monotonic() + 0.5
    while time.monotonic() < deadline:
        try:
            ready, _, _ = select.select([master], [], [], 0.05)
        except OSError:
            break
        if not ready:
            continue
        try:
            data = os.read(master, 65536)
        except BlockingIOError:
            continue
        except OSError:
            break  # EIO: every slave fd is closed — real EOF
        if not data:
            break
        _emit_filtered(sanitizer.feed(data))
    _emit_filtered(sanitizer.flush())


def _host_tty_fd() -> int | None:
    """A host terminal fd for TIOCGWINSZ: stdin, else stdout."""
    for stream in (sys.stdin, sys.stdout):
        try:
            if stream is not None and stream.isatty():
                return stream.fileno()
        except (OSError, ValueError, AttributeError):
            pass
    return None


def _forwardable_stdin_fd() -> int | None:
    """An fd to forward host stdin from when there is no raw tty: a
    real stdin keeps `... | sbox.py --filter-output -- cmd` pipelines
    working exactly like the non-filtered mode (bwrap inherits stdin)."""
    try:
        if sys.stdin is not None:
            return sys.stdin.fileno()
    except (OSError, ValueError, AttributeError):
        pass
    return None


def _enter_raw_mode() -> tuple[int | None, list | None]:
    """Put the host stdin tty into raw mode; returns (fd, saved termios)
    for restoring, or (None, None) when stdin is not a usable tty. Raw
    mode is what makes byte-wise stdin forwarding possible (no line
    buffering, no host-side signal/echo processing)."""
    global _raw_term
    try:
        if not sys.stdin.isatty():
            return None, None
        fd = sys.stdin.fileno()
        saved = termios.tcgetattr(fd)
        tty.setraw(fd)
    except (OSError, ValueError, termios.error):
        return None, None
    _raw_term = True
    return fd, saved


def _restore_termios(fd: int, saved) -> None:
    try:
        termios.tcsetattr(fd, termios.TCSADRAIN, saved)
    except (OSError, termios.error):
        pass


# ---------------------------------------------------------------- seccomp ---
# A deny-list cBPF program bwrap installs itself, as the very last step
# before exec'ing the payload (--add-seccomp-fd / --seccomp, see run_sandbox)
# — after bwrap's own namespace setup, but before the payload's first
# instruction, so the shell, the socat bridge, the command and all
# descendants inherit it and nothing inside runs unfiltered. (Installing it
# from a python3 helper inside the sandbox — the previous design — had a
# pre-filter window: site.py runs user .pth files/usercustomize before the
# helper's first statement, and it failed open when the sandbox had no
# python3.) Kernel attack surface that namespaces alone cannot hide; the
# same list Flatpak/Chrome disable
# for untrusted code:
#   io_uring_*                large, bug-prone surface (Google disabled it)
#   bpf, perf_event_open,     classic LPE primitives, almost never
#   userfaultfd               legitimate for ordinary tools
#   keyctl, add_key,          the kernel keyring is NOT namespaced
#   request_key
#   unshare, setns, clone3,   nested user namespaces hand the sandboxed
#   clone with CLONE_NEWUSER  process CAP_SYS_ADMIN over a new namespace
#                             (netfilter, mount handling, ... follow)
#   mount, umount2,           administrative operations normal tools never
#   pivot_root, kexec_load,   need
#   kexec_file_load,
#   init_module, finit_module,
#   delete_module,
#   open_by_handle_at,         file handles bypass directory permissions
#   name_to_handle_at,         (and DAC); quotactl/syslog/fanotify_init are
#   quotactl, syslog,          admin/surface calls normal tools never need
#   fanotify_init              (syslog = kernel log, KASLR leaks where
#                             dmesg_restrict=0 — Docker denies it too)
#   vmsplice                   historical LPE primitive, plain pipes cover
#                             ordinary tools
#   ptrace, process_vm_       injecting syscalls into other processes —
#   readv, process_vm_writev  defense in depth: everything inside the
#                             sandbox shares the filter, but deny the
#                             injection APIs outright (gdb/strace need
#                             --no-seccomp)
#   kcmp, pidfd_getfd,        more process-inspection/fd-stealing surface
#   personality, chroot       legacy attack surface (setarch -R needs
#                             --no-seccomp)
#   fsopen, fsmount, fsconfig, the new mount API: same powers as mount(),
#   move_mount, open_tree,    which the caps normally already gate — pure
#   mount_setattr             defense in depth
#   socket(AF_VSOCK/AF_       AF_VSOCK reaches the hypervisor in VM guests,
#   PACKET/...)               bypassing the netns on older kernels; only
#                             AF_UNIX/INET/INET6/NETLINK pass (Flatpak's set)
#   ioctl TIOCSTI /           injecting keystrokes into the controlling tty
#   TIOCLINUX                 / raw console ioctls (--new-session already
#                             blunts TIOCSTI; this is belt and braces)
#
# This is a deny-list, NOT an allow-list: everything unlisted stays allowed,
# so ordinary toolchains keep working. Denied calls get ENOSYS where calling
# code has fallbacks (io_uring users fall back to plain threads; glibc falls
# back from clone3 to clone — EPERM there would break threading) and EPERM
# elsewhere. Foreign-ABI binaries (e.g. i386 compat under an x86_64 kernel)
# are killed — the whole thread group (SECCOMP_RET_KILL_PROCESS): syscall
# numbers differ per ABI, so number-based filtering would be meaningless
# for them. x32 is the exception the arch check cannot catch (same
# AUDIT_ARCH_X86_64, bit 0x40000000 in the number) — it is killed
# explicitly on x86_64.

# Native syscall numbers; aarch64 and riscv64 share the asm-generic table.
# Hand-typed: tests/test_seccomp.py cross-checks every entry against kernel
# headers / scmp_sys_resolver / ausyscall — extend it when editing this.
SECCOMP_SYSCALLS = {
    "x86_64": {
        "ioctl": 16, "clone": 56, "socket": 41, "syslog": 103, "ptrace": 101,
        "personality": 135, "pivot_root": 155, "mount": 165, "chroot": 161,
        "umount2": 166, "quotactl": 179, "init_module": 175, "delete_module": 176,
        "kexec_load": 246, "add_key": 248, "request_key": 249, "keyctl": 250,
        "perf_event_open": 298, "fanotify_init": 300, "open_by_handle_at": 304,
        "name_to_handle_at": 303, "setns": 308, "vmsplice": 278,
        "process_vm_readv": 310, "process_vm_writev": 311, "kcmp": 312,
        "unshare": 272, "finit_module": 313, "kexec_file_load": 320,
        "bpf": 321, "userfaultfd": 323, "io_uring_setup": 425,
        "io_uring_enter": 426, "io_uring_register": 427, "open_tree": 428,
        "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
        "clone3": 435, "pidfd_getfd": 438, "mount_setattr": 442,
    },
    "aarch64": {
        "umount2": 39, "mount": 40, "pivot_root": 41, "ptrace": 117,
        "chroot": 51, "personality": 92, "unshare": 97, "kexec_load": 104,
        "init_module": 105, "delete_module": 106, "socket": 198,
        "clone": 220, "add_key": 217, "request_key": 218, "keyctl": 219,
        "ioctl": 29, "quotactl": 60, "vmsplice": 75, "syslog": 116,
        "perf_event_open": 241, "fanotify_init": 262, "name_to_handle_at": 264,
        "open_by_handle_at": 265,
        "process_vm_readv": 270, "process_vm_writev": 271, "kcmp": 272,
        "finit_module": 273, "setns": 268, "kexec_file_load": 294,
        "bpf": 280, "userfaultfd": 282, "io_uring_setup": 425,
        "io_uring_enter": 426, "io_uring_register": 427, "open_tree": 428,
        "move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432,
        "clone3": 435, "pidfd_getfd": 438, "mount_setattr": 442,
    },
}
SECCOMP_SYSCALLS["riscv64"] = SECCOMP_SYSCALLS["aarch64"]

# AUDIT_ARCH_* values of seccomp_data.arch for the native ABI.
SECCOMP_AUDIT_ARCH = {
    "x86_64": 0xC000003E,
    "aarch64": 0xC00000B7,
    "riscv64": 0xC00000F3,
}

SECCOMP_FAKE_MISSING = ("clone3", "io_uring_setup", "io_uring_enter", "io_uring_register")
SECCOMP_EPERM = (
    "bpf", "perf_event_open", "userfaultfd",
    "keyctl", "add_key", "request_key",
    "unshare", "setns", "ptrace", "process_vm_readv", "process_vm_writev",
    "kcmp", "pidfd_getfd", "personality", "chroot", "vmsplice",
    "mount", "umount2", "pivot_root", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module", "open_by_handle_at",
    "name_to_handle_at", "quotactl", "syslog", "fanotify_init",
    "open_tree", "move_mount", "fsopen", "fsconfig", "fsmount",
    "mount_setattr",
)

CLONE_NEWUSER = 0x10000000
TIOCSTI = 0x5412
TIOCLINUX = 0x541C

# Socket families the filter allows (identical values on every arch we
# support): AF_UNIX, AF_INET, AF_INET6, AF_NETLINK — the Flatpak set.
# Everything else (AF_VSOCK, AF_PACKET, ...) is refused: AF_VSOCK can bypass
# network-namespace isolation in VM guests on older kernels.
SOCKET_FAMILIES = (1, 2, 10, 16)

# cBPF machine constants (linux/filter.h) + seccomp return actions.
_BPF_LD_W_ABS = 0x20   # A = u32 at seccomp_data offset k
_BPF_JEQ_K = 0x15      # if A == k jump jt else jf
_BPF_JSET_K = 0x45     # if A & k  jump jt else jf
_BPF_RET_K = 0x06
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_KILL_THREAD = 0x00000000
# Kills the whole thread group, not just the calling thread (kernel >= 4.14;
# bwrap sandboxes require user namespaces anyway, so old kernels are moot).
_SECCOMP_RET_KILL_PROCESS = 0x80000000


def seccomp_machine(machine: str = "") -> str:
    """platform.machine() normalized to the SECCOMP_SYSCALLS keys."""
    machine = machine or platform.machine().lower()
    return {"amd64": "x86_64", "arm64": "aarch64"}.get(machine, machine)


def build_seccomp_bpf(machine: str = "") -> bytes | None:
    """Compile the deny-list into a cBPF program for prctl(PR_SET_SECCOMP).

    Returns None on unsupported architectures (the caller warns and runs
    without the filter rather than blocking the wrong numbers).
    """
    machine = seccomp_machine(machine)
    table = SECCOMP_SYSCALLS.get(machine)
    if table is None:
        return None

    insns: list[list] = []  # [code, k, jt_label_or_None, jf_label_or_None]

    def emit(code: int, k: int = 0, jt=None, jf=None) -> None:
        insns.append([code, k, jt, jf])

    # seccomp_data: { int nr; u32 arch; u64 ip; u64 args[6]; } (native LE)
    emit(_BPF_LD_W_ABS, 4)                       # arch
    emit(_BPF_JEQ_K, SECCOMP_AUDIT_ARCH[machine], None, "kill")
    emit(_BPF_LD_W_ABS, 0)                       # syscall nr
    if machine == "x86_64":
        # x32 shares AUDIT_ARCH_X86_64 but sets bit 0x40000000 in the
        # number, so the arch check does not catch it and the exact-number
        # rules below would silently miss it (fall through to ALLOW).
        # Kill it like any other foreign ABI.
        emit(_BPF_JSET_K, 0x40000000, "kill", None)
    for name in SECCOMP_FAKE_MISSING:
        emit(_BPF_JEQ_K, table[name], "enosys", None)
    for name in SECCOMP_EPERM:
        emit(_BPF_JEQ_K, table[name], "eperm", None)
    # Fall-through labels are positions in the instruction list; the tail
    # action blocks below are added to the same map.
    marks: dict[str, int] = {}
    # clone(): deny only CLONE_NEWUSER (bit 28, below 2^32 on every arch we
    # support, so the low flags word is enough); threads use clone freely.
    emit(_BPF_JEQ_K, table["clone"], None, "after_clone")
    emit(_BPF_LD_W_ABS, 16)                      # args[0] low word (flags)
    emit(_BPF_JSET_K, CLONE_NEWUSER, "eperm", None)
    emit(_BPF_LD_W_ABS, 0)                       # reload nr: A holds the flags
    marks["after_clone"] = len(insns)
    # ioctl(): TIOCSTI (fake tty input) / TIOCLINUX (raw console ioctls).
    # The kernel takes cmd as an unsigned int — the upper 32 bits of the
    # register are ignored — so only the low word is compared (Flatpak uses
    # MASKED_EQ 0xFFFFFFFF for the same reason). Requiring the high word to
    # be 0 here would let 0x1_0000_5412 through as TIOCSTI.
    emit(_BPF_JEQ_K, table["ioctl"], None, "after_ioctl")
    emit(_BPF_LD_W_ABS, 24)                      # args[1] low word (cmd is u32)
    emit(_BPF_JEQ_K, TIOCSTI, "eperm", None)
    emit(_BPF_JEQ_K, TIOCLINUX, "eperm", None)
    emit(_BPF_LD_W_ABS, 0)                       # reload nr: A holds the cmd
    marks["after_ioctl"] = len(insns)
    # socket(): allow only the usual families (SOCKET_FAMILIES; Flatpak's
    # set). AF_VSOCK notably reaches the host hypervisor in VM guests,
    # bypassing the network namespace on older kernels. socketpair() is not
    # restricted: a socket pair never connects anywhere.
    emit(_BPF_JEQ_K, table["socket"], None, "after_socket")
    emit(_BPF_LD_W_ABS, 16)                      # args[0] low word (domain)
    for fam in SOCKET_FAMILIES:
        emit(_BPF_JEQ_K, fam, "allow", None)
    emit(_BPF_RET_K, _SECCOMP_RET_ERRNO | errno.EPERM)
    # The default ALLOW comes directly after the last rule (fall-through
    # and skip targets must reach it, not the RET blocks below).
    marks["after_socket"] = len(insns)
    marks["allow"] = len(insns)
    emit(_BPF_RET_K, _SECCOMP_RET_ALLOW)
    # Action blocks for the deny rules and the arch-mismatch kill.
    for label, action in (
        ("enosys", _SECCOMP_RET_ERRNO | errno.ENOSYS),
        ("eperm", _SECCOMP_RET_ERRNO | errno.EPERM),
        ("kill", _SECCOMP_RET_KILL_PROCESS),
    ):
        marks[label] = len(insns)
        emit(_BPF_RET_K, action)

    out = bytearray()
    for i, (code, k, jt, jf) in enumerate(insns):
        def off(label, i=i):
            if label is None:
                return 0  # fall through to the next instruction
            delta = marks[label] - i - 1
            if not 0 <= delta <= 255:
                raise RuntimeError("seccomp: cBPF jump out of 8-bit range")
            return delta
        out += struct.pack("<HBBI", code, off(jt), off(jf), k)
    return bytes(out)


# bwrap itself installs the compiled filter (raw cBPF: the fd must contain
# nothing but sock_filter instructions, a multiple of 8 bytes — no length
# prefix; bwrap reads it at option-parse time and applies it as the very
# last step before exec'ing the payload, after PR_SET_NO_NEW_PRIVS, so
# unprivileged installation works and nothing inside the sandbox — not even
# its first instruction — runs unfiltered). --add-seccomp-fd is the
# current spelling (repeatable), --seccomp the old one (bwrap >= 0.4.1);
# both take the same wire format. There is deliberately NO in-sandbox
# fallback anymore: an in-sandbox helper ran after python3's site.py (user
# .pth files, usercustomize — a seccomp bypass via --home) and failed open
# when the sandbox had no python3. If bwrap cannot install the filter, the
# launcher dies (--no-seccomp is the explicit opt-out).
def parse_bwrap_caps(text: str) -> dict:
    """Parse `bwrap --help` output into the options this launcher relies on.
    Capability probing (not version parsing) so distro backports like
    bwrap 0.6.3 (--bind-fd backported from 0.10) are detected correctly."""
    def has(opt: str) -> bool:
        return re.search(rf"(?<![\w-]){re.escape(opt)}(?![\w-])", text) is not None

    return {
        # option to hand the filter to bwrap with, None = unsupported
        "seccomp": "--add-seccomp-fd" if has("--add-seccomp-fd") else
                   ("--seccomp" if has("--seccomp") else None),
        # >= 0.8: nested user namespaces die at the kernel level
        # (max_user_namespaces in a nested userns; --assert-... makes bwrap
        # verify it and die otherwise)
        "disable_userns": has("--disable-userns") and has("--assert-userns-disabled"),
        # >= 0.10 (or 0.6.3): TOCTOU-free binds via pinned O_PATH fds
        "bind_fd": has("--bind-fd") and has("--ro-bind-fd"),
    }


_BWRAP_CAPS: dict | None = None  # cache; main() sets opts._bwrap_caps


def bwrap_caps(binpath: str = "bwrap") -> dict:
    """Probe the real bwrap once; {} when the probe fails (callers then
    degrade loudly, and seccomp — which cannot degrade — fails closed)."""
    global _BWRAP_CAPS
    if _BWRAP_CAPS is not None:
        return _BWRAP_CAPS
    try:
        r = subprocess.run([binpath, "--help"], capture_output=True, text=True, timeout=10)
        _BWRAP_CAPS = parse_bwrap_caps(r.stdout + r.stderr) if r.returncode == 0 else {}
    except (OSError, subprocess.SubprocessError):
        _BWRAP_CAPS = {}
    return _BWRAP_CAPS


def seccomp_fd_args(caps: dict, verbose: bool) -> tuple[str, int]:
    """Compile the deny-list and hand it to bwrap through a pipe.

    Returns (bwrap_option, read_fd); the caller puts both into the bwrap
    argv, passes the fd to Popen and closes it after the spawn. DIES (never
    warns) when the filter cannot be installed — fail-closed by design;
    --no-seccomp is the explicit opt-out and never reaches here.
    """
    bpf = build_seccomp_bpf()
    if bpf is None:
        die(f"no seccomp syscall table for this machine ({platform.machine()}) — "
            "refusing to run without the filter (pass --no-seccomp to override)")
    opt = caps.get("seccomp")
    if opt is None:
        die("this bwrap supports neither --add-seccomp-fd nor --seccomp — cannot "
            "install the seccomp deny-list (upgrade bwrap >= 0.4.1, or pass "
            "--no-seccomp)")
    r, w = os.pipe()  # empty pipe, blocking fd: completes for << 64K; the
    try:              # loop is belt and braces for a much bigger filter
        view = memoryview(bpf)
        while view:
            view = view[os.write(w, view):]
    finally:
        os.close(w)
    if verbose:
        err(f"seccomp: deny-list handed to bwrap via {opt} ({len(bpf) // 8} filter instructions)")
    return opt, r


# ------------------------------------------------------------------ sandbox ---

INNER_PROXY = """\
socat TCP-LISTEN:1080,bind=127.0.0.1,fork,reuseaddr UNIX-CONNECT:/run/proxy.sock &
i=0
until socat -u /dev/null TCP:127.0.0.1:1080 >/dev/null 2>&1; do
    i=$((i+1)); [ "$i" -ge 50 ] && { echo "sbox.py: warning: in-sandbox proxy bridge not ready after 2.5s" >&2; break; }
    sleep 0.05
done
"""
INNER_DIRECT = ""

# Installed read-only at /etc/ssh/ssh_config inside the sandbox (proxied mode
# only). socat is guaranteed to exist in there — the bridge itself runs on it.
# The proxy resolves and allowlist-checks %h host-side, exactly like the
# env-var path for curl etc. Note ssh reads ~/.ssh/config first and the first
# obtained value wins, so a user config (e.g. --home) overrides per-option.
SSH_CLIENT_CONFIG = """\
# Generated by sbox.py: ssh has no native proxy support, so every host is
# routed through the sandbox's HTTP-CONNECT proxy (destination allowlist is
# enforced host-side). Disable per-invocation with -o ProxyCommand=none.
Host *
\tProxyCommand socat - PROXY:127.0.0.1:%h:%p,proxyport=1080
"""


def protected_paths(home: str) -> set[str]:
    """Paths a user-supplied bind (or the cwd bind) must never cover."""
    return set(SYSTEM_DIRS) | {os.path.realpath(home), "/run/user", f"/run/user/{os.getuid()}"}


# Well-known host control sockets: binding any of these hands the sandbox
# full control of the host (docker/containerd/CRI-O/podman/incus/LXD =
# root via the container daemon; D-Bus/systemd = arbitrary privileged
# services; libvirt = VMs; gnome-keyring/gpg-agent/1Password = your
# identity and ssh keys; snapd/tailscaled = service control; X11 = input
# injection) — a trivial escape, so they are refused exactly like protected
# paths even though they are only *children* of them. Matching uses the
# covers() ancestor test, so the parent dirs (e.g. -b /run/docker, -b
# ~/.gnupg) are refused too. realpath() collapses the /var/run -> /run
# symlink, so listing both spellings is belt and braces. This list will
# always lag reality — the shape rule below (anything under /run or any
# socket file) is what actually fail-closes it.
CONTROL_SOCKETS = {
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
    # Daemon directories as well: the bidirectional (ancestor/descendant)
    # match must also catch differently-NAMED sockets in a known control
    # dir (podman-run.sock, systemd/notify, ...) even via --bind-socket.
    "/run/podman", "/run/systemd", "/run/containerd", "/run/crio",
    "/run/dbus", "/run/libvirt", "/run/incus",
    "/tmp/.X11-unix", "/tmp/.ICE-unix", f"/tmp/tmux-{os.getuid()}",
    f"/run/user/{os.getuid()}/bus",
    f"/run/user/{os.getuid()}/gnupg/S.gpg-agent",
    f"/run/user/{os.getuid()}/pipewire-0",
    f"/run/user/{os.getuid()}/docker.sock",
    f"/run/user/{os.getuid()}/podman/podman.sock",
    f"/run/user/{os.getuid()}/systemd/private",
    f"/run/user/{os.getuid()}/keyring",      # gnome-keyring: secrets + ssh agent
    os.path.expanduser("~/.1password/agent.sock"),
    # Root-equivalent VM/container daemons that live in $HOME (Docker
    # Desktop, colima; lima's sockets move around ~/.lima/*/sock — the
    # _contains_socket scan catches those when ~/.lima is bound).
    os.path.expanduser("~/.docker/desktop/docker.sock"),
    os.path.expanduser("~/.docker/run/docker.sock"),
    os.path.expanduser("~/.colima/default/docker.sock"),
}


def _is_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


# Well-known $HOME persistence paths: a read-write bind covering any of
# these is host code execution at the next login/session — shell rc files
# run at shell startup, ~/.ssh/authorized_keys at the next sshd login,
# systemd user units and XDG autostart at session start, ~/.local/bin is
# on default PATHs, ~/.gitconfig aliases execute shell commands. Like
# CONTROL_SOCKETS this list will always lag reality, but unlike control
# sockets these binds are legitimate far more often, so they are WARNED
# about (naming the paths), never refused. Read-only binds are fine.
def persistence_paths(home: str) -> set[str]:
    h = os.path.realpath(home)
    cfg = os.environ.get("XDG_CONFIG_HOME") or os.path.join(h, ".config")
    data = os.environ.get("XDG_DATA_HOME") or os.path.join(h, ".local", "share")
    # XDG spec: relative values are ignored, i.e. resolved under $HOME.
    if not os.path.isabs(cfg):
        cfg = os.path.join(h, cfg)
    if not os.path.isabs(data):
        data = os.path.join(h, data)
    return {
        os.path.join(h, ".bashrc"), os.path.join(h, ".bash_profile"),
        os.path.join(h, ".bash_login"), os.path.join(h, ".profile"),
        os.path.join(h, ".zprofile"), os.path.join(h, ".zshrc"),
        os.path.join(h, ".zshenv"), os.path.join(h, ".zlogin"),
        os.path.join(h, ".kshrc"),
        os.path.join(h, ".emacs"), os.path.join(h, ".vimrc"),
        os.path.join(h, ".gitconfig"), os.path.join(cfg, "git", "config"),
        os.path.join(h, ".ssh", "authorized_keys"),
        os.path.join(h, ".local", "bin"),
        os.path.join(cfg, "fish", "config.fish"),
        os.path.join(cfg, "systemd", "user"),
        os.path.join(cfg, "autostart"),
        os.path.join(data, "systemd", "user"),
    }


def _path_ident(path: str) -> tuple[int, int] | None:
    """(st_dev, st_ino) for the validation-time inode a later O_PATH pin
    must still match, or None when the path does not exist (binds of
    missing paths fail in bwrap exactly as before)."""
    try:
        st = os.stat(path, follow_symlinks=False)
    except OSError:
        return None
    return (st.st_dev, st.st_ino)


# O_PATH availability guard (Linux 2.6.39+; every kernel that runs bwrap
# has it — this only keeps exotic interpreters honest).
_O_PATH = getattr(os, "O_PATH", 0)


def open_path_pinned(path: str, expect: tuple[int, int] | None = None,
                     max_hops: int = 40) -> int:
    """O_PATH|O_NOFOLLOW-open `path` with no TOCTOU window.

    os.path.realpath() validation + a later plain open() leaves a race: a
    concurrent sandbox sharing a writable directory can swap a component
    for a symlink in between, redirecting the bind (e.g. onto ~/.ssh).
    Instead every component is opened with openat(O_PATH|O_NOFOLLOW)
    relative to the pinned parent directory only; symlinks are resolved
    textually (absolute targets restart the walk at /, .. pops to the
    pinned parent — never through a re-resolved path) and bounded by
    max_hops. The final inode must match `expect` (captured at validation
    time by _path_ident): an attacker may move the validated object, but
    never substitute a different one. Raises OSError (ENOENT etc.) or
    ValueError on an inode mismatch; the caller owns the returned fd.
    """
    if not _O_PATH:
        raise OSError(errno.ENOSYS, "O_PATH unavailable", path)
    if not os.path.isabs(path):
        raise OSError(errno.EINVAL, "pinning needs an absolute path", path)
    remaining = path.split("/")
    stack = [os.open("/", _O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC)]
    hops = 0
    final = None
    try:
        while remaining:
            comp = remaining.pop(0)
            if comp in ("", "."):
                continue
            if comp == "..":
                if len(stack) > 1:
                    os.close(stack.pop())
                continue
            cur = os.open(comp, _O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
                          dir_fd=stack[-1])
            if stat.S_ISLNK(os.fstat(cur).st_mode):
                hops += 1
                if hops > max_hops:
                    raise OSError(errno.ELOOP, "too many symlink hops", path)
                # readlinkat against the pinned dir: the target read may
                # race a swap of this very name, but a mixed walk cannot
                # reach the validated inode of a DIFFERENT object — the
                # final expect check below is what makes substitution
                # impossible, this only keeps legit symlinks working.
                target = os.readlink(comp, dir_fd=stack[-1])
                os.close(cur)
                if target.startswith("/"):
                    for fd in stack[1:]:
                        os.close(fd)
                    del stack[1:]
                remaining = target.split("/") + remaining
                continue
            if remaining:
                stack.append(cur)
            else:
                final = cur
        if final is None:  # path was "/" (or only . / .. components)
            final = stack.pop()
        if expect is not None:
            st = os.fstat(final)
            if (st.st_dev, st.st_ino) != expect:
                raise ValueError(
                    f"{path}: pinned inode ({st.st_dev}, {st.st_ino}) != "
                    f"validated inode {expect} — the path was swapped "
                    "between validation and mount")
        return final
    except BaseException:
        if final is not None:
            try:
                os.close(final)
            except OSError:
                pass
        raise
    finally:
        for fd in stack:
            try:
                os.close(fd)
            except OSError:
                pass


class BindPinner:
    """Pins validated bind sources as O_PATH fds for bwrap --[ro-]bind-fd.

    bwrap >= 0.10 mounts the object the fd refers to and re-verifies the
    inode after mounting, so validation and mount can no longer diverge.
    With `enabled=False` (old bwrap, or capabilities unknown) every pin()
    is a no-op and callers emit the plain path-based flags instead.
    """

    def __init__(self, enabled: bool):
        self.enabled = enabled
        self.fds: dict[str, int] = {}

    def pin(self, path: str, expect: tuple[int, int] | None = None) -> int | None:
        """An O_PATH fd for `path` (cached; the sandbox only ever mounts
        each source once), or None when pinning is unavailable and the
        path form must be used. ENOENT maps to None as well: --bind-socket
        legitimately names runtime paths that do not exist yet, and the
        path form preserves bwrap's own not-found error. Anything else —
        including an inode mismatch — dies: an actively raced path must
        not silently fall back to the TOCTOU-vulnerable form."""
        if path in self.fds:
            return self.fds[path]
        if not self.enabled:
            return None
        try:
            fd = open_path_pinned(path, expect)
        except OSError as e:
            if e.errno == errno.ENOENT:
                return None
            die(f"cannot pin bind source {path} ({e.strerror or e}) — refusing")
        except ValueError as e:
            die(f"{e} — refusing")
        self.fds[path] = fd
        return fd

    def close(self) -> None:
        for fd in self.fds.values():
            try:
                os.close(fd)
            except OSError:
                pass
        self.fds.clear()


def _contains_socket(root: str, max_depth: int = 3, max_entries: int = 5000) -> str | None:
    """Bounded scan for a Unix socket inside root (depth- and entry-capped
    so huge trees stay cheap); returns the first socket path found, or None.
    Binding a directory that contains a socket usually means binding a
    control socket we simply do not know by name."""
    n = 0
    for dirpath, dirnames, filenames in os.walk(root):
        if dirpath[len(root):].count("/") >= max_depth:
            dirnames[:] = []
        for name in filenames:
            n += 1
            if n > max_entries:
                return None
            p = os.path.join(dirpath, name)
            if _is_socket(p):
                return p
    return None


def check_bind_paths(opts, home: str) -> list[tuple[str, str, tuple[int, int] | None]]:
    """Validate -b/--ro-bind before anything is started; return the resolved
    (flag, realpath, inode-identity) triples that build_bwrap mounts via
    O_PATH pins — validation and mount must use the same object, so symlink
    swaps and relative paths can't make bwrap mount something that was
    never checked (the identity survives until the --bind-fd mount).

    Whatever these paths really point at is handed to the sandbox, so refuse
    anything that covers a protected path (an ancestor of — or equal to —
    $HOME, a system dir, or the user runtime dir with its agent/pipewire/
    D-Bus sockets), covers a known host control socket (CONTROL_SOCKETS),
    or is socket-shaped by rule: any socket file, anything under /run,
    /var/run or $XDG_RUNTIME_DIR, or a directory that contains a Unix
    socket (bounded _contains_socket scan) — control-socket territory
    where a name list will always lag reality. --bind-socket PATH
    (mounted read-only) is the explicit per-path opt-in for the
    socket-shaped rules; known control sockets are never overridable. Children of protected
    paths are fine otherwise (e.g. -b ~/proj). -b $HOME itself is
    only acceptable together with --home (which binds it anyway); anything
    that merely covers $HOME, like /home, is still refused.
    """
    real_home = os.path.realpath(home)
    protected = sorted(protected_paths(home))
    explicit = {os.path.realpath(p) for p in getattr(opts, "bind_socket", [])}
    runtime_roots = {"/run", "/var/run"}
    xdg = os.environ.get("XDG_RUNTIME_DIR")
    if xdg:
        runtime_roots.add(os.path.realpath(xdg))
    binds: list[tuple[str, str]] = []
    for flag, paths in (("--bind", opts.bind), ("--ro-bind", opts.ro_bind),
                        # --bind-socket mounts read-only: connect() works
                        # through a ro-bind (as /run/proxy.sock proves), and
                        # rw would let the sandbox replace the socket file.
                        ("--ro-bind", opts.bind_socket)):
        for p in paths:
            rp = os.path.realpath(p)
            # -b $HOME together with --home re-binds what --home binds
            # anyway: exempt from ALL socket checks (but surface the risk
            # in the --home note below, so it is never silent).
            exempt = flag == "--bind" and opts.home and rp == real_home
            hits = [] if exempt else [q for q in protected if covers(rp, q)]
            if hits:
                die(f"{flag} {p} covers protected path(s): {', '.join(hits)}"
                    + ("; use --home to bind $HOME itself"
                       if flag == "--bind" and rp == real_home else ""))
            if not exempt:
                # Bidirectional: neither an ancestor of a listed socket
                # (-b /run/docker) nor a descendant of a listed directory
                # (--bind-socket .../keyring/ssh) may pass.
                sock_hits = sorted(s for s in CONTROL_SOCKETS
                                   if covers(rp, s) or covers(s, rp))
                if sock_hits:
                    die(f"{flag} {p} overlaps host control socket(s): "
                        f"{', '.join(sock_hits)} — that hands the sandbox "
                        "full control of the host (container runtime, D-Bus/"
                        "systemd, keyring, X11, ...); refusing")
                if rp not in explicit and (
                        any(covers(root, rp) for root in runtime_roots)
                        or _is_socket(rp)):
                    die(f"{flag} {p}: {rp} is a socket or lives under a runtime "
                        "dir — control-socket territory (a full host escape "
                        "waiting for a name we forgot); pass "
                        "--bind-socket to bind it anyway")
                if rp not in explicit and os.path.isdir(rp):
                    found = _contains_socket(rp)
                    if found:
                        die(f"{flag} {p}: contains a Unix socket ({found}) — "
                            "control-socket territory; pass --bind-socket to "
                            "bind it anyway")
            if flag == "--bind" and not exempt:
                # Persistence, not escape: code planted through these rw
                # binds executes AS THE HOST USER at next login/session
                # (the --home notes cover the exempt whole-home case).
                hits = sorted(q for q in persistence_paths(home) if covers(rp, q))
                if hits:
                    err(f"note: {flag} {p} covers host persistence path(s): "
                        + ", ".join(hits)
                        + " — sandboxed code can plant things there that run "
                        "as you at next login/session; prefer -r or a "
                        "narrower bind")
            binds.append((flag, rp, _path_ident(rp)))
    if opts.home:
        home_socks = sorted(s for s in CONTROL_SOCKETS
                            if covers(real_home, s) and os.path.exists(s))
        if home_socks:
            err("note: --home carries known control socket(s) inside $HOME: "
                + ", ".join(home_socks)
                + " — that is your full identity; see the --home notes")
    return binds


def agent_socket_path() -> str:
    """Resolve $SSH_AUTH_SOCK for --ssh-agent. Fails loudly: an explicit
    flag must never silently forward nothing (or bind a non-socket)."""
    raw = (os.environ.get("SSH_AUTH_SOCK") or "").strip()
    if not raw:
        die("--ssh-agent: SSH_AUTH_SOCK is not set — no agent to forward")
    path = os.path.realpath(raw)  # agents are often reached via a symlink
    try:
        st = os.stat(path)
    except OSError as e:
        die(f"--ssh-agent: agent socket {raw!r} is not usable: {e}")
    if not stat.S_ISSOCK(st.st_mode):
        die(f"--ssh-agent: SSH_AUTH_SOCK {raw!r} is not a Unix socket")
    return path


def build_bwrap(opts, sand: str, sock: str, home: str,
                user_binds: list[tuple[str, str, tuple[int, int] | None]],
                agent: str | None, ssh_cfg: str | None,
                pinner: BindPinner | None = None) -> tuple[list[str], str]:
    import pwd  # POSIX only; we require Linux anyway (bwrap)

    def mount_args(flag: str, src: str, dest: str,
                   ident: tuple[int, int] | None = None) -> list[str]:
        """One bind, TOCTOU-free where possible: with a pinner (bwrap
        >= 0.10) the validated source is handed over as an O_PATH fd
        (mount-by-inode, no re-resolution at mount time); without one
        this is the classic path-based flag. Used for sources another
        sandbox could race — user binds, the cwd mount, $HOME. System
        trees (/usr, /etc/ssl, ...), the 0700 $WORK dir and the runtime
        sockets below stay path-based on purpose: they are not writable
        by sandboxed processes, so there is nothing to race."""
        fd = pinner.pin(src, ident) if pinner is not None else None
        if fd is not None:
            return [flag + "-fd", str(fd), dest]
        return [flag, src, dest]

    uid = os.getuid()
    user = os.environ.get("USER") or pwd.getpwuid(uid).pw_name
    bw = [
        "--unshare-all",
        "--die-with-parent",
        "--new-session",
        # Run the payload as pid 1 instead of bwrap's own zombie-reaper
        # init: that init is NOT covered by our seccomp filter and is the
        # command's PARENT, so on Yama ptrace_scope=0 systems a filtered
        # process could write to /proc/1/mem and inject syscalls into it
        # (the ptrace-syscall ban does not cover /proc/<pid>/mem). Trade-
        # off: orphaned grandchildren are not reaped while pid 1 lives.
        "--as-pid-1",
        "--clearenv",
        "--setenv", "HOME", home,
        "--setenv", "USER", user,
        "--setenv", "TERM", os.environ.get("TERM") or "xterm-256color",
        "--setenv", "PATH", os.environ.get("PATH") or "/usr/local/bin:/usr/bin:/bin",
        "--setenv", "LANG", os.environ.get("LANG") or "C.UTF-8",
        "--proc", "/proc",
        "--dev", "/dev",
        "--bind", sand, "/tmp",
        "--ro-bind", "/usr", "/usr",
        "--ro-bind-try", "/lib", "/lib",
        "--ro-bind-try", "/lib64", "/lib64",
        "--ro-bind-try", "/bin", "/bin",
        "--ro-bind-try", "/sbin", "/sbin",
        # CA stores: Debian/Ubuntu (/etc/ssl), Fedora/RHEL (/etc/pki, where
        # /etc/ssl/certs is often a dangling symlink without this), misc.
        "--ro-bind-try", "/etc/ssl", "/etc/ssl",
        "--ro-bind-try", "/etc/pki", "/etc/pki",
        "--ro-bind-try", "/etc/ca-certificates", "/etc/ca-certificates",
        "--ro-bind-try", "/etc/hosts", "/etc/hosts",
        "--ro-bind-try", "/etc/localtime", "/etc/localtime",
        "--ro-bind-try", "/etc/passwd", "/etc/passwd",
        "--ro-bind-try", "/etc/group", "/etc/group",
        # Debian/Ubuntu: many /usr/bin entries (awk, editor, java, vi, at
        # times python3) are symlinks into /etc/alternatives, which dangle
        # without this; ld.so.cache matters if libs live outside the default
        # loader paths.
        "--ro-bind-try", "/etc/alternatives", "/etc/alternatives",
        "--ro-bind-try", "/etc/ld.so.cache", "/etc/ld.so.cache",
        "--perms", "0755", "--tmpfs", "/run",
    ]

    if not opts.net:
        bw += [
            "--setenv", "all_proxy", "socks5h://127.0.0.1:1080",
            "--setenv", "ALL_PROXY", "socks5h://127.0.0.1:1080",
            "--setenv", "http_proxy", "http://127.0.0.1:1080",
            "--setenv", "https_proxy", "http://127.0.0.1:1080",
            "--setenv", "HTTP_PROXY", "http://127.0.0.1:1080",
            "--setenv", "HTTPS_PROXY", "http://127.0.0.1:1080",
            "--setenv", "no_proxy", "localhost,127.0.0.1,::1",
            "--setenv", "NO_PROXY", "localhost,127.0.0.1,::1",
            "--ro-bind", sock, "/run/proxy.sock",
        ]
        if ssh_cfg:
            # Nothing else mounts /etc/ssh; bwrap creates the dest path.
            bw += ["--ro-bind", ssh_cfg, "/etc/ssh/ssh_config"]
        inner = INNER_PROXY
    else:
        # --share-net keeps the host network namespace (only valid together
        # with --unshare-all); resolv.conf makes DNS work. NOTE: this also
        # exposes host loopback services and abstract Unix sockets.
        bw += ["--share-net", "--ro-bind-try", "/etc/resolv.conf", "/etc/resolv.conf"]
        inner = INNER_DIRECT

    if opts.home:
        # NOTE: the identity must be of the RESOLVED path — $HOME itself is
        # often a symlink, and its lstat inode is the link's, never the
        # target's (a false "swapped" refusal otherwise).
        real_home_src = os.path.realpath(home)
        bw += mount_args("--bind", real_home_src, home, _path_ident(real_home_src))
    else:
        bw += ["--perms", "0700", "--tmpfs", home]

    if opts.gui:
        # X11 allows any client to log keys, capture the screen AND inject
        # input (XTEST/SendEvent) — i.e. type into your terminal: treat X11
        # passthrough as unsandboxed. Wayland is the preferred path. Keep
        # the sockets themselves read-only.
        xdg = os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{uid}"
        bw += ["--setenv", "XDG_RUNTIME_DIR", xdg, "--perms", "0700", "--dir", xdg]
        wl = os.environ.get("WAYLAND_DISPLAY")
        if wl:
            path = wl if wl.startswith("/") else os.path.join(xdg, wl)
            bw += ["--setenv", "WAYLAND_DISPLAY", wl, "--ro-bind-try", path, path]
        if os.environ.get("DISPLAY"):
            bw += ["--setenv", "DISPLAY", os.environ["DISPLAY"],
                   "--ro-bind-try", "/tmp/.X11-unix", "/tmp/.X11-unix"]
            for xauth in (os.environ.get("XAUTHORITY"), os.path.join(home, ".Xauthority")):
                if xauth and os.path.exists(xauth):
                    bw += ["--setenv", "XAUTHORITY", xauth, "--ro-bind-try", xauth, xauth]
                    break

    if agent:
        # One socket file, read-only — connect() works through a ro-bind
        # (same trick as /run/proxy.sock). Fixed path inside, because the
        # host path is usually under /run/user/<uid>, which stays hidden.
        bw += [
            "--ro-bind", agent, "/run/ssh-agent.sock",
            "--setenv", "SSH_AUTH_SOCK", "/run/ssh-agent.sock",
        ]

    # Current directory: bind it (rw unless --ro-cwd) unless it covers a
    # protected path (system dir, $HOME or an ancestor of it — a recursive
    # bind of e.g. /home would cover the tmpfs $HOME and expose the real
    # ~/.ssh etc.) or sits under a tmpfs $HOME. A cwd at or below an
    # explicitly bound path still exists inside the sandbox, so chdir works.
    # Children of /dev, /proc, /sys and /run (incl. XDG_RUNTIME_DIR) are not
    # auto-mounted either: `cd` alone should never hand over runtime state —
    # use an explicit -b for the rare legitimate case (e.g. -b /dev/dri).
    real_home = os.path.realpath(home)
    protected = sorted(protected_paths(home))
    runtime_roots = ("/dev", "/proc", "/sys", "/run")
    project = os.path.realpath(os.getcwd())
    bind = True
    if project == real_home or project.startswith(real_home + "/"):
        if not opts.home:
            err("note: cwd is inside $HOME and $HOME is a tmpfs — using /tmp instead (--home to bind)")
            bind = False
    else:
        hits = [q for q in protected if covers(project, q)]
        hits += [q for q in runtime_roots if covers(q, project)]
        if hits:
            err(f"note: cwd {project} overlaps protected path(s) {', '.join(sorted(set(hits)))} — not mounting it")
            bind = False

    # Emit the cwd bind BEFORE the user binds: a later bind shadows earlier
    # mounts at or below its target, so the automatic (rw by default) cwd
    # mount must come first for explicit -r/-b flags to win — `-r "$PWD"`
    # would otherwise silently end up read-write.
    if bind:
        bw += mount_args("--ro-bind" if opts.ro_cwd else "--bind", project, project,
                         _path_ident(project))

    for flag, rp, ident in user_binds:
        # mount exactly the validated (resolved) object, ideally by fd
        bw += mount_args(flag, rp, rp, ident)

    # bwrap applies --chdir after all mounts, wherever it sits in argv.
    user_bound = {rp for _, rp, _ in user_binds}
    if bind or any(covers(b, project) for b in user_bound):
        bw += ["--chdir", project]
    else:
        bw += ["--chdir", "/tmp"]

    # inner ends with a plain exec: bwrap installs the seccomp filter (when
    # enabled) as the very last step before exec'ing THIS script (see
    # run_sandbox assembling the argv), so the filter covers the shell,
    # the socat bridge AND the command from their first instruction. That
    # ordering is load-bearing: once sh execs the command, the command is
    # the bridge's parent, and Yama scope 1 lets a process ptrace (or
    # /proc/<pid>/mem-write) its own descendants — an unfiltered bridge
    # would be a syscall-injection escape hatch for everything the filter
    # denies. socat and sh use none of the denied calls; ptrace and
    # process_vm_* are denied outright as defense in depth.
    inner += 'exec "$@"\n'

    return bw, inner


def wait_for_socket(sock_path: str, proc: subprocess.Popen, timeout: float = 5.0) -> None:
    """Wait until the proxy is actually accepting connections. The socket
    file appears at bind() time, before listen(), so existence alone is not
    enough — poll with a real connect() to avoid an ECONNREFUSED race."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if os.path.exists(sock_path):
            probe = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                probe.connect(sock_path)
                return
            except OSError:
                pass  # bound but not listening yet
            finally:
                probe.close()
        if proc.poll() is not None:
            die("the proxy died at startup (see errors above)")
        time.sleep(0.02)
    die("the proxy did not come up")


def rm_tree_writable(path: str) -> None:
    # The sandbox may have created 0555 directories; make them removable.
    # lstat everywhere: /tmp inside the sandbox is attacker-controlled, and
    # a symlink like x -> ~/.ssh/config must never be chmod'ed through.
    for dirpath, dirnames, filenames in os.walk(path):
        for name in dirnames + filenames:
            p = os.path.join(dirpath, name)
            try:
                st = os.lstat(p)
                if not stat.S_ISLNK(st.st_mode):
                    os.chmod(p, st.st_mode | 0o700)
            except OSError:
                pass
    shutil.rmtree(path, ignore_errors=True)


def run_sandbox(opts, command: list[str], allows: list[dict], upstream: dict | None) -> int:
    # During startup there is nothing to forward signals to yet; die so the
    # finally below removes $WORK (proxy.json may hold upstream credentials).
    # Replaced by the forwarding handler once the sandbox is up. Installed
    # before $WORK exists so every startup signal is caught by these handlers.
    def early_signal(signum, _frame):
        raise SystemExit(128 + signum)

    for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
        signal.signal(sig, early_signal)

    work: str | None = None
    procs: list[subprocess.Popen] = []
    sandbox: subprocess.Popen | None = None
    proxy: subprocess.Popen | None = None
    pinner = BindPinner(enabled=False)  # O_PATH bind pins (opened below)
    seccomp_fd: int | None = None       # read end bwrap loads the filter from
    # --filter-output state (set up below, just before bwrap starts).
    master: int | None = None        # pty master: host-side, never sandboxed
    slave: int | None = None         # pty slave: bwrap's only stdio
    raw_stdin: int | None = None     # host tty fd we set raw (to restore)
    saved_termios = None
    tty_fd: int | None = None        # winsize source for SIGWINCH forwards
    stdin_fd: int | None = None      # host stdin forwarded into the master
    prev_winch = None                # previous SIGWINCH handler
    winch = {"hit": False}           # mutable: the signal handler flips it
    sanitizer: OutputSanitizer | None = None
    try:
        # mkdtemp inside the try: early_signal raises SystemExit, and a
        # signal landing anywhere between mkdtemp() and the setup below must
        # still unwind through the finally instead of leaking $WORK on the
        # host (os.mkdir(sand) etc. are such windows).
        work = tempfile.mkdtemp(prefix="sbox.", dir="/tmp")
        sand = os.path.join(work, "tmp")
        sock = os.path.join(work, "net.sock")
        cfg_path = os.path.join(work, "proxy.json")
        os.mkdir(sand)
        os.chmod(work, 0o700)
        # Validate user binds (resolved paths) before starting anything.
        user_binds = check_bind_paths(opts, os.environ["HOME"])
        agent = agent_socket_path() if opts.ssh_agent else None
        ssh_cfg = None
        # bwrap capabilities (probed once in main(); deliberately NOT
        # probed here — a test shim on $PATH must not be asked). Missing
        # means unknown: only the conservative path-based forms are used,
        # and seccomp (which cannot degrade) fails closed in that case.
        caps = getattr(opts, "_bwrap_caps", None) or {}
        # TOCTOU-free binds: pin every source another sandbox could race
        # (user binds, the cwd mount, $HOME) as O_PATH fds for bwrap
        # --[ro-]bind-fd. Old bwrap keeps the path-based flags instead —
        # loud, not silent (a pinned bind is strictly stronger).
        pinner.enabled = bool(caps.get("bind_fd"))
        if user_binds and not pinner.enabled:
            err("note: this bwrap lacks --bind-fd — binds re-resolve their "
                "source path at mount time (TOCTOU window if another sandbox "
                "can write a parent dir); bwrap >= 0.10 mounts by pinned fd")
        hardening: list[str] = []
        if not opts.no_seccomp:
            # Fail-closed: seccomp_fd_args dies when bwrap cannot install
            # the filter (--no-seccomp is the explicit opt-out).
            opt, seccomp_fd = seccomp_fd_args(caps, opts.verbose)
            hardening += [opt, str(seccomp_fd)]
        if caps.get("disable_userns"):
            # Kernel-level: bwrap sets max_user_namespaces=1 in a nested
            # user namespace, consumes the one slot itself, and (with
            # --assert-userns-disabled) refuses to run unless nesting is
            # really dead — belt and braces under the unshare/setns deny
            # rules, immune to hand-typed-number mistakes. The explicit
            # --unshare-user is required: --unshare-all only sets
            # --unshare-user-try, and bwrap checks the combination before
            # its non-root "just DWIM" fallback gets a chance to run.
            hardening += ["--unshare-user",
                          "--disable-userns", "--assert-userns-disabled"]
            if opts.verbose:
                err("userns: nested user namespaces disabled at the kernel level "
                    "(--disable-userns --assert-userns-disabled)")

        if not opts.net:
            # Created 0600 from the start — it may carry upstream credentials.
            fd = os.open(cfg_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump({"allows": allows, "upstream": upstream, "verbose": opts.verbose}, fh)
            proxy = subprocess.Popen(
                [sys.executable, os.path.abspath(__file__), "--_proxy", sock, cfg_path, str(os.getpid())],
                stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,  # logs go to stderr
                start_new_session=True,  # keep terminal Ctrl-C out of the proxy's way
            )
            procs.append(proxy)
            wait_for_socket(sock, proxy)
            # The proxy has read its config by now (it accepted a connection);
            # drop the file so a SIGKILLed launcher cannot leave credentials
            # behind in /tmp.
            try:
                os.unlink(cfg_path)
            except OSError:
                pass
            self_test(sock, allows)
            # No secrets here (the proxy does the allowlist checks), so this
            # one is world-readable and merely deleted with $WORK at exit.
            ssh_cfg = os.path.join(work, "ssh_config")
            with open(ssh_cfg, "w", encoding="utf-8") as fh:
                fh.write(SSH_CLIENT_CONFIG)

        bw, inner = build_bwrap(opts, sand, sock, os.environ["HOME"], user_binds, agent, ssh_cfg,
                                pinner)
        if opts.filter_output:
            # Fail closed: without a pty there is no host-side filtering,
            # so refuse to run rather than pass output through raw.
            try:
                master, slave = pty.openpty()
            except OSError as e:
                die(f"--filter-output: cannot allocate a pty ({e}) — refusing to run unfiltered")
            sanitizer = OutputSanitizer(strict_cr=getattr(opts, "strict_crlf", False))
            tty_fd = _host_tty_fd()
            if tty_fd is not None:
                _copy_winsize(tty_fd, master)  # initial size for the pair
            raw_stdin, saved_termios = _enter_raw_mode()
            stdin_fd = raw_stdin if raw_stdin is not None else _forwardable_stdin_fd()
            if raw_stdin is None and stdin_fd is not None:
                # Piped/closed stdin: no interactive echo through the pty
                # (the slave echoes by default — script(1) behavior — which
                # would duplicate piped data in the output).
                try:
                    attrs = termios.tcgetattr(slave)
                    attrs[3] &= ~termios.ECHO
                    termios.tcsetattr(slave, termios.TCSANOW, attrs)
                except (OSError, termios.error):
                    pass

        # bwrap installs the seccomp filter (hardening, above) as the very
        # last step before exec'ing /bin/sh, so the shell, the socat bridge
        # and the command inherit it from their first instruction; --seccomp
        # fds and pin fds travel via pass_fds (nothing terminal-shaped ever
        # enters bwrap — close_fds stays on for everything else).
        argv = ["bwrap"] + hardening + bw + ["--"]
        argv += ["/bin/sh", "-c", inner, "sbox-sh"] + command
        pass_fds = tuple(([seccomp_fd] if seccomp_fd is not None else [])
                         + list(pinner.fds.values()))
        if opts.filter_output:
            # The sandbox's ONLY terminal is the pty slave: fds 0/1/2 are
            # it, and close_fds (the Popen default) hands over nothing
            # else — the host's real terminal fd never enters bwrap. The
            # master stays host-side and feeds the sanitizer.
            sandbox = subprocess.Popen(argv, stdin=slave, stdout=slave, stderr=slave,
                                       pass_fds=pass_fds)
            os.close(slave)  # else the host holds EOF away from us
            slave = None
            # Non-blocking master: the pump must survive a full pty
            # buffer (a sandbox that stopped reading stdin) without
            # freezing the output direction.
            fcntl.fcntl(master, fcntl.F_SETFL,
                        fcntl.fcntl(master, fcntl.F_GETFL) | os.O_NONBLOCK)
        else:
            sandbox = subprocess.Popen(argv, pass_fds=pass_fds)
        # bwrap has inherited everything it needs; our copies may go.
        if seccomp_fd is not None:
            os.close(seccomp_fd)
            seccomp_fd = None
        pinner.close()
        procs.append(sandbox)

        seen_signals: set[int] = set()

        def forward(signum, _frame):
            # Reality check: bwrap does NOT relay signals. SIGINT/SIGTERM
            # to it kill the bwrap parent outright, and --die-with-parent's
            # PDEATHSIG then SIGKILLs the sandbox payload — so Ctrl-C has
            # always been a hard kill and the sandboxed command never sees
            # a catchable signal (a --info-fd child-pid relay would be
            # needed for graceful shutdown). The escalation below is only
            # belt and braces for the window where bwrap has not died yet;
            # --die-with-parent covers a SIGKILL of the launcher itself.
            escalate = signum in seen_signals
            seen_signals.add(signum)
            if sandbox is None or sandbox.poll() is not None:
                return
            try:
                if escalate:
                    sandbox.kill()
                else:
                    sandbox.send_signal(signum)
            except ProcessLookupError:
                pass

        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, forward)

        # --filter-output: forward terminal resizes while the pump runs.
        if opts.filter_output:
            def on_winch(_signum, _frame):
                winch["hit"] = True
            prev_winch = signal.signal(signal.SIGWINCH, on_winch)

        pending = bytearray()   # stdin bytes the sandbox has not read yet
        master_eof = False
        stdin_eof = False

        # Supervisor: if the proxy dies, tear the sandbox down (and vice versa).
        while sandbox.poll() is None:
            if proxy is not None and proxy.poll() is not None:
                err("the network proxy exited unexpectedly — shutting the sandbox down")
                sandbox.terminate()
                try:
                    sandbox.wait(5)
                except subprocess.TimeoutExpired:
                    sandbox.kill()
                    sandbox.wait()
                return 1
            if sanitizer is None:
                time.sleep(0.1)
                continue
            # One pump round (select timeout = the old poll interval):
            # master -> filtered stdout, host stdin -> master, resizes.
            if winch["hit"]:
                winch["hit"] = False
                if tty_fd is not None:
                    _copy_winsize(tty_fd, master)
            fds = [] if master_eof else [master]
            if stdin_fd is not None and not stdin_eof:
                fds.append(stdin_fd)
            if not fds:
                time.sleep(0.1)
                continue
            try:
                ready, _, _ = select.select(fds, [], [], 0.1)
            except OSError:
                continue
            if master in ready:
                data = _read_maybe(master)
                if data == b"":
                    master_eof = True  # every slave fd closed: EOF
                elif data:
                    _emit_filtered(sanitizer.feed(data))
            if stdin_fd is not None and not stdin_eof and stdin_fd in ready:
                idata = _read_maybe(stdin_fd, 4096)
                if idata == b"":
                    # Host stdin closed. A pty has no EOF to inherit, so
                    # deliver the line discipline's VEOF (^D) instead —
                    # twice: once to flush a pending partial line, once
                    # to signal EOF to the reader.
                    stdin_eof = True
                    pending += b"\x04\x04"
                elif idata and len(pending) < MAX_PENDING_INPUT:
                    pending += idata  # past the cap: input is dropped
            if not master_eof and pending:
                try:
                    n = os.write(master, bytes(pending))
                    del pending[:n]
                except (BlockingIOError, InterruptedError):
                    pass  # pty buffer full: retry after the next round
                except OSError:
                    pending.clear()
        if sanitizer is not None and not master_eof:
            _drain_master(master, sanitizer)
        rc = sandbox.returncode
        if rc is None:
            rc = 1
        elif rc < 0:  # killed by a signal: report the conventional 128+signum
            rc = 128 - rc
        return rc
    finally:
        # A second Ctrl-C while cleaning up must not abort the cleanup
        # (a skipped rm_tree_writable would leave proxy.json behind).
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, signal.SIG_IGN)
        # Restore the host terminal FIRST: the teardown below can block
        # for seconds, and a raw terminal is unusable meanwhile.
        global _raw_term
        if raw_stdin is not None and saved_termios is not None:
            _restore_termios(raw_stdin, saved_termios)
        _raw_term = False
        if prev_winch is not None:
            signal.signal(signal.SIGWINCH, prev_winch or signal.SIG_DFL)
        for fd in (master, slave):
            if fd is not None:
                try:
                    os.close(fd)
                except OSError:
                    pass
        if seccomp_fd is not None:  # bwrap was never spawned (or died early)
            try:
                os.close(seccomp_fd)
            except OSError:
                pass
        pinner.close()
        for p in procs:
            if p.poll() is None:
                p.terminate()
        for p in procs:
            try:
                p.wait(3)
            except subprocess.TimeoutExpired:
                p.kill()
                p.wait()
        if work:
            rm_tree_writable(work)


# ---------------------------------------------------------------------- cli ---

OPTS_WITH_VALUE = {
    "-a", "--allow", "-A", "--allow-file", "-b", "--bind", "-r", "--ro-bind",
    "--bind-socket", "--upstream", "--_proxy",
}


def split_argv(argv: list[str]) -> tuple[list[str], list[str]]:
    """Split argv at the first positional: everything after it belongs to the
    sandboxed command (so `sbox.py -- cmd -v` works), like the shell version."""
    i = 0
    while i < len(argv):
        tok = argv[i]
        if tok == "--":
            return argv[:i], argv[i + 1:]
        if tok.startswith("-") and tok != "-":
            # "--allow x" consumes two tokens; "--allow=x" (or a flag) one.
            i += 2 if "=" not in tok and tok in OPTS_WITH_VALUE else 1
            continue
        return argv[:i], argv[i:]
    return argv, []


def parse_cli(argv: list[str]):
    pre, command = split_argv(argv)
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Run COMMAND in a bubblewrap sandbox with an allowlisted network.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False,  # split_argv only knows full option names
        epilog="""\
By default the sandbox has no network except a SOCKS5 *and* HTTP-CONNECT
proxy (auto-detected) at 127.0.0.1:1080 — http_proxy/https_proxy/all_proxy
are pre-set. https:// always goes through CONNECT; plain http:// URLs are
forwarded (absolute-form). Destinations not on the allowlist are denied
BEFORE any DNS lookup happens. Hostnames are resolved host-side; answers in
private, loopback, link-local or CGNAT ranges are rejected, so allowed names
cannot reach host/LAN services (explicit -a IP/CIDR entries bypass that
guard; effectively catch-all networks such as 0.0.0.0/1 are refused).
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
    /var/run or $XDG_RUNTIME_DIR — each is a trivial full escape.
    --bind-socket PATH is the explicit opt-in when you really mean it.
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
    per-option; `ssh -o ProxyCommand=none` opts out (and usually fails,
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
    an explicit -b "$PWD"/-r "$PWD" to have it), and cwds covering
    protected paths (/etc, /usr, /run, ...) are never auto-mounted either.
  - Explicit -b/-r binds overlay the automatic cwd mount when they cover
    it: -r "$PWD" from inside the directory gives a read-only cwd, and
    likewise -b over --ro-cwd gives read-write (the explicit flag wins).
    Read-write binds covering $HOME persistence paths (shell rc files,
    ~/.ssh/authorized_keys, systemd user units, XDG autostart,
    ~/.local/bin) are warned about: each means host code execution at the
    next login/session. Validated bind sources are handed to bwrap
    (>= 0.10) as pinned fds, so a concurrent sandbox cannot swap a path
    component between check and mount.
  - The sandbox runs in a new session (TIOCSTI protection): Ctrl-C reaches
    sbox.py, which then tears the whole sandbox down — a hard kill: bwrap
    does not relay signals, so the command itself never sees a catchable
    SIGINT (graceful shutdown inside the sandbox is not supported).
  - Seccomp deny-list: io_uring_*, bpf, perf_event_open, userfaultfd,
    keyring, namespace (unshare/setns/clone3/clone-with-CLONE_NEWUSER),
    admin (mount/pivot_root/chroot/kexec/module loading/open_by_handle_at/
    name_to_handle_at/quotactl/syslog and the new mount API fsopen/fsmount/
    move_mount/...), process-inspection/injection (ptrace, process_vm_*/
    kcmp/pidfd_getfd/personality, vmsplice), fanotify_init and
    ioctl(TIOCSTI/TIOCLINUX) are refused inside the sandbox; socket() is
    limited to AF_UNIX/AF_INET/AF_INET6/AF_NETLINK (AF_VSOCK bypasses
    netns isolation in VM guests on older kernels) — ENOSYS where runtimes
    have fallbacks, EPERM otherwise; foreign-ABI binaries (e.g. 32-bit
    compat, x32) are killed. bwrap itself installs the filter right before
    exec'ing the payload (no python3 needed inside the sandbox), so
    everything inside is covered from the first process (the socat bridge
    included; the payload runs as pid 1, so no unfiltered bwrap reaper
    init remains). bwrap >= 0.8 additionally gets --disable-userns:
    nested user namespaces die at the kernel level, not just by syscall
    number. FAILS CLOSED: without seccomp support (bwrap < 0.4.1) or on an
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
    and bidi/zero-width characters are dropped. WITHOUT it, raw sandbox
    bytes reach your terminal unchanged — use it for untrusted work. The
    host tty goes raw (stdin and SIGWINCH forwarded, termios restored on
    exit). --strict-crlf (implies --filter-output) additionally drops \r
    not followed by \n: a bare \r lets payload output visually overwrite
    the current line after you read it (progress bars break). Known
    limits: Ctrl-C reaches the sandbox as a byte — a command that never
    reads stdin cannot be interrupted from the keyboard (kill sbox.py
    from another shell); hidden text is not prevented beyond SGR 8
    conceal (matching fg/bg colors hide text just as well).

Examples:
  sbox.py -a pypi.org -a files.pythonhosted.org -- pip install requests
  sbox.py -a github.com -- git clone https://github.com/torvalds/linux
  sbox.py -a example.com -v -- curl -sI https://example.com
  sbox.py -a example.com --filter-output -- curl -s https://example.com
  sbox.py --ssh-agent -a github.com -- git clone git@github.com:me/repo.git
""",
    )
    parser.add_argument("-a", "--allow", action="append", default=[], metavar="HOST",
                        help="Allow HOST or any subdomain (suffix match on a dot boundary); "
                             "IP/CIDR entries match literal IP destinations; optional :port. Repeatable.")
    parser.add_argument("-A", "--allow-file", action="append", default=[], metavar="FILE",
                        help="File with allow entries (one per line, '#' comments). Repeatable.")
    parser.add_argument("-b", "--bind", action="append", default=[], metavar="PATH",
                        help="Bind PATH read-write at the same location. Repeatable.")
    parser.add_argument("-r", "--ro-bind", action="append", default=[], metavar="PATH",
                        help="Bind PATH read-only at the same location. Repeatable.")
    parser.add_argument("--bind-socket", action="append", default=[], metavar="PATH",
                        help="Bind PATH even though it is a socket or lives under /run, /var/run or "
                             "$XDG_RUNTIME_DIR (refused by default: control sockets there are full "
                             "host escapes). Explicit per-path opt-in; repeatable. Known control "
                             "sockets and protected paths are still refused.")
    parser.add_argument("--ro-cwd", action="store_true", help="Mount the current directory read-only (default: rw).")
    parser.add_argument("--home", action="store_true", help="Bind the real $HOME (default: private tmpfs home).")
    parser.add_argument("--gui", action="store_true",
                        help="Pass through Wayland/X11 sockets. X11 is effectively an escape: clients can "
                             "log keys, capture the screen and inject input (XTEST) — treat it as unsandboxed.")
    parser.add_argument("--ssh-agent", action="store_true",
                        help="Forward the host SSH agent socket ($SSH_AUTH_SOCK) into the sandbox, read-only, "
                             "at /run/ssh-agent.sock. Anything in the sandbox can then sign with every key "
                             "loaded in the agent, and the agent protocol also lets it remove identities or "
                             "lock the agent (ssh-add -D/-x) — prefer a dedicated agent (ssh-add -c/-h) "
                             "for untrusted code.")
    parser.add_argument(
        "--filter-output",
        action="store_true",
        help="Sanitize stdout/stderr on the host via a host-side PTY filter. "
             "Strips dangerous ANSI escape sequences (OSC 52 clipboard writes, "
             "terminal queries, invisible text, cursor manipulations) while preserving "
             "standard text and safe SGR colors. Recommended for untrusted work; "
             "without it raw sandbox bytes reach your terminal unchanged."
    )
    parser.add_argument(
        "--strict-crlf",
        action="store_true",
        help="With --filter-output (implied): additionally drop \\r not immediately followed "
             "by \\n — a bare \\r lets sandbox output visually overwrite the current line "
             "after you read it. Breaks progress bars and \\r-based redraw."
    )
    parser.add_argument("--upstream", metavar="URL",
                        help="Egress through an upstream proxy: http://, https://, socks5://, socks5h:// "
                             "(userinfo supported). Default: $SBOX_UPSTREAM, else $https_proxy/$HTTPS_PROXY. "
                             "Pass an empty string to force direct egress.")
    parser.add_argument("--upstream-insecure", action="store_true",
                        help="Do not verify the upstream's TLS certificate (https:// upstreams).")
    parser.add_argument("--net", action="store_true",
                        help="Share the host network namespace: direct egress, DNS via the host resolver, "
                             "no proxy/allowlist (-a/-A/--upstream are ignored).")
    parser.add_argument("--no-seccomp", action="store_true",
                        help="Do not install the seccomp deny-list (otherwise io_uring_*, bpf, "
                             "perf_event_open, userfaultfd, keyring, unshare/setns/clone3/CLONE_NEWUSER, "
                             "mount/kexec/module-loading, ptrace/process_vm_* and friends are blocked with "
                             "ENOSYS/EPERM inside the sandbox). Note the launcher FAILS CLOSED without it: "
                             "when the filter cannot be installed (bwrap < 0.4.1, unsupported architecture) "
                             "it refuses to run instead of running unfiltered.")
    parser.add_argument("-v", "--verbose", action="store_true", help="Log allow/deny decisions to stderr.")
    parser.add_argument("--shell", action="store_true", help="Run an interactive shell ($SHELL if available).")
    parser.add_argument("--_proxy", nargs=3, metavar=("SOCK", "CFG", "PPID"), help=argparse.SUPPRESS)
    opts = parser.parse_args(pre)
    return parser, opts, command


def main(argv: list[str]) -> int:
    if argv[:1] == ["--_proxy"]:
        if len(argv) != 4:
            die("internal error: --_proxy needs SOCK CFG PPID")
        return proxy_main(argv[1], argv[2], int(argv[3]))
    parser, opts, command = parse_cli(argv)
    if opts._proxy:
        return proxy_main(*opts._proxy)
    if opts.strict_crlf:
        opts.filter_output = True  # --strict-crlf is a --filter-output mode

    if not shutil.which("bwrap"):
        die("missing dependency: bwrap (needed on the host)")
    # Probe bwrap's capabilities ONCE here (never lazily inside run_sandbox:
    # a test shim on $PATH would not survive `bwrap --help`). opts carries
    # the result; run_sandbox reads it via getattr with a conservative
    # default for direct/unit-test callers.
    opts._bwrap_caps = bwrap_caps()
    if not opts._bwrap_caps and not opts.no_seccomp:
        # seccomp_fd_args would die with the dedicated message; say why the
        # probe failed first when the binary is otherwise fine.
        err("warning: cannot determine this bwrap's capabilities (bwrap --help failed)")
    if not opts.net and not shutil.which("socat"):
        die("missing dependency: socat (needed on the host for the in-sandbox bridge)")
    if "HOME" not in os.environ:
        die("HOME is not set")

    if opts.shell and command:
        parser.error("--shell takes no command")
    if opts.shell:
        shell = os.environ.get("SHELL") or "/bin/bash"
        home = os.environ["HOME"]
        usable = shell.startswith(("/usr/", "/bin/")) or (opts.home and shell.startswith(home + "/"))
        if not usable or not os.path.isfile(shell):
            shell = "/bin/bash" if os.path.isfile("/bin/bash") else "/bin/sh"
            err(f"note: $SHELL is not available inside the sandbox — falling back to {shell}")
        command = [shell]
    if not command:
        parser.error("no command given (or use --shell)")

    if opts.net and (opts.allow or opts.allow_file or opts.upstream is not None):
        err("warning: --net shares the host network directly; -a/-A/--upstream are ignored")

    try:
        allows = load_allows(opts.allow, opts.allow_file)
        if not opts.net and not allows:
            err("warning: no --allow entries — ALL outbound connections will be denied")

        if opts.upstream is None:
            raw = os.environ.get("SBOX_UPSTREAM") or os.environ.get("https_proxy") or os.environ.get("HTTPS_PROXY") or ""
        else:
            raw = opts.upstream
        upstream = parse_upstream(raw, opts.upstream_insecure or bool(os.environ.get("SBOX_UPSTREAM_INSECURE")))

        return run_sandbox(opts, command, allows, upstream)
    except KeyboardInterrupt:
        # Covers the pre-sandbox window (allow-file reads can block, e.g.
        # -A on a FIFO) plus the few instructions at run_sandbox entry
        # before it installs early_signal/forward — from then on SIGINT is
        # handled there and never surfaces as KeyboardInterrupt.
        return 130


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
