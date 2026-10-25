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

  - Seccomp hardening on top of the namespaces: a deny-list filter is
    installed at sandbox startup — the helper is the first process inside
    (after bwrap is done, so the filter cannot break bwrap's own namespace
    setup), and the shell, the socat bridge, the command and all descendants
    inherit it. The payload also runs as pid 1 (--as-pid-1), so there is no
    unfiltered bwrap reaper init inside the sandbox: on Yama
    ptrace_scope=0 systems that parent could otherwise be /proc/1/mem-
    injected, which the ptrace-syscall ban cannot stop. The filter blocks
    kernel surface namespaces cannot hide — io_uring_*, bpf,
    perf_event_open, userfaultfd, the (non-namespaced) kernel keyring,
    nested user namespaces (unshare/setns/clone3/clone-with-CLONE_NEWUSER),
    admin ops (mount, umount2, pivot_root, chroot, kexec, module loading,
    open_by_handle_at and the new mount API: fsopen/fsconfig/fsmount/
    move_mount/open_tree/mount_setattr), process-injection APIs (ptrace,
    process_vm_readv/writev, kcmp, pidfd_getfd, personality) and ioctl
    TIOCSTI/TIOCLINUX; socket() is limited to AF_UNIX/AF_INET/AF_INET6/
    AF_NETLINK (AF_VSOCK bypasses netns isolation in VM guests on older
    kernels). Denied calls return ENOSYS where runtimes have
    fallbacks (io_uring users, glibc clone3) and EPERM otherwise;
    foreign-ABI binaries (e.g. 32-bit compat, x32) are killed, whole
    thread group included.
    After installing the filter, a fail-closed self-probe requires
    unshare(0) to be denied (EPERM): a wrong number in the hand-typed
    syscall tables would otherwise block the wrong syscall silently. The
    tables are cross-checked against kernel headers by tests/test_seccomp.py.
    --no-seccomp opts out; without python3 inside the sandbox the filter is
    skipped with a loud warning, which --require-seccomp turns fatal.

  - --net skips all of the above: bwrap then shares the host network
    namespace (--unshare-all --share-net), /etc/resolv.conf is mounted, and
    no proxy is started (direct egress; the allowlist is NOT enforced, and
    host loopback services and abstract Unix sockets — D-Bus, X11, ... —
    become reachable; only use it for trusted work).
  - Lifecycle: one component dies -> everything dies (supervisor loop,
    --die-with-parent on bwrap, PR_SET_PDEATHSIG on the proxy; a SIGKILLed
    launcher therefore still takes the proxy with it).

Dependencies: bwrap, socat and python3 >= 3.8 (stdlib only). --net mode needs
bwrap only.

Known limits (design trade-offs, not bugs):
  - -b/--ro-bind paths are refused when they cover a protected path
    (system dirs, $HOME, /run/user/<uid>) or are socket-shaped: a known
    host control socket (CONTROL_SOCKETS: docker/containerd, D-Bus,
    systemd, libvirt, X11, keyring, gpg-agent, ...) or, by rule, any
    socket file and anything under /run, /var/run or $XDG_RUNTIME_DIR
    (--bind-socket PATH opts back in per path — the list of names would
    always lag reality, the shape rule fail-closes it). Anything else you
    bind — the launcher's /tmp/sbox.* work dir, which holds proxy.json and
    any upstream credentials, included — is handed over as requested.
  - --as-pid-1 makes the command pid 1 of the sandbox: long-lived commands
    that spawn and abandon children accumulate zombies (nothing reaps
    them; a shell as pid 1 reaps via waitpid(-1)), and signals sent to
    pid 1 from inside the sandbox are ignored unless the command handles
    them (pid-namespace init semantics). External teardown (SIGTERM to
    sbox.py, --die-with-parent) works exactly as before.
  - No resource limits (CPU/memory/PID/fds) inside the sandbox; the
    boundary is bwrap's namespaces plus the seccomp deny-list above. That
    deny-list is best-effort hardening: unsupported architectures or a
    sandbox without python3 disable it (with a warning — fail-open;
    --require-seccomp makes it fatal, consider it in your alias), and
    --no-seccomp opts out entirely.
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

Installed to ~/.local/bin via config/sync.py (Directory("bin", ..., "~/.local/bin")).
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import ctypes
import errno
import ipaddress
import json
import os
import platform
import re
import shutil
import signal
import socket
import ssl
import stat
import struct
import subprocess
import sys
import tempfile
import time
import traceback
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


def err(msg: str) -> None:
    print(f"{PROG}: {msg}", file=sys.stderr, flush=True)


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


# ---------------------------------------------------------------- seccomp ---
# A deny-list cBPF program installed INSIDE the sandbox (by SECCOMP_HELPER
# below) right before the command runs — after bwrap is done, so the filter
# never interferes with bwrap's own namespace setup. Kernel attack surface
# that namespaces alone cannot hide; the same list Flatpak/Chrome disable
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
#   open_by_handle_at
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
        "ioctl": 16, "clone": 56, "socket": 41, "ptrace": 101,
        "personality": 135, "pivot_root": 155, "mount": 165, "chroot": 161,
        "umount2": 166, "init_module": 175, "delete_module": 176,
        "kexec_load": 246, "add_key": 248, "request_key": 249, "keyctl": 250,
        "perf_event_open": 298, "open_by_handle_at": 304, "setns": 308,
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
        "ioctl": 29, "perf_event_open": 241, "open_by_handle_at": 265,
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
    "kcmp", "pidfd_getfd", "personality", "chroot",
    "mount", "umount2", "pivot_root", "kexec_load", "kexec_file_load",
    "init_module", "finit_module", "delete_module", "open_by_handle_at",
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


# Runs INSIDE the sandbox as /tmp/.sbox-seccomp.py, as the FIRST sandboxed
# process (bwrap execs it directly): install the compiled filter, self-probe
# it, then exec the command line (sh, the socat bridge, the command and all
# descendants inherit the filter — nothing unfiltered is left below it).
# Self-contained stdlib-only Python so nothing but python3 is needed in the
# sandbox. Fails loudly instead of running unfiltered.
SECCOMP_HELPER = """\
import ctypes, os, sys
bpf = bytes.fromhex("@BPF@")

class SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_ushort), ("jt", ctypes.c_ubyte),
                ("jf", ctypes.c_ubyte), ("k", ctypes.c_uint)]

class SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(SockFilter))]

prog = SockFprog(len(bpf) // 8, (SockFilter * (len(bpf) // 8)).from_buffer_copy(bpf))
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
libc.prctl.restype = ctypes.c_int
libc.prctl(38, 1, 0, 0, 0)  # PR_SET_NO_NEW_PRIVS (bwrap sets it too; idempotent)
if libc.prctl(22, 2, ctypes.byref(prog), 0, 0) != 0:  # PR_SET_SECCOMP, SECCOMP_MODE_FILTER
    print("sbox.py: cannot install the seccomp filter:",
          os.strerror(ctypes.get_errno()), file=sys.stderr)
    sys.exit(1)
# Fail-closed self-probe (the seccomp analogue of the proxy self-test): a
# wrong number in the hand-typed syscall table would silently deny the wrong
# syscall and load fine. unshare(0) is a harmless no-op that succeeds
# unfiltered; under this filter it must return -1 with EPERM. Probe through
# the C library's unshare() wrapper — it maps the name to the kernel's real
# number, so the table cannot fool its own probe. The return value is
# checked first: a successful call does not update errno.
if hasattr(libc, "unshare"):
    ctypes.set_errno(0)
    rc = libc.unshare(0)
else:  # libc without the wrapper: fall back to our own table number
    libc.syscall.restype = ctypes.c_long
    ctypes.set_errno(0)
    rc = libc.syscall(@UNSHARE@, 0)
if rc != -1 or ctypes.get_errno() != 1:  # EPERM
    print(f"sbox.py: seccomp self-probe failed: unshare(0) not denied "
          f"(rc={rc}, errno={ctypes.get_errno()}) — refusing to run unfiltered",
          file=sys.stderr)
    sys.exit(1)
os.execvp(sys.argv[1], sys.argv[1:])
"""


def sandbox_python3() -> str | None:
    """A python3 that exists inside the sandbox: the RESOLVED interpreter
    (only /usr, /bin, ... are mounted there — $HOME/.pyenv/bin/python or an
    activated venv's ~/venv/bin/python is a tmpfs path inside, even when it
    symlinks to /usr/bin/python3.x)."""
    for cand in (sys.executable, "/usr/bin/python3", "/bin/python3", "/usr/bin/python"):
        if not cand:
            continue
        try:
            real = os.path.realpath(cand)
        except OSError:
            continue
        # The interpreter must live under a mounted tree post-symlink, and
        # the path we return must be that resolved one: cand itself may
        # exist only via a symlink outside the mounted trees (venv,
        # linuxbrew, ...), which is a tmpfs path inside the sandbox.
        if os.path.isfile(real) and real.startswith(("/usr/", "/bin/")):
            return real
    return None


def seccomp_exec(sand: str, verbose: bool, required: bool = False) -> list[str] | None:
    """Write the helper into the sandbox's /tmp (bound from $WORK) and
    return the argv prefix ([python3, helper]) that bwrap execs as the
    FIRST sandbox process — everything below it (sh, the socat bridge, the
    command) inherits the installed filter — or None (with a warning — or
    a hard error under `required`, i.e. --require-seccomp) when the
    hardening cannot be provided."""

    def unavailable(msg: str) -> None:
        if required:
            die(f"--require-seccomp: {msg}")
        err(f"warning: {msg}")

    bpf = build_seccomp_bpf()
    if bpf is None:
        unavailable(f"no seccomp syscall table for this machine ({platform.machine()}) — "
                    "seccomp hardening disabled")
        return None
    py = sandbox_python3()
    if py is None:
        unavailable("no python3 available inside the sandbox (bwrap only mounts /usr, /bin, ...) — "
                    "seccomp hardening disabled")
        return None
    path = os.path.join(sand, ".sbox-seccomp.py")
    with open(path, "w", encoding="utf-8") as fh:
        # @UNSHARE@ is only the fallback probe number (the primary probe
        # uses the C library's unshare() wrapper, which cannot be fooled by
        # our own table).
        unshare_nr = SECCOMP_SYSCALLS[seccomp_machine()]["unshare"]
        fh.write(SECCOMP_HELPER.replace("@BPF@", bpf.hex()).replace("@UNSHARE@", str(unshare_nr)))
    os.chmod(path, 0o500)
    if verbose:
        err(f"seccomp: deny-list installed via /tmp/.sbox-seccomp.py ({len(bpf) // 8} filter instructions)")
    return [py, "/tmp/.sbox-seccomp.py"]


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
    "/tmp/.X11-unix",
    f"/run/user/{os.getuid()}/bus",
    f"/run/user/{os.getuid()}/gnupg/S.gpg-agent",
    f"/run/user/{os.getuid()}/pipewire-0",
    f"/run/user/{os.getuid()}/docker.sock",
    f"/run/user/{os.getuid()}/podman/podman.sock",
    f"/run/user/{os.getuid()}/systemd/private",
    f"/run/user/{os.getuid()}/keyring",      # gnome-keyring: secrets + ssh agent
    os.path.expanduser("~/.1password/agent.sock"),
}


def _is_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def check_bind_paths(opts, home: str) -> list[tuple[str, str]]:
    """Validate -b/--ro-bind before anything is started; return the resolved
    (flag, realpath) pairs that build_bwrap mounts — validation and mount
    must use the same path, so symlink swaps and relative paths can't make
    bwrap mount something that was never checked.

    Whatever these paths really point at is handed to the sandbox, so refuse
    anything that covers a protected path (an ancestor of — or equal to —
    $HOME, a system dir, or the user runtime dir with its agent/pipewire/
    D-Bus sockets), covers a known host control socket (CONTROL_SOCKETS),
    or is socket-shaped by rule: any socket file, and anything under /run,
    /var/run or $XDG_RUNTIME_DIR — control-socket territory where a
    name list will always lag reality. --bind-socket PATH is the explicit
    per-path opt-in for the socket-shaped rule. Children of protected
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
                        ("--bind", opts.bind_socket)):
        for p in paths:
            rp = os.path.realpath(p)
            exempt = flag == "--bind" and opts.home and rp == real_home
            hits = [] if exempt else [q for q in protected if covers(rp, q)]
            if hits:
                die(f"{flag} {p} covers protected path(s): {', '.join(hits)}"
                    + ("; use --home to bind $HOME itself"
                       if flag == "--bind" and rp == real_home else ""))
            sock_hits = sorted(s for s in CONTROL_SOCKETS if covers(rp, s))
            if sock_hits or rp.startswith("/tmp/.X11-unix/"):
                die(f"{flag} {p} covers host control socket(s): "
                    f"{', '.join(sock_hits) or rp} — that hands the sandbox "
                    "full control of the host (container runtime, D-Bus/"
                    "systemd, keyring, X11, ...); refusing")
            if rp not in explicit and (
                    any(covers(root, rp) for root in runtime_roots)
                    or _is_socket(rp)):
                die(f"{flag} {p}: {rp} is a socket or lives under a runtime "
                    "dir — control-socket territory (a full host escape "
                    "waiting for a name we forgot); pass "
                    "--bind-socket to bind it anyway")
            binds.append((flag, rp))
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


def build_bwrap(opts, sand: str, sock: str, home: str, user_binds: list[tuple[str, str]],
                agent: str | None, ssh_cfg: str | None) -> tuple[list[str], str]:
    import pwd  # POSIX only; we require Linux anyway (bwrap)

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
        bw += ["--bind", home, home]
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
        bw += ["--ro-bind" if opts.ro_cwd else "--bind", project, project]

    for flag, rp in user_binds:
        bw += [flag, rp, rp]  # mount exactly the validated (resolved) path

    # bwrap applies --chdir after all mounts, wherever it sits in argv.
    user_bound = {rp for _, rp in user_binds}
    if bind or any(covers(b, project) for b in user_bound):
        bw += ["--chdir", project]
    else:
        bw += ["--chdir", "/tmp"]

    # inner ends with a plain exec: the seccomp helper (when present) is
    # exec'd by bwrap BEFORE this script (see run_sandbox), so the filter
    # it installs covers the shell, the socat bridge AND the command. That
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
        # Seccomp deny-list (best-effort: None with a warning when this
        # machine or sandbox has no usable python3; --no-seccomp skips it;
        # --require-seccomp makes unavailability fatal).
        seccomp = None if opts.no_seccomp else seccomp_exec(sand, opts.verbose, opts.require_seccomp)

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

        bw, inner = build_bwrap(opts, sand, sock, os.environ["HOME"], user_binds, agent, ssh_cfg)
        # The seccomp helper must be the FIRST process in the sandbox: the
        # filter it installs (and self-probes) is inherited by everything it
        # execs — the shell, the socat bridge and the command. bwrap's own
        # namespace setup runs outside and is untouched. Passing the helper
        # as argv (never a shell string) also avoids quoting pitfalls.
        argv = ["bwrap"] + bw + ["--"]
        if seccomp:
            argv += seccomp
        argv += ["/bin/sh", "-c", inner, "sbox-sh"] + command
        sandbox = subprocess.Popen(argv)
        procs.append(sandbox)

        seen_signals: set[int] = set()

        def forward(signum, _frame):
            # The first signal is relayed as-is; a sandboxed command that
            # traps or ignores it would otherwise hang the launcher forever
            # (repeated Ctrl-C did nothing useful), so the same signal
            # arriving twice escalates to SIGKILL. --die-with-parent already
            # covers a SIGKILL of the launcher itself.
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
            time.sleep(0.1)
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
  - The cwd is mounted read-write by default: sandboxed code can plant
    .git/hooks, Makefiles etc. that run on the host later. Use --ro-cwd
    for untrusted code.
  - Explicit -b/-r binds overlay the automatic cwd mount when they cover
    it: -r "$PWD" from inside the directory gives a read-only cwd, and
    likewise -b over --ro-cwd gives read-write (the explicit flag wins).
  - The sandbox runs in a new session (TIOCSTI protection): Ctrl-C reaches
    sbox.py, which then tears the whole sandbox down.
  - Seccomp deny-list: io_uring_*, bpf, perf_event_open, userfaultfd,
    keyring, namespace (unshare/setns/clone3/clone-with-CLONE_NEWUSER),
    admin (mount/pivot_root/chroot/kexec/module loading/open_by_handle_at
    and the new mount API fsopen/fsmount/move_mount/...), process-
    inspection/injection (ptrace, process_vm_*/kcmp/pidfd_getfd/personality)
    syscalls plus ioctl(TIOCSTI/TIOCLINUX) are refused inside the sandbox;
    socket() is limited to AF_UNIX/AF_INET/AF_INET6/AF_NETLINK (AF_VSOCK
    bypasses netns isolation in VM guests on older kernels) — ENOSYS where
    runtimes have fallbacks, EPERM otherwise; foreign-ABI binaries (e.g.
    32-bit compat, x32) are killed. The filter covers everything inside
    the sandbox from the first process (the socat bridge included; the
    payload runs as pid 1, so no unfiltered bwrap reaper init remains).
    Needs python3 inside the sandbox; perf, io_uring runtimes, unshare-
    based builders, keyring-using kerberos, debuggers (gdb/strace), setarch
    or nested containers need --no-seccomp. Without it the launcher
    FAILS OPEN with a warning — --require-seccomp makes that fatal and is
    the recommended default for untrusted work (put it in your alias).

Examples:
  sbox.py -a pypi.org -a files.pythonhosted.org -- pip install requests
  sbox.py -a github.com -- git clone https://github.com/torvalds/linux
  sbox.py -a example.com -v -- curl -sI https://example.com
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
                             "mount/kexec/module-loading, ptrace/process_vm_* syscalls and "
                             "ioctl TIOCSTI/TIOCLINUX are blocked with ENOSYS/EPERM inside the sandbox).")
    parser.add_argument("--require-seccomp", action="store_true",
                        help="Abort instead of warning when the seccomp filter cannot be installed "
                             "(no python3 inside the sandbox, unsupported architecture).")
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
    if opts.no_seccomp and opts.require_seccomp:
        parser.error("--no-seccomp and --require-seccomp are contradictory")

    if not shutil.which("bwrap"):
        die("missing dependency: bwrap (needed on the host)")
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
