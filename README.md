# sbox.py

Run a command in a [bubblewrap](https://github.com/containers/bubblewrap) sandbox
with an **allowlisted network** — untrusted code can compute, but it can only
talk to the hosts you name, and everything else fails closed.

```console
$ sbox.py -a pypi.org -a files.pythonhosted.org -- pip install requests
$ sbox.py -a github.com -- git clone https://github.com/torvalds/linux
$ sbox.py -a example.com -v -- curl -sI https://example.com
$ sbox.py --ssh-agent -a github.com -- git clone git@github.com:me/repo.git
```

Why not just `bwrap` alone? Namespaces hide the network but give you no
policy: it is all or nothing. `sbox.py` adds the missing piece — a
default-deny egress allowlist — while keeping the tool a single stdlib-only
Python file with no third-party proxy dependency.

## Requirements

- Linux with unprivileged user namespaces (many containers block this —
  bwrap then fails with "No permissions to create a new namespace")
- `bwrap` and `socat` on the host; `python3 >= 3.8` (stdlib only)
- `--net` mode needs `bwrap` only

## Install

Copy the file anywhere in `$PATH` and make it executable:

```sh
install -m 755 sbox.py ~/.local/bin/sbox.py
```

## Usage

```
sbox.py [options] [--] COMMAND [args...]
sbox.py [options] --shell
```

Everything after the first positional (or `--`) is the sandboxed command.

| Option | Meaning |
| --- | --- |
| `-a, --allow HOST` | Allow `HOST` and its subdomains (suffix match on a dot boundary). Also accepts IPs, CIDRs and an optional `:port` (`example.com:443`, `203.0.113.0/24`, `[2001:db8::]/32`). Repeatable. |
| `-A, --allow-file FILE` | File with allow entries, one per line, `#` comments. Repeatable. |
| `-b, --bind PATH` | Bind `PATH` read-write into the sandbox. Repeatable. |
| `-r, --ro-bind PATH` | Bind `PATH` read-only. Repeatable. |
| `--ro-cwd` | Mount the current directory read-only (default: read-write). |
| `--home` | Bind the real `$HOME` (default: private tmpfs home). |
| `--gui` | Pass through Wayland (preferred) and X11 sockets. |
| `--ssh-agent` | Forward `$SSH_AUTH_SOCK` read-only to `/run/ssh-agent.sock`. |
| `--upstream URL` | Chain egress through an upstream proxy: `http://`, `https://`, `socks5://`, `socks5h://` (userinfo supported). Default: `$SBOX_UPSTREAM`, else `$https_proxy`/`$HTTPS_PROXY`; empty string forces direct. |
| `--upstream-insecure` | Skip TLS verification of an `https://` upstream (or `$SBOX_UPSTREAM_INSECURE`). |
| `--net` | Share the host network namespace: direct egress, no proxy/allowlist (`-a/-A/--upstream` ignored). |
| `--no-seccomp` | Do not install the seccomp deny-list. |
| `--require-seccomp` | Abort instead of warning when the seccomp filter cannot be installed (no python3 inside the sandbox, unsupported architecture). |
| `-v, --verbose` | Log every allow/deny decision to stderr. |
| `--shell` | Run an interactive shell (`$SHELL` if usable, else bash). |

## How it works

- **No network stack in the sandbox.** `bwrap --unshare-all` removes it; the
  only egress is a Unix socket passed in at `/run/proxy.sock`.
- **The launcher is the proxy.** The same file re-executes itself as a small
  asyncio SOCKS5 + HTTP-CONNECT server on the host, listening on that socket.
- **Inside**, a `socat` loopback bridge makes the proxy available at
  `127.0.0.1:1080`, auto-detecting SOCKS5 vs HTTP per connection — so
  `http_proxy=http://127.0.0.1:1080` works for tools that do not understand
  `socks5h://` (npm, apt, ...). Proxy env vars are preset; apps that ignore
  them simply get no network (fail-closed).
- **ssh** ignores proxy env vars, so proxied mode injects `/etc/ssh/ssh_config`
  with a `ProxyCommand` through the bridge: `ssh`/`scp`/`sftp` and
  git-over-ssh ride the same allowlist-checked proxy. `~/.ssh/config` still
  wins per-option. No `known_hosts` is injected: host-key verification
  fails closed (tmpfs home, no TTY) — pass `-r ~/.ssh/known_hosts` or pin
  hosts yourself.
- **Startup self-test:** before the sandbox starts, a non-allowed destination
  is probed on the real socket and must be refused on both protocols — the
  fail-closed guarantee is checked, not assumed.
- **Seccomp hardening:** a deny-list filter (io_uring, bpf, perf_event_open,
  userfaultfd, kernel keyring, nested user namespaces, mount/kexec/module
  syscalls, process-injection APIs — ptrace, process_vm_readv/writev — and
  `ioctl(TIOCSTI/TIOCLINUX)`) is installed by the *first* process inside the
  sandbox and inherited by everything below it: the shell, the socat bridge
  and the command, so a filtered command cannot inject syscalls into an
  unfiltered sibling (ptrace/`/proc/<pid>/mem`, Yama scope 1). ENOSYS where
  runtimes have fallbacks, EPERM elsewhere; foreign-ABI binaries are killed.
  Needs `python3` inside the sandbox, otherwise skipped with a warning
  (fatal with `--require-seccomp`); debuggers (gdb/strace) need
  `--no-seccomp`.
- **Lifecycle:** if any component dies, everything dies (supervisor loop,
  `--die-with-parent`, `PR_SET_PDEATHSIG` on the proxy) — even a SIGKILLed
  launcher takes the proxy with it.

## Security model

- **Default-deny.** A destination is checked against the allowlist *before
  anything else*; hostnames of denied destinations are never resolved — there
  is no DNS side channel (no `<data>.evil.com` exfiltration through lookups).
- **SSRF guard.** Allowed hostnames are resolved host-side; answers in
  private, loopback, link-local, CGNAT, multicast or reserved ranges are
  rejected, so an allowed name cannot reach host or LAN services (including
  `169.254.169.254`). Explicit `-a IP/CIDR` entries deliberately bypass this
  guard — use them with care.
- **Loud, not wide.** Catch-all entries (`*`, `0.0.0.0/0`, effectively-global
  CIDRs) and CIDRs with host bits set (`203.0.113.7/24`) are rejected loudly
  instead of being widened or silently allowed.
- **Ports** are unrestricted unless an entry carries `:port`.

### Trust decisions — read before using

- The **cwd is mounted read-write by default**: sandboxed code can plant
  `.git/hooks`, Makefiles etc. that run on the host later. Use `--ro-cwd` for
  untrusted code.
- `--home` exposes the real `$HOME`: `~/.bashrc`, `~/.local/bin` and any agent
  sockets in it run with your full identity.
- `--ssh-agent` lets *any* code in the sandbox sign with every key loaded in
  the agent, i.e. authenticate as you wherever the network policy allows.
  The read-only bind limits the socket file, **not the agent protocol**:
  sandboxed code can equally strip all identities or lock the agent
  (`ssh-add -D`/`-x`) — a DoS on your agent, not a key leak. Prefer a
  dedicated agent holding only the needed key, loaded with `ssh-add -c`
  (confirm each use) or `-h` (destination constraint), for untrusted work.
- ssh destinations need `known_hosts`: with a tmpfs home and no TTY
  (`--new-session`), host-key prompting fails closed — pass
  `-r ~/.ssh/known_hosts` (or pin hosts in your own `~/.ssh/config`, which
  wins per-option).
- `--gui` passes through Wayland and X11. X11 allows any client to log
  keystrokes and capture the screen.
- `--net` shares the host network namespace: the allowlist is **not** enforced,
  and host loopback services and abstract Unix sockets (D-Bus, X11, ...) become
  reachable. Only use it for trusted work.

## Known limits

Design trade-offs, not bugs:

- `-b`/`-r` binds are only refused when they cover a protected path (system
  dirs, `$HOME`, `/run/user/<uid>`); anything else you bind is handed over as
  requested — including the launcher's `/tmp/sbox.*` work dir with any upstream
  credentials.
- No resource limits (CPU/memory/PID/fds) inside the sandbox; the boundary is
  bwrap's namespaces plus the seccomp deny-list.
- No domain-fronting protection: an allowed CDN host may serve many origins.
- With `--upstream`, the destination reaches the upstream as a literal IP
  (`CONNECT 1.2.3.4:443`), never the hostname — hostname-based policy on that
  proxy cannot work, and some proxies reject IP CONNECT targets.
- The proxy has no connection caps, idle timeouts or header-count limits;
  tunnels have no TCP half-close, and only the first resolved address is tried
  when chaining through an upstream.

## Development

Single file, stdlib only. Seccomp tests: `python3 tests/test_seccomp.py`
(plain python3 or pytest; skips cleanly when references or capabilities are
missing). See [AGENTS.md](AGENTS.md) for architecture notes, verification
recipes and the invariants to preserve.
