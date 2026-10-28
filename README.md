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
| `--bind-socket PATH` | Explicit opt-in (mounted **read-only**) to bind a socket, a runtime-dir path, or a socket-bearing directory that `-b`/`-r` refuse by default. Repeatable; known control sockets and protected paths stay refused. |
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
  syscalls plus the new mount API, process-injection APIs — ptrace,
  process_vm_readv/writev, kcmp, pidfd_getfd, personality — and
  `ioctl(TIOCSTI/TIOCLINUX)`) is installed by the *first* process inside the
  sandbox and inherited by everything below it: the shell, the socat bridge
  and the command — which also runs as pid 1 (`--as-pid-1`), so no unfiltered
  bwrap reaper init remains inside (on Yama `ptrace_scope=0` systems that
  parent could otherwise be `/proc/1/mem`-injected, bypassing the filter).
  Note pid-1 semantics: long-lived commands that abandon children see
  zombies, and `kill 1` from inside is ignored unless handled.
  `socket()` is limited to `AF_UNIX`/`AF_INET`/`AF_INET6`/`AF_NETLINK`
  (AF_VSOCK bypasses netns isolation in VM guests on older kernels). ENOSYS
  where runtimes have fallbacks, EPERM elsewhere; foreign-ABI binaries are
  killed, thread group included. Without a usable python3 inside the sandbox
  the filter is **skipped with a warning (fail-open)** — fatal with
  `--require-seccomp`, the recommended default for untrusted work:

  ```sh
  alias sbox='sbox.py --require-seccomp'
  ```

  Debuggers (gdb/strace) and `setarch` need `--no-seccomp`.
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
- **The allowlist is also an exfiltration channel.** Suffix matching means
  `-a github.com` allows *pushing* to (and gisting from) any repo of yours,
  not just cloning; multi-tenant domains (`amazonaws.com`, `github.io`,
  `cloudfront.net`, `pages.dev`, ...) allow attacker-controlled hosts under
  the same suffix. With `--home`, everything in `$HOME` can leave through
  any allowed host. Keep allowlists minimal and scoped (`:port` helps).

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
- `--gui` passes through Wayland and X11. **X11 is effectively an escape**:
  any client can log keystrokes, capture the screen *and inject input*
  (XTEST/SendEvent — e.g. type into your terminal, which is host command
  execution). Treat X11 passthrough as unsandboxed; prefer Wayland.
- Binding host control sockets via `-b`/`-r` is refused outright — by name
  (`docker.sock`, `containerd`, `podman`, `crio`, D-Bus, `systemd`,
  `libvirt`, `snapd`, `tailscaled`, `incus`/LXD, X11, `tmux`, `gnome-keyring`,
  `gpg-agent`, pipewire, 1Password, Docker Desktop/colima in `$HOME` —
  parent dirs *and* sibling files in known control dirs included), and by
  **shape**: any socket file, anything under `/run`, `/var/run` or
  `$XDG_RUNTIME_DIR`, and any directory containing a Unix socket (bounded
  scan — that closes the "project dir with a dev-server socket" case
  outside `/run`). Each is a trivial full escape. `--bind-socket PATH`
  (read-only) is the explicit per-path opt-in for the shape/scan rules;
  known control sockets and protected paths stay refused. `--home` (and
  `-b ~` with it) binds the whole home by design — known control sockets
  inside `$HOME` produce a note, not a refusal.
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
