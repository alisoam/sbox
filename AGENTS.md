# AGENTS.md

Single-file tool: `sbox.py` runs a command in a bubblewrap sandbox whose only
network egress is a host-side allowlist-checking proxy (SOCKS5 + HTTP CONNECT,
auto-detected per first byte). No packaging, no linter, no CI; seccomp tests
in `tests/` (plain `python3 tests/test_seccomp.py`, pytest-compatible).

## Hard constraints

- Host dependencies: `bwrap` + `socat`; a `python3` under `/usr` or `/bin` must
  exist inside the sandbox or seccomp hardening is skipped (loud warning).
- The module docstring *is* the spec (security model, known limits); the
  argparse epilog and option help duplicate the user-facing parts. Behavior
  changes must update docstring and epilog/help together.
- **Trap when adding a CLI option with a value:** it must be added to
  `OPTS_WITH_VALUE` or `split_argv` mis-splits `sbox.py --newopt x -- cmd`.
  (`allow_abbrev=False` exists for the same reason.)
- Style: wrap source/comments at ~100 columns. `from __future__ import
  annotations` is what makes `X | None` annotations legal on 3.8.

## Architecture facts you'd otherwise miss

- The file **re-executes itself as the proxy** via the hidden `--_proxy SOCK
  CFG PPID` flag. The proxy runs host-side on a Unix socket bound read-only
  into the sandbox at `/run/proxy.sock`; a `socat` bridge inside exposes it at
  `127.0.0.1:1080`.
- Seccomp is a hand-compiled cBPF deny-list (`build_seccomp_bpf`), injected
  as a generated stdlib-only `/tmp/.sbox-seccomp.py` that bwrap execs as the
  **FIRST sandbox process**: it installs + self-probes the filter, then
  execs the command line (`run_sandbox` assembles the argv — the helper is
  never interpolated into the shell script). Everything below inherits the
  filter: sh, the socat bridge, the command. That order is load-bearing —
  never start the bridge before the helper: once sh execs the command, the
  command is the bridge's *parent*, and Yama scope 1 allows
  ptrace/`/proc/<pid>/mem` against your own descendants, so any unfiltered
  process below the command is a syscall-injection bypass.
- Proxy config travels via `$WORK/proxy.json` (mode 0600 — it may hold
  upstream credentials) and is unlinked as soon as the proxy has read it.

## Verifying changes (tests live in tests/)

```sh
python3 -m py_compile sbox.py
python3 sbox.py --help
python3 tests/test_seccomp.py   # syscall table vs references + live filter
                                # probe (fork + PR_SET_SECCOMP — works even
                                # where bwrap cannot, e.g. this container)
# Pure functions import side-effect-free; unit-check without bwrap:
python3 -c "import sbox; print(sbox.parse_allow_entry('example.com:443'))"
python3 -c "import sbox; print(len(sbox.build_seccomp_bpf())//8, 'filter insns')"
# Live smoke tests — bwrap needs unprivileged user namespaces, which THIS
# container does not allow (bwrap dies with "No permissions to create a new
# namespace"); run these on a real host. Everything before bwrap (allowlist
# parsing, proxy start, fail-closed self-test) does run even here.
./sbox.py -a example.com -v -- curl -sI https://example.com   # allow + decision log
./sbox.py -- curl -sI https://example.com                     # must be denied
./sbox.py --shell                                            # interactive poking
```

## Invariants — easy to break, load-bearing

Allowlist/denial semantics:
- The allowlist is checked **before any DNS**; denied hostnames are never
  resolved (no DNS exfiltration side channel). Keep `connect_destination`
  ordered: allowlist → resolve (filtered) → connect.
- SSRF guard: allowed names resolving into private/loopback/link-local/CGNAT/
  multicast/reserved ranges are rejected (`bad_ip`, incl. NAT64/6to4/Teredo
  embedding). Only explicit `-a IP/CIDR` literals bypass it — deliberately.
- Fail loud, never widen: catch-all entries (`*`, `0.0.0.0/0`,
  effectively-global CIDRs, host bits set) are rejected, not interpreted.
- Never print attacker-controlled bytes raw: `!r` for hostnames,
  `redact_userinfo()` for upstream URLs (credentials), sanitized single-line
  `X-Sbox-Error` header.

Lifecycle and path handling:
- `check_bind_paths` validates *realpaths* and `build_bwrap` mounts those same
  resolved paths — validation and mount must never diverge (symlink swaps).
- bwrap argv order matters: the automatic cwd bind is emitted **before** user
  binds (a later bind shadows an earlier one at the same target), so explicit
  `-r "$PWD"` wins over the default read-write cwd.
- Signals: `early_signal` (startup) → `forward` (same signal twice escalates
  to SIGKILL) → `SIG_IGN` during cleanup so `$WORK` removal cannot be
  interrupted. The proxy dies with the launcher (PR_SET_PDEATHSIG + ppid
  check); bwrap gets `--die-with-parent`.
- `rm_tree_writable` uses `lstat` everywhere: never chmod through a symlink
  planted in the sandbox's `/tmp`.

Seccomp specifics:
- **The syscall tables are hand-typed** — a wrong number silently denies the
  wrong syscall (this shipped once: ioctl=29/shmget, unshare=310/
  process_vm_readv on x86_64). Three layers pin it down: `tests/
  test_seccomp.py` checks every entry against kernel headers /
  `scmp_sys_resolver` / `ausyscall`, its runtime probe calls `unshare(0)` /
  `ioctl(TIOCSTI)` / `ptrace(ATTACH)` through the **C library wrappers**
  (name→number ground truth, so the table cannot fool its own probe), and
  the sandbox helper self-probes fail-closed at startup before exec'ing the
  command. Extend the table only together with the test.
- `ptrace` and `process_vm_readv/writev` are denied as defense in depth
  (debuggers — gdb/strace — inside the sandbox need `--no-seccomp`).
- cBPF argument quirks: the kernel truncates `ioctl`'s cmd to 32 bits, so
  the TIOCSTI/TIOCLINUX rules compare the **low word only** — a high-word==0
  requirement is a bypass (`0x1_0000_5412` executes as TIOCSTI). And x32
  shares `AUDIT_ARCH_X86_64` with bit `0x40000000` set in the number, so
  x86_64 kills any number with that bit explicitly (exact-number rules
  would silently allow x32 calls).
- ENOSYS only where callers have fallbacks (`clone3`, `io_uring_*`: glibc
  falls back to clone, runtimes to plain threads); EPERM for the rest;
  foreign-ABI binaries (e.g. 32-bit compat) are killed — syscall numbers are
  per-ABI, number-based filtering would be meaningless.
- It is a **deny-list**: everything unlisted stays allowed so ordinary
  toolchains keep working. Unsupported arch or no sandbox python3 ⇒ skip with
  a warning, never filter the wrong numbers (`--require-seccomp` makes the
  skip fatal; it contradicts `--no-seccomp` — the launcher refuses both).
