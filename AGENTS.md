# AGENTS.md

Single-file tool: `sbox.py` runs a command in a bubblewrap sandbox whose only
network egress is a host-side allowlist-checking proxy (SOCKS5 + HTTP CONNECT,
auto-detected per first byte). No packaging, no linter, no CI; seccomp tests
in `tests/` (plain `python3 tests/test_seccomp.py`, pytest-compatible).

## Hard constraints

- Host dependencies: `bwrap` + `socat` + host `python3 >= 3.8`. The seccomp
  filter is installed by bwrap itself (`--add-seccomp-fd`, `--seccomp` on
  bwrap >= 0.4.1) — nothing is needed *inside* the sandbox, and if bwrap
  cannot install the filter the launcher **dies** (fail-closed; only
  `--no-seccomp` opts out). `--disable-userns` needs bwrap >= 0.8,
  fd-pinned binds need >= 0.10 (older bwrap degrades with a loud note).
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
- Seccomp is a hand-compiled cBPF deny-list (`build_seccomp_bpf`) handed to
  **bwrap itself** via `--add-seccomp-fd`/`--seccomp` through a pipe
  (`seccomp_fd_args` writes the raw `sock_filter` bytes — a multiple of 8,
  **no length prefix**; bwrap reads the fd at argv-parse time and applies
  the filter as the very last step before `execve` of `/bin/sh`). So sh,
  the socat bridge, the command and every descendant are filtered from
  their first instruction — there is deliberately NO in-sandbox installer
  anymore (the old python3 helper ran *after* site.py had processed user
  `.pth`/usercustomize, and failed open when the sandbox lacked python3).
  The Yama-scope-1 argument still holds: never arrange for anything
  unfiltered below the command — once sh execs the command, the command is
  the bridge's *parent*, and ptrace/`/proc/<pid>/mem` against your own
  descendants is allowed, so an unfiltered process below the command is a
  syscall-injection bypass.
- bwrap capabilities are **probed, not version-matched**: `bwrap_caps()`
  runs `bwrap --help` once and `parse_bwrap_caps()` greps the option names
  (0.6.3 backported `--bind-fd` from 0.10, version numbers lie). The probe
  happens in `main()` and travels via `opts._bwrap_caps`; `run_sandbox`
  must NOT probe lazily — tests put fake `bwrap` shims on `$PATH` whose
  `--help` would hang. Missing caps ⇒ conservative defaults there.
- On bwrap >= 0.8 the argv also carries `--unshare-user --disable-userns
  --assert-userns-disabled` (nested user namespaces die at the kernel
  level via `max_user_namespaces` in a nested userns, verified by bwrap).
  The **explicit `--unshare-user` is required**: `--unshare-all` only sets
  `--unshare-user-try`, and bwrap checks the combination *before* its
  non-root "just DWIM" fallback — without it bwrap dies at argv parse.
  The combination is **probed once per launch** (`userns_probe_ok`: a
  throwaway sandbox running the SAME namespace/pid/session flags as the
  real argv — `--unshare-all --die-with-parent --new-session --as-pid-1`
  plus `--share-net` in `--net` mode — so flag interactions fail in the
  probe, not the launch): hosts where it cannot work at all (setuid
  bwrap, `unprivileged_userns_clone=0`, `max_user_namespaces=0`) skip the
  flags with a note (shown at most once a day, `note_recently_shown`) —
  the seccomp unshare/setns/clone deny rules still cover nesting.
- User binds, the cwd mount and `--home` are mounted **by pinned fd**, and
  validation is **fd-FIRST** (`validate_bind_source` + `BindPinner.pin` +
  `open_path_pinned`): the realpath is pinned FIRST — a
  component-by-component `openat(O_PATH|O_NOFOLLOW)` walk that refuses
  ANY symlink (its input is a realpath, so a symlink means something was
  swapped) — then every check runs on the pinned object: `fstat` for the
  socket rules, the `_contains_socket` scan rooted at `/proc/self/fd/N`,
  and `_fd_reaches` (readlink of `/proc/self/fd/N` must still name the
  validated path — the kernel's own view, dies on rename/swap/delete).
  `check_bind_paths` returns `(flag, realpath, fd)` triples and
  `build_bwrap` mounts exactly those fds. **Never validate a path string
  and mount a separately-resolved fd (or vice versa)** — the fd you
  validated is the fd you mount; there is no "expected inode" to keep in
  sync anymore. **Only fds the argv names reach bwrap**: `run_sandbox`
  derives `pass_fds` from the emitted `--bind-fd`/`--ro-bind-fd` numbers
  and closes every unused pin (`BindPinner.release`; the refused cwd
  releases its pin in `build_bwrap`) — bwrap closes only fds attached to
  setup ops, so a stray pin would survive into the payload, and an O_PATH
  fd to host ground makes `/proc/self/fd/N/..` walk the HOST mount tree
  (the runc CVE-2024-21626 "Leaky Vessels" escape;
  test_no_orphan_pins_reach_payload is the regression net). A pin NAMED
  TWICE in one argv (cwd == a `-b` path, `-b $HOME --home`) gets an
  `os.dup()` per extra use — `build_bwrap` returns the dups as a third
  value for parent-side closing — so bwrap's per-op close ordering can
  never decide whether the later `--bind-fd N` still resolves.
  System trees, `$WORK` and runtime sockets stay path-based
  (not writable by other sandboxes, nothing to race).
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
python3 -c "import sbox; print(sbox.bwrap_caps())"        # real bwrap's options
python3 -c "import sbox; sbox.seccomp_selfprobe(sbox.build_seccomp_bpf()); print('self-probe ok')"
python3 -c "import sbox, os; fd=sbox.open_path_pinned('/tmp'); print(os.fstat(fd))"
# Live smoke tests — bwrap needs unprivileged user namespaces, which THIS
# container does not allow (bwrap dies with "No permissions to create a new
# namespace"); run these on a real host. Everything before bwrap (allowlist
# parsing, proxy start, fail-closed self-test) does run even here.
./sbox.py -a example.com -v -- curl -sI https://example.com   # allow + decision log
./sbox.py -- curl -sI https://example.com                     # must be denied
./sbox.py --filter-output -- sh -c 'printf "\033]52;c:aGk=\033\\visible\033[31m!\033[0m\n"'
                                                              # OSC 52 stripped, text+color kept
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
  effectively-global CIDRs, host bits set) are rejected, not interpreted;
  single-label entries (`-a com` — a whole TLD) are warned about
  (`_warn_single_label`).
- Never print attacker-controlled bytes raw: `!r` for hostnames,
  `redact_userinfo()` for upstream URLs (credentials), sanitized single-line
  `X-Sbox-Error` header.
- `split_argv` **rejects clustered short FLAGS** (`-va`) loudly — it
  cannot expand them, and the silent single-token skip made the token
  after a cluster parse as the sandboxed command. Attached short VALUES
  (`-b/some/path`, `-aexample.com`) are valid argparse and consume one
  token (`SHORT_WITH_VALUE`, derived from `OPTS_WITH_VALUE` so the trap
  list stays the single source of truth). A new value-taking option must
  still land in `OPTS_WITH_VALUE` (above).

Output filter specifics (`--filter-output`):
- bwrap's fds 1/2 are a host-side pty **slave**, and fd 0 is decided by
  `_filter_child_stdin(slave, raw_stdin)` — decided on the VERY fd it
  returns, never a blind inherit of fd 0: the pty slave only for a real
  (raw-mode) host tty; the exact non-tty fd `sys.stdin` wraps otherwise
  (a pipe/file inherits byte-exact — routing it through the pty would
  feed the bytes to the slave's canonical line discipline: 4095-byte
  line truncation, `^D/^U/^W/^V/^R` editing, ICRNL, ISIG, drops past the
  backlog cap — `tar c . | sbox.py --filter-output -- tar x` must
  round-trip byte-exact); `/dev/null` when there is no usable stdin
  (`sys.stdin` can be None — `_enter_raw_mode` catches AttributeError
  for that); and a tty raw mode could NOT tame (hung-up tty etc.) is a
  LOUD REFUSAL — inheriting it would hand the sandbox the host terminal
  fd itself (O_RDWR: `write(0, ...)` bypasses the filter, keystrokes
  become readable). The cheap half of that refusal (isatty +
  tcgetattr failing) runs FIRST, at the top of `run_sandbox`
  (`_check_filter_stdin_early`) — fail fast, before the proxy, the
  self-test or the pty exist; a raw-mode failure that only surfaces
  later still dies in `_filter_child_stdin`, before anything is
  spawned. `close_fds` (the Popen default) keeps every other
  fd out. The master stays
  host-side, non-blocking, pumped inside the supervisor loop's select
  (output to stdout, host tty stdin into the master with a bounded
  backlog that BACKPRESSURES — stop selecting on stdin at
  `MAX_PENDING_INPUT` — instead of dropping bytes, SIGWINCH →
  TIOCSWINSZ); the post-exit drain is deadline-bounded because a
  daemonized child can hold the slave open forever. termios/raw restore
  happens FIRST in the finally; the SIGWINCH restore uses a separate
  `winch_installed` flag because `signal.signal()` returns None for a
  C-installed handler (None must not mean "nothing to restore" there).
- `OutputSanitizer` is an **allowlist**: printable text, `\n\r\t`, and SGR
  `[0-9;]{0,64}` params without conceal (8) — everything else is DROPPED,
  never rewritten or "fixed up" (dropping shows less, never more). C1
  chars (U+009B CSI) are dropped as characters, NOT interpreted as
  sequence starters. A C0 control interleaved in a pending escape
  sequence is EXECUTED like a real terminal (`\n\r\t` pass, the state
  keeps waiting) — a stray ESC must not eat the following newline.
  `strict_cr=True` (the `--strict-crlf` flag, which
  implies `--filter-output`) drops `\r` unless the NEXT byte is `\n`: the
  pending `\r` is held across `feed()` boundaries and dropped at
  `flush()` — that one byte of lookahead must stay split-invariant.
  Hidden text is otherwise NOT prevented (fg==bg colors) — documented,
  not "fixed". Extend tests/test_sandbox.py's sanitizer tests with
  every rule change — including the chunk-boundary equivalence property
  (splitting a stream at any read boundary must filter identically, in
  BOTH default and strict_cr modes).

Lifecycle and path handling:
- `check_bind_paths` validates *realpaths* and returns
  `(flag, realpath, fd)` triples — `fd` is the O_PATH pin captured during
  validation; `build_bwrap` mounts exactly those fds (see the fd-first
  architecture note above) — validation and mount must never diverge
  (symlink swaps). In `BindPinner.pin`, ENOENT maps to the path form ONLY
  for `--bind-socket` (`allow_missing`: runtime paths that do not exist
  yet; bwrap's own not-found error is preserved) — a missing `-b/-r`
  source DIES: those use non---try bwrap flags (bwrap would fail anyway),
  and the path form would let a concurrent sandbox plant a symlink at the
  missing path before the mount. A symlink on the walk, a `_fd_reaches`
  mismatch (rename/swap/delete) or any other pin failure DIES, never
  silently falls back to the racy form. One fd per source (the pin cache):
  the cwd mount and a `-b` of the same path share the object validation
  checked — there is exactly one pin per validated object.
  Binds covering protected paths are refused (`protected_paths` also
  carries the resolved `$XDG_RUNTIME_DIR` as a ROOT, so an ANCESTOR bind
  of it is refused by shape when it lives outside `/run`, instead of
  depending on the depth-3 scan), and so are control sockets:
  known ones via `CONTROL_SOCKETS` matched **bidirectionally** (`covers` in
  both directions: `-b /run/docker`, `--bind-socket .../keyring/ssh` and
  sibling files in listed daemon dirs are all caught; the daemon *dirs* are
  listed too) — always through `_control_sockets()`, which realpaths every
  entry at check time: the `$HOME`-relative entries are expanded WITHOUT
  resolving symlinks, and on a symlinked `$HOME` (Silverblue: /home →
  /var/home) the raw spelling never matched a realpath'd source. Paths
  INSIDE `/proc`, `/sys`, `/dev` (`NO_DESCEND_ROOTS`) are refused under
  every label with NO `--bind-socket` override: `protected_paths` only
  blocks ancestors, and a bind is not a fresh proc mount —
  `/proc/<pid>/root` and `/proc/<pid>/fd/*` are magic links that resolve
  in the host task's context (`ptrace_may_access` is a kuid comparison,
  same uid passes from a child userns; with ptrace_scope=0
  `/proc/<pid>/mem` is writable — the CVE-2024-21626 class via a bind).
  Plus a shape rule — any socket file (`S_ISSOCK`), anything
  under `/run`, `/var/run` or `$XDG_RUNTIME_DIR`, and any `-b`/`-r`
  directory containing a socket (bounded `_contains_socket` scan,
  depth/entry-capped — DIRECTORIES count toward the entry cap, and
  hitting it is fail-open by design but prints a note, at most once a
  day or with `--verbose` (a large cwd must not print on every launch);
  rooted at
  `/proc/self/fd/N` when pinned; refusal
  messages name the HOST path, not the `/proc/self/fd/N` spelling). The
  residual race — a socket appearing after the scan — is accepted: a
  sandbox cannot create host control sockets. `--bind-socket PATH` is the
  explicit per-path opt-in for the shape/scan rules ONLY and takes a
  value — keep it in `OPTS_WITH_VALUE`; it is NEVER an opt-in for a
  read-write mount of connect-only ground: a socket file or runtime-dir
  path with a rw mount mode (`-b P --bind-socket P`, or the rw cwd) is
  REFUSED outright (rw would let the sandbox replace the socket and
  impersonate the service) — plain `--bind-socket` and `-r P
  --bind-socket P` mount them read-only. Plain directories via
  `--bind-socket` mount READ-WRITE (the socket-bearing project dir —
  puma.sock, `.s.PGSQL.5432`, `.git/fsmonitor--daemon.ipc`).
  Known control sockets and protected paths are never overridable.
  `-b $HOME --home` re-binds what `--home` binds: exempt from the socket
  rules but surfaced as a stderr note.
  `test_bind_policy_table` is the machine-readable encoding of these
  mount-mode promises — extend its rows whenever a promise changes.
- The automatic cwd mount goes through the SAME validator
  (`validate_bind_source`, label `"cwd"`): a refusal becomes a WARNING
  ("the command runs with the sandbox's /tmp as its working directory"),
  never a silent note and never a die — the cwd is implicit, not an
  explicit request (`cd /tmp/.X11-unix`, an LXD/tmux socket dir, a dir
  under /proc//sys//dev or a socket-bearing dir is not auto-mounted;
  `--bind-socket "$PWD"` opts back in — read-write for a plain dir,
  read-only on connect-only ground, and a rw cwd of connect-only ground
  is refused like `-b`). EXCEPTION: when an explicit user bind COVERS
  the cwd, the refusal is silent — `--chdir` lands under the user's
  mount exactly as asked (the same `covers()` test picks the chdir
  target), and the "/tmp as cwd" note would be wrong; only the
  automatic mount is skipped. The refused cwd's pin is RELEASED (see the
  no-fd-leak invariant above). A cwd inside `$HOME` with `--home` skips
  validation entirely (the `--home` notes cover it) but is still pinned,
  so its mount is fd-based like the rest.
- Read-write binds covering known `$HOME` persistence paths
  (`persistence_paths`: shell rc/session files, `authorized_keys`, systemd
  user units, XDG autostart + `environment.d`, `~/.local/share/applications`
  (.desktop `Exec=`), `~/.config/nvim`, `~/.local/bin`, `~/.cargo/bin`,
  `~/go/bin`, `~/.gitconfig`) print a WARNING naming the paths — matched in
  **both directions** (`covers(rp, q) or covers(q, rp)`), so
  `-b ~/.local/bin/mytool` warns like `-b ~/.local/bin`; refused would just
  lag reality; `--home`'s own notes cover the whole-home case. The note is
  keyed on the final MOUNT MODE (`_persistence_warning`): a
  `--bind-socket` DIRECTORY that resolves to `--bind` warns identically —
  never gate it on the CLI label again. `$XDG_CONFIG_HOME`/
  `$XDG_DATA_HOME` are realpath'd inside `persistence_paths` for the same
  reason `CONTROL_SOCKETS` entries are. Read-only binds stay silent.
- bwrap argv order matters: the automatic cwd bind is emitted **before** user
  binds (a later bind shadows an earlier one at the same target), so explicit
  `-r "$PWD"` wins over the default read-write cwd.
- Signals: `early_signal` (startup) → `forward` (bwrap does NOT relay
  signals — SIGINT/SIGTERM kill bwrap, `--die-with-parent` then SIGKILLs
  the payload; the escalation branch in `forward` is only for the window
  where bwrap lingers; graceful shutdown would need a `--info-fd`
  child-pid relay) → `SIG_IGN` during cleanup so `$WORK` removal cannot be
  interrupted. The proxy dies with the launcher (PR_SET_PDEATHSIG + ppid
  check); bwrap gets `--die-with-parent`.
- `rm_tree_writable` chmods through `O_PATH|O_NOFOLLOW` fds and the
  `/proc/self/fd/N` magic link, never through paths: a symlink planted in
  the sandbox's `/tmp` cannot redirect a chmod onto a host file
  (`O_NOFOLLOW` pins the LINK itself, `S_ISLNK` entries are skipped —
  rmtree removes them unfollowed), and O_PATH (not O_RDONLY: opening a
  dir O_RDONLY needs read permission the owner lacks there) is what keeps
  a mode-0000 directory from failing EACCES, being skipped and LEAKING
  the whole `$WORK`. Sockets, FIFOs and vanished entries are skipped —
  `shutil.rmtree` removes them without following.

Seccomp specifics:
- **The syscall tables are hand-typed** — a wrong number silently denies the
  wrong syscall (this shipped once: ioctl=29/shmget, unshare=310/
  process_vm_readv on x86_64; and in this revision's draft:
  vmsplice=316/278, fanotify_init=290/262). Three layers pin it down:
  `seccomp_selfprobe` (called by `seccomp_fd_args` on EVERY launch — the
  filter is installed in a forked child via prctl and the libc
  `unshare()`, `ioctl(TIOCSTI)`, `socket(AF_VSOCK)`, `personality()` and
  `ptrace()` wrappers must all come back EPERM; name→number ground truth
  verified on the user's machine, not only in the test suite; dies
  otherwise — `--no-seccomp` is the explicit opt-out). The probe SAMPLES
  five entries — the rest of the table is pinned only by the test suite,
  so run `tests/test_seccomp.py` after touching `SECCOMP_SYSCALLS`.
  That suite checks every entry against kernel headers /
  `scmp_sys_resolver` / `ausyscall`, and its runtime probe installs the
  real filter in a forked child and calls `unshare(0)` / `ioctl(TIOCSTI)`
  / `ptrace(ATTACH)` / `personality(0)` / `vmsplice` through the
  **C library wrappers** (name→number ground truth, so the table cannot
  fool its own probe).
  Extend the table only together with the test (interpreter golden cases
  included).
- `socket()` is family-gated to `SOCKET_FAMILIES` (AF_UNIX/INET/INET6/
  NETLINK, the Flatpak set) — AF_VSOCK bypasses netns isolation in VM
  guests on older kernels. Kill actions use `SECCOMP_RET_KILL_PROCESS`
  (whole thread group), and x32 (same audit arch, nr bit `0x40000000`) is
  killed explicitly on x86_64.
- **`--as-pid-1` in the bwrap argv is load-bearing** — never remove it:
  bwrap otherwise keeps its own *unfiltered* zombie-reaper init as pid 1
  (the command's parent); on Yama ptrace_scope=0 systems that init can be
  `/proc/1/mem`-injected, which no syscall ban covers. Trade-offs: orphaned
  grandchildren are not reaped while pid 1 lives (long-running commands
  that abandon children accumulate zombies), and signals sent to pid 1
  from inside are ignored unless handled (pid-namespace init semantics).
  External teardown is unaffected.
- The BPF rule blocks must each **reload the syscall number** before their
  fall-through label (`clone` and `ioctl` both do; A holds an argument
  otherwise, and the next number-match rule misfires). The interpreter test
  (`test_bpf_interpreter_golden_cases`) walks the compiled program and
  catches stale-register fall-throughs — extend its cases when adding rules.
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
  toolchains keep working. Installation is **fail-closed**: an
  unsupported architecture or a bwrap without seccomp support kills the
  launcher (`--no-seccomp` is the explicit opt-out; the old
  fail-open-with-warning path and its `--require-seccomp` crutch are
  gone — never reintroduce a "run unfiltered with a warning" mode).
