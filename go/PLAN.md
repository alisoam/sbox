# Plan: `sbox` in Go (stdlib only)

A faithful Go port of `../sbox.py` — run a command in a bubblewrap sandbox
whose only network egress is a host-side, allowlist-checking SOCKS5 +
HTTP-CONNECT proxy. **No third-party libraries**: `stdlib` + `syscall` only,
built `CGO_ENABLED=0` (hermetic static binary). The Python module docstring,
README and `../AGENTS.md` are the spec; every invariant, comment and
fail-closed guarantee carries over, and this port keeps them byte-faithful
where behavior is observable (allowlist semantics, sanitizer output, bwrap
argv shape, seccomp filter bytes).

The Go port lives in `go/` and does NOT replace `sbox.py` — both implement
the same spec; tests that pin shared behavior (sanitizer chunk equivalence,
seccomp tables, bind policy table) are ported so either implementation can
be checked against them.

---

## 1. What `cmd/` do we create?

**Exactly one command: `go/cmd/sbox` → binary `sbox`.** No subcommands; the
CLI surface is flag-compatible with `sbox.py` (same flags, same `--`
splitting, same epilog/help text, `allow_abbrev=False` semantics, clustered
short flags rejected loudly by the tokenizer).

Two Python-internal mechanics are re-modeled, both *invisible* to the user:

| sbox.py mechanism | Go replacement |
| --- | --- |
| the file re-executes itself as `--_proxy SOCK CFG PPID` (asyncio proxy is a separate process; config travels via a 0600 `proxy.json` that is unlinked after read) | **the proxy is a goroutine in the launcher process.** No re-exec, no `proxy.json` at all — upstream credentials stay in memory, never touching `$WORK`. Lifecycle gets *stronger*: any launcher death (incl. SIGKILL) kills the proxy with the process; the `PR_SET_PDEATHSIG` + ppid-check machinery becomes redundant. The Unix listener is still host-side and only the socket *file* is bound into the sandbox at `/run/proxy.sock`. |
| `seccomp_selfprobe` forks and does prctl + probe calls in the forked child (single-threaded in Python, trivial) | Go cannot safely return from a raw fork, and `PR_SET_SECCOMP` is per-thread — so the binary re-executes itself with a hidden flag: `sbox --_selfprobe` (a real `exec.Command(os.Args[0])`). The child receives the compiled filter bytes on stdin, does `PR_SET_NO_NEW_PRIVS` + `PR_SET_SECCOMP` (via `syscall.Syscall(SYS_PRCTL, …)`), then calls the probe syscalls **using `syscall.SYS_*` numbers from Go's `syscall` package** — kernel-header-derived ground truth our hand-typed table cannot fool, the exact analog of the libc-wrapper guarantee — and reports via the same exit-code vocabulary (3/30/31/32/33/34/4/5). |

So: `cmd/sbox/main.go` is the launcher, the supervisor, and (via the hidden
`--_selfprobe` re-exec) the probe child. The proxy needs no process at all.

> Host note: a Go toolchain is installed via goenv (`go 1.26.2` at
> `~/.local/share/goenv/versions/1.26.2/bin`; non-interactive shells may
> need it on $PATH explicitly). `go.mod` pins `go 1.22` (first version
> where everything needed is stable).

---

## 2. The bwrap abstraction (removable backend)

The supervisor, bind policy and seccomp pipeline are **backend-neutral**.
Only one package knows bwrap's flag spellings; everything else talks to an
interface. Swapping bwrap out later (a pure-Go `clone(CLONE_NEWUSER|…)`
backend, systemd-run, whatever) means writing one package.

```
internal/sandbox/sandbox.go   — Spec, Mount, Provider interface, supervisor
internal/sandbox/bwrap/       — the ONLY bwrap-aware code (probe, argv, notes)
```

### The contract

```go
// internal/sandbox

// Caps: what the backend can do. Probed ONCE in main() and carried in the
// options — never probed lazily inside the supervisor (a $PATH test shim
// must not be re-probed mid-launch; mirrors opts._bwrap_caps).
type Caps struct {
    BindFD        bool // fd-pinned mounts (--bind-fd / --ro-bind-fd)
    AddSeccompFD  bool // filter via fd, raw sock_filter bytes
    LegacySeccomp bool // older spelling, still via fd
    DisableUserns bool // kernel-level nested-userns kill
}

type Mount struct {
    Src string    // host path (informational; FD is authoritative when set)
    Dst string    // in-sandbox mount point
    RW  bool      // final mount mode — policy warnings key on THIS
    FD  *os.File  // pinned O_PATH fd from bindpolicy; nil ⇒ path-based
                  // (system trees, $WORK, runtime sockets: nothing to race)
}

type Spec struct {          // everything the launcher decided, validated:
    ShareNet      bool      // --net
    Env           []string  // HOME USER TERM PATH LANG, proxy vars, …
    SystemMounts  []Mount   // /usr ro, CA dirs, /etc/alternatives, …
    UserMounts    []Mount   // cwd mount FIRST, then user binds (order is
                            // load-bearing: later binds shadow earlier)
    Tmpfs         []Tmpfs   // /run 0755, $HOME 0700 when not --home
    Dirs          []Dir     // --dir + perms (XDG_RUNTIME_DIR)
    Chdir         string
    Bridge        string    // in-sandbox sh script (socat bridge, readiness
                            // loop, exec "$@") — backend-neutral text
    Seccomp       []byte    // raw sock_filter bytes (multiple of 8, no
                            // length prefix); nil ⇒ --no-seccomp
    Stdio         Stdio     // plain inherit vs pty slave + chosen stdin fd
}

type Launch struct {
    Argv    []string   // backend argv, "--" and payload appended by caller
    PassFDs []*os.File // EXACTLY the fds the argv names (bind-fd numbers +
                       // seccomp pipe read end); becomes cmd.ExtraFiles so
                       // Go itself guarantees the CVE-2024-21626 invariant
                       // (no stray O_PATH pin reaches the payload)
    CloseAfterSpawn []*os.File // dups for pins named twice in one argv
}

type Provider interface {
    Name() string
    Probe() (Caps, error)                    // bwrap --help grep, once
    UsernsProbe(shareNet bool) bool          // throwaway sandbox with the
                                             // SAME ns/pid/session flags
    Build(spec *Spec) (*Launch, error)       // argv + fd wiring
}
```

Why this shape:

- **Seccomp stays backend-neutral**: `internal/seccomp` produces raw filter
  *bytes* + runs the self-probe; the bwrap provider renders them as
  `--add-seccomp-fd N` / `--seccomp N` (a native backend would instead
  prctl them into the child pre-exec). Fail-closed lives in the shared code.
- **Bind policy stays backend-neutral**: `internal/bindpolicy` validates and
  pins; it hands the provider `(flag, realpath, fd)` triples exactly like
  `check_bind_paths`. Only the provider knows that a pinned fd is spelled
  `--bind-fd 3 /dest` and that a pin named twice needs one `os.Dup` per
  extra use (bwrap's per-op fd close ordering must never decide whether a
  later `--bind-fd N` resolves).
- **The supervisor stays backend-neutral**: spawn (`exec.Cmd` with
  `ExtraFiles` = `Launch.PassFDs`), signal forwarding, wait, `$WORK`
  teardown. `--die-with-parent`, `--new-session`, `--as-pid-1`,
  `--unshare-all` are bwrap's *opinions*; a future backend encodes them
  differently but the Spec fields (`AsPid1`, `NewSession`, … — folded into
  the provider today) map 1:1.

The one deliberate bwrap-ism outside the package: `userns_probe_ok` runs
`bwrap` with the real argv's namespace flags — that stays in the provider,
and the supervisor just calls `UsernsProbe(shareNet)`.

---

## 3. Package layout

```
go/
  go.mod                          module sbox; go 1.22; no requires
  cmd/sbox/main.go                ONE command: launcher + supervisor +
                                  hidden --_selfprobe child entry
  internal/cliutil/               split_argv, OPTS_WITH_VALUE trap list,
                                  flag parser (argparse semantics: no
                                  abbreviations, attached short values,
                                  =-forms, -- splitting, loud clustered-
                                  flag rejection), help/epilog text
  internal/allow/                 allowlist parsing/matching, SSRF guard,
                                  no_proxy — pure, table-tested:
                                  parse_allow_entry, load_allows,
                                  destination_allowed, private_allowed,
                                  bad_ip (net/netip; NAT64/6to4/Teredo
                                  embedding incl.), parse_no_proxy,
                                  no_proxy_matches
  internal/proxy/                 SOCKS5 + HTTP-CONNECT server (in-process
                                  goroutine), auto-detect by first byte,
                                  connect_destination ordering, upstream
                                  chaining (http/https/socks5/socks5h,
                                  Basic + RFC 1929 auth), one-shot plain-
                                  http forwarding, self-test
  internal/seccomp/               SECCOMP_SYSCALLS tables (x86_64, aarch64,
                                  riscv64), AUDIT_ARCH map, cBPF builder
                                  (KILL_PROCESS, x32 bit kill, socket
                                  family gate, ioctl low-word compares,
                                  personality 0xffffffff allow, ENOSYS vs
                                  EPERM sets, nr reload before fall-through
                                  labels), SelfProbe() (re-exec child),
                                  FilterFD() (pipe write + read end)
  internal/bindpolicy/            fd-first validation: OpenPathPinned
                                  (component-by-component Openat(O_PATH|
                                  O_NOFOLLOW), refuses ANY symlink),
                                  fdReaches (/proc/self/fd/N readlink must
                                  still name the validated path), Pinner
                                  (one fd per source; release refused
                                  cwds), containsSocket scan (depth/entry
                                  caps, /proc/self/fd-rooted), SYSTEM_DIRS,
                                  NO_DESCEND_ROOTS, CONTROL_SOCKETS
                                  (bidirectional covers, $HOME expanded
                                  WITHOUT resolving symlinks), persistence
                                  paths (both-direction warnings keyed on
                                  final mount mode), BindPolicyTable test
  internal/sandbox/               Spec/Mount/Provider/Caps + supervisor:
                                  early_signal → forward, SIG_IGN during
                                  cleanup, wait/exit-code propagation,
                                  rmTreeWritable (O_PATH fd walk, never
                                  paths), wait_for_socket
  internal/sandbox/bwrap/         bwrap Provider: caps probe, argv build
                                  (cwd mount BEFORE user binds, --chdir,
                                  inner sh script), userns probe, fd dup
                                  accounting, once-a-day fallback notes
  internal/outputfilter/          OutputSanitizer (byte-exact state
                                  machine port + chunk-boundary equivalence
                                  tests both modes), pty pump (open
                                  /dev/ptmx, TIOCSPTLCK/TIOCGPTN,
                                  non-blocking master, MAX_PENDING_INPUT
                                  backpressure, SIGWINCH → TIOCSWINSZ,
                                  deadline-bounded drain, termios restore
                                  first), filterChildStdin decision
                                  (raw-tty → slave; non-tty → the exact
                                  fd; none → /dev/null; untameable tty →
                                  LOUD refusal), early stdin check
  internal/notes/                 note_recently_shown / mark_note_shown
                                  (once-a-day stamps)
  internal/oracle/                test support for the differential
                                  cross-check: locates sbox.py +
                                  python3, batch "zzdiff" driver runner
                                  (JSONL in/out, die() patched into a
                                  catchable exception), and the Python
                                  proxy spawned exactly like the
                                  production launcher (--_proxy SOCK
                                  CFG PPID). Skips cleanly when the
                                  oracle is absent.
```

Each package that ports a Python surface also keeps a `*_diff_test.go`
feeding identical inputs to both implementations and comparing outputs
(byte-exact where the revisions share a spec, quote/status-line
normalized where they legitimately differ). This is the throwaway
`zzdiff` differential harness made permanent — it stays while sbox.py
still exists: `go test ./... -run Differential`.

`syscall` (stdlib) covers prctl/ioctl/termios/winsize/ptmx/Openat/O_PATH —
no golang.org/x/sys anywhere.

### Python symbol → Go package map

| sbox.py | Go |
| --- | --- |
| `split_argv`, `parse_cli`, epilog | `internal/cliutil` + `cmd/sbox` |
| `parse_allow_entry` … `bad_ip` | `internal/allow` |
| `Proxy`, `connect_destination`, `_one_shot*`, `self_test`, `parse_upstream` | `internal/proxy` |
| `parse_hostport`, `urlsplit` (via CONNECT targets / --upstream URLs) | `internal/proxy` (`pyparse.go`: quirk-faithful stdlib ports) |
| differential zzdiff harness + Python oracle | `internal/oracle` + `*_diff_test.go` |
| `SECCOMP_*`, `build_seccomp_bpf`, `seccomp_selfprobe`, `seccomp_fd_args` | `internal/seccomp` |
| `open_path_pinned`, `BindPinner`, `validate_bind_source`, `check_bind_paths`, `protected_paths`, `CONTROL_SOCKETS`, `persistence_paths`, `_contains_socket` | `internal/bindpolicy` |
| `build_bwrap`, `bwrap_caps`, `parse_bwrap_caps`, `userns_probe_ok` | `internal/sandbox/bwrap` |
| `run_sandbox`, `wait_for_socket`, `rm_tree_writable`, signal lifecycle | `internal/sandbox` (supervisor) + `cmd/sbox` |
| `OutputSanitizer`, pty pump, `_filter_child_stdin`, `_enter_raw_mode` | `internal/outputfilter` |
| `proxy_main`, `--_proxy` re-exec, `proxy.json` | **deleted** (goroutine) |
| `_note_stamp_path`, `note_recently_shown` | `internal/notes` |

---

## 4. Implementation phases

Each phase lands green (`go build ./... && go vet ./... && go test ./...`),
unit-testable without bwrap (pure functions + interfaces), in dependency
order:

**Phase 0 — skeleton.** `go.mod`; `internal/cliutil` (tokenizer + parser +
epilog port); `internal/notes`. Tests: every `split_argv` case from
`tests/test_sandbox.py` (attached values `-b/path`, `=`-forms, clustered
`-va` rejection, `--` splitting, `--_selfprobe` token shape skipped).

**Phase 1 — `internal/allow`.** Port the entry grammar exactly: suffix match
on dot boundaries, `:port` (incl. `[v6]:443`), IP/CIDR, `!private` marker,
catch-all rejection (`*`, `0.0.0.0/0`, effectively-global, host bits set —
loud, never widened), single-label warning, `$no_proxy` (lowercase wins,
`host:port` loses port, IP entries match literal destinations only, `*`).
`bad_ip` on `net/netip`: private/loopback/link-local/multicast/reserved/
unspecified/CGNAT **plus** NAT64 unwrap-and-recurse, 6to4 embedded-IPv4
judgment, whole-`2001::/32` Teredo refusal — port Python's `is_reserved`
coverage faithfully (240.0.0.0/4, 255.255.255.255, ::/8, …).
Tests: the full allowlist/no_proxy table from `tests/test_sandbox.py`, plus
the differential cross-check vs the installed sbox.py (`diff_test.go`:
parse_allow_entry, destination_allowed, bad_ip — the last against the live
CPython ipaddress module). **Status: landed, differential added with
Phase 2.**

**Phase 2 — `internal/proxy`.** Listener goroutine + per-conn goroutines;
first-byte 0x05 autodetect. Order is the spec: **allowlist → resolve
(SSRF-filtered) → connect** — denied names never resolved. SOCKS5
(no-auth, reply codes), HTTP CONNECT, absolute-form one-shot forward (Host
rewritten from the checked URL and emitted FIRST, RFC 9110 token-validated
header names, obs-fold refused, Transfer-Encoding refused, single
unambiguous Content-Length body, then half-close — `net.TCPConn.CloseWrite`;
TLS upstreams can't half-close, same documented exception), `X-Sbox-Error`
sanitized single-line, 15 s connect timeout, upstream chaining with
Basic/RFC 1929 auth and optional TLS skip-verify, `$no_proxy` route picking
(allowlist still applies), redact-userinfo logging, `!r`-style safe
hostnames in logs. `SelfTest()` dials the real socket, expects denial on
both protocols, before the sandbox starts.
Tests: in-process listener + fake origins/upstreams, plus the
**differential cross-check** (`diff_test.go`, `internal/oracle`): the
parse_hostport / parse_upstream corpora and a live protocol battery
(SOCKS5 replies, HTTP error bodies, CONNECT tunnels, upstream
handshake bytes incl. RFC 1929 auth and TLS skip-verify) run against
this port AND a real `sbox.py --_proxy` subprocess, compared byte for
byte. **Status: landed** (`internal/proxy`, `internal/oracle`).

**Phase 3 — `internal/seccomp`.** Tables verbatim (they are hand-typed —
a wrong number silently denies the wrong syscall; copy entry-by-entry),
builder preserving instruction order and every quirk, `SelfProbe` via the
`--_selfprobe` re-exec, `FilterFD`. Tests: golden BPF interpreter cases
ported from `test_seccomp.py` (catches stale-register fall-through), table
cross-check against kernel headers / `scmp_sys_resolver` / `ausyscall` when
present, and a live install-probe test (skip where seccomp is unavailable,
e.g. this container). **Status: landed** (`internal/seccomp`; the
differential test pins the filter bytes BYTE-EXACT against sbox.py's
build_seccomp_bpf for every machine, the kernel-header cross-check pins
the x86_64 table, and the live probe runs green in this container).

**Phase 4 — `internal/bindpolicy`.** O_PATH pinning walk, fd-first
validation, shape rules, control-socket bidirectional matching, `--bind-socket`
mount-mode semantics (ro for socket files/runtime paths — `-b P
--bind-socket P` refused; rw for plain dirs), missing `-b/-r` source dies,
`--bind-socket` of a missing runtime path keeps the path form, persistence
warnings keyed on final mount mode, refused-cwd pin release. Tests: port
`test_bind_policy_table` row-for-row (the machine-readable encoding of the
mount-mode promises) + the pin/race unit tests. **Status: landed and
reconciled against the real sbox.py** (`internal/bindpolicy` — initially a
reconstruction from PLAN.md + the epilog, then corrected against the
actual `validate_bind_source`/`check_bind_paths`/`open_path_pinned`/
`_contains_socket`: realpath-then-pin walk, `protected_paths(home)` (so
`-b /etc` IS refused, `-b $HOME` needs `--home`), the real CONTROL_SOCKETS
with realpath'd copies, realpath'd `$XDG_RUNTIME_DIR` runtime roots,
group-order flag composition with the `bound` dedupe, fail-open scan caps
with once-a-day notes, and unconditional refused-cwd pin release; the
`*_diff_test.go` compares `ValidateBindSource` against the Python in path
mode, refusal/warning/rp byte-exact).

**Phase 5 — `internal/sandbox` + `internal/sandbox/bwrap`.** Caps probe
(`--help` grep — versions lie), userns probe, argv builder (system mounts,
proxy-env branch vs `--share-net` branch, `--home` pinned realpath, gui,
ssh-agent, cwd-before-user-binds, `--chdir`, bridge script), ExtraFiles→
fd-number accounting (only argv-named fds pass; dups for twice-named pins
closed after spawn). Tests: argv golden tests against injected fake
`Provider`/caps — no real bwrap needed. **Status: landed** (`internal/
sandbox` = Spec-as-ordered-ops + Provider/Caps/Launch + BuildSpec, the
build_bwrap decision port incl. the cwd-mount validation/refusal flow and
AgentSocketPath/PayloadArgv; `internal/sandbox/bwrap` = ParseCaps
(word-boundary `has()`, no lookbehind in RE2), Probe/UsernsProbe (both
10 s-subprocess probes), and Build: seccomp fail-closed flag+fd FIRST,
userns hardening, fixed skeleton, 1:1 op rendering, and the fd accounting
— first use passes the original pin, every further use gets an os.Dup
(CloseAfterSpawn), child fds numbered 3.. via ExtraFiles so Go itself
enforces the CVE-2024-21626 invariant. Tests run against fake-bwrap
shims (probe argv recorded and compared token-exact), and
`bwrap/diff_test.go` compares the FULL argv + bridge against sbox.py's
build_bwrap across 8 scenarios — token-exact after canonicalizing fd
numbers (parent fds vs ExtraFiles numbering) and the documented
sbox.py→sbox self-name in the bridge warning).

**Phase 6 — supervisor + `cmd/sbox/main.go`.** Wire everything: workdir
(0700 mkdtemp, `sand/` subdir, ssh_config), proxy goroutine +
`wait_for_socket` + self-test + seccomp probe/fd + userns hardening +
notes, spawn, signal lifecycle (`early_signal` → `forward`; SIGINT/SIGTERM
kill bwrap, `--die-with-parent` SIGKILLs the payload; SIG_IGN during
cleanup so `$WORK` removal can't be interrupted), exit-code propagation,
`rm_tree_writable`. Verification: the AGENTS.md live smoke recipes on a
real host. **Status: landed** (`internal/sandbox/supervisor.go` +
`cmd/sbox/main.go`: the full run_sandbox port — the guarded $WORK block,
the in-process proxy behind WaitForSocket + SelfTest, the seccomp gate
(build the table → caps fail-closed check → `--_selfprobe` re-exec →
verbose note → bytes into the Spec), userns hardening with the
once-a-day fallback note, the no-`--bind-fd` TOCTOU note, the spawn via
Launch.Bin + ExtraFiles with parent copies closed right after, and a
teardown that ALWAYS runs (fd/pinner close, sandbox terminate→kill,
bounded proxy close, RmTreeWritable). Signals: one hub goroutine over
main's armed channel — setup phase records the early exit (checked at
every phase boundary, including right after the spawn, exactly where
python swaps early_signal for forward), run phase forwards and
escalates a repeat to SIGKILL, done phase IS the cleanup SIG_IGN (no
OS-disposition games: Go's Reset does not undo Ignore, and an
OS-level SIG_IGN would leak into children via exec). Exit codes:
128+signal for killed sandboxes, 128+signum for early signals, 1 for
every startup failure (`--filter-output` failed CLOSED here until
phase 7 landed the pty). `cmd/sbox/main.go` routes the hidden
`--_selfprobe` child, prints argparse-shaped usage errors (exit 2),
checks bwrap/socat/HOME, resolves `--shell`, parses allows + upstream
(`$SBOX_UPSTREAM`/`$https_proxy` fallback, `_env_flag` semantics) and
drives the Supervisor. Tests: full-run e2e + workdir shape against a
recording bwrap shim (external test package — the real provider imports
sandbox), the seccomp/userns/TOCTOU gates, forward/escalate/early
signal lifecycle, RmTreeWritable's 0000/0555/symlink cases and
WaitForSocket, plus cmd/sbox CLI tests; verified live on a
no-unprivileged-userns host: byte-identical notes vs sbox.py and no
$WORK leftovers.)

**Phase 7 — `internal/outputfilter`.** Sanitizer state machine ported
byte-exactly (allowlist: printable + `\n\r\t`, SGR `[0-9;]{0,64}` sans
conceal, everything else DROPPED never rewritten; C0 interleaved in a
pending escape EXECUTED; C1 dropped as characters; string openers
`]P_^X`; 4096 pending cap; stateful UTF-8 errors=replace; bidi/zero-width/
blank/variation-selector/CGJ drops with U+FE0F kept; strict_cr lookahead
split-invariant). Pty pump: goroutines + channels instead of asyncio/
select, non-blocking master, backpressured stdin forward, SIGWINCH,
deadline drain, termios restore first, `winch_installed` flag semantics,
early stdin check before anything spawns. Tests: port EVERY sanitizer test
from `test_sandbox.py` including the chunk-boundary equivalence property in
both modes. **Status: landed** (`internal/outputfilter` = sanitizer.go +
utf8.go (CPython-exact incremental decoder: one U+FFFD per invalid start
byte, per-byte for well-formed-but-illegal sequences (surrogates,
overlongs, >U+10FFFF), one per maximal subpart for truncation and broken
continuations — probed live against CPython 3.15 and pinned by
`TestDecoderByteForByteCPython` + the differential) + pty.go (OpenPty via
/dev/ptmx + TIOCSPTLCK/TIOCGPTN — the unlock is REQUIRED in some
containers; HostTTY/CopyWinsize/EnterRawMode = cfmakeraw+TCSAFLUSH =
this CPython's tty.setraw; RestoreTermios TCSADRAIN;
CheckStdinEarly/FilterChildStdin with the loud unrawable-tty refusal;
EmitDiag = _emit_diag with the `_raw_term` CR flag, now package-global
and set by EnterRawMode) + pump.go (master→sanitizer→stdout reader whose
EOF/eviction point owns the flush so it can never interleave a Feed —
reproducing sbox.py's master_eof quirk: EOF during the run skips drain
AND flush; deadline-bounded Stop(500ms) drains like _drain_master;
stdin forwarder reads a DUP of the raw host tty through a
chunked backlog capped at MAX_PENDING_INPUT with cond-var backpressure —
never drops; SIGWINCH→TIOCSWINSZ behind an RWMutex so a resize can never
race the fd teardown). Supervisor wiring: CheckStdinEarly at the top,
Setup between Build and the spawn (fail-closed die messages verbatim),
slave as the sandbox's only stdio + FilterChildStdin's fd as stdin,
parent's slave copy closed post-spawn, pump.Stop's 500ms drain before
hub.done, teardown restores termios FIRST; the proxy decision log under
--filter-output flows through its own Sanitizer + EmitDiag (python's
piped-stderr analog); cmd/sbox's errf routes through EmitDiag so raw-mode
diagnostics CR their newlines. Tests: the full behavior table (python-
verified expectations incl. the CSI-body subtleties: non-ASCII swallowed
without growing the pending seq, C1 swallowed then the sequence
completes), chunk-equivalence in both modes (all 2-way splits, per-byte,
random), the byte-counting cap in OSC bodies, pump e2e on real ptys
(filtering, drain-deadline flush, EOF-during-run no-flush, stdin
forward + backpressure boundedness, winsize, Close-restores-termios),
supervisor e2e (filter + strict-crlf + a grandchild's late drain output
through the 500ms window) and the whole-binary cmd/sbox run; the
differential pins the sanitizer byte-exact against the repo sbox.py over
a structured+random corpus under 5 chunkings × both strict modes, the
raw decoder against the live `codecs` incremental decoder, _char_allowed
against `str.isprintable` (tolerating ONLY the known Unicode-table-age
drift — Go 15.0.0 vs CPython 17.0.0 assignments, fail-closed direction —
and failing hard on anything Go passes that Python drops), and
_sgr_conceals. Verified live: the epilog recipe drops the OSC 52 write
and passes `visible\x1b[31m!\x1b[0m`, --strict-crlf drops bare \r, and
piped stdin round-trips byte-exact through the inherited fd.
Environment note: `go test -race` clean; the winch delta (signal.Stop
fully restores — no C-installed-handler ambiguity) and the forwarder's
parks-on-tty-read goroutine dying with the process are documented in
pump.go.

**Phase 8 — polish.** `go/README.md` (install: `CGO_ENABLED=0 go build
-o ~/.local/bin/sbox ./cmd/sbox`), review pass over AGENTS.md invariants
with the checklist below, full test run. **Status: landed** (`go/README.md`
with the complete delta list — the review extended it with the
phase-review micro-deltas (§5.6–8); the stale `go/sbox.py` oracle copy that
shadowed the repo's spec in the walk-up resolution is gone, and `RunBatch`
runs python `-B` so test runs never write `__pycache__` next to whichever
sbox.py resolved). The review also made the `--help` snapshot byte-exact
against the oracle: the options section now carries argparse's own
rendering (metavar once after the long form, help column 24) and the
epilog is an oracle-derived snapshot keeping python's real control bytes —
pinned permanently by `TestDifferentialUsage` via `oracle.Help()`, with
the prog name and the seccomp-probe paragraph as the only documented
wording deltas.

---

## 5. Deliberate deltas vs sbox.py (everything else is faithful)

1. **In-process proxy** (no re-exec, no `proxy.json`): strictly better —
   credentials never hit disk; lifecycle simplifies to "process dies ⇒ all
   dies". The `$WORK`-holds-credentials known-limit shrinks accordingly.
2. **Self-probe as self re-exec** (`--_selfprobe`): same fail-closed
   guarantee, no fork-in-runtime hazards; probe syscalls use
   `syscall.SYS_*` (kernel-header-derived) as the ground truth instead of
   libc wrappers.
3. **Pure-Go DNS resolver** (`CGO_ENABLED=0`): exotic nsswitch backends
   (mdns, myhostname) won't resolve host-side. Documented; a cgo build is
   possible but not default.
4. **Binary name `sbox`** (messages say `sbox:`); Python stays `sbox.py`.
5. **Unicode table age**: Go's `unicode` tables (15.0.0 today) trail
   CPython's (17.0.0), so characters assigned in between (CJK Ext H/I,
   Egyptian Hieroglyphs Ext-A, ...) print for sbox.py and are dropped
   here — the fail-closed direction. The differential test tolerates
   exactly that direction (verified against the live `unicodedata`
   category) and fails hard on anything this port passes that Python
   drops.
6. **Message-shape micro-deltas** (each phase-review-accepted, pinned by
   normalized differentials): `%q` where sbox.py uses `!r`; Go-native
   OS-error text where sbox.py embeds an `OSError` string; ASCII-only
   digit parsing, Content-Length > 18 digits refused.
7. **Note stamps** under `~/.cache/sbox/notes/` instead of
   `~/.cache/sbox/*.note` — once-a-day state does not interoperate with
   sbox.py's.
8. **`--filter-output` corners**: no `UnicodeEncodeError` re-encode arm
   (Go writes UTF-8 regardless of host locale); a closed fd 0 is
   inherited as-is instead of python's `/dev/null` (`os.Stdin` always
   wraps fd 0).

## 6. Verification (mirrors AGENTS.md)

```sh
cd go && go vet ./... && go test ./... && go build ./...
go test ./internal/seccomp -run CrossCheck   # needs kernel headers/ausyscall
go test ./... -run Differential              # needs python3 + sbox.py (skips without)
# live smoke tests need a real host (unprivileged userns), like sbox.py:
go run ./cmd/sbox -a example.com -v -- curl -sI https://example.com  # allow + log
go run ./cmd/sbox -- curl -sI https://example.com                    # must be denied
go run ./cmd/sbox --filter-output -- sh -c 'printf "\033]52;c:aGk=\033\\visible\033[31m!\033[0m\n"'
go run ./cmd/sbox --shell
```

## 7. Invariant checklist (from AGENTS.md — the port must keep every one)

- Allowlist before DNS, always; SSRF guard; fail loud, never widen; never
  print attacker bytes raw (`%q` hostnames, redacted URLs, sanitized
  `X-Sbox-Error`); one-shot plain-http with Host rewrite.
- Seccomp: fail-closed install, hand-typed tables pinned by tests AND the
  runtime probe, `--as-pid-1`, nr reload before labels, ioctl low-word,
  x32 kill, ENOSYS-only-with-fallbacks, deny-list + explicit opt-out.
- Binds: fd-first validation, validated fd == mounted fd, only argv-named
  fds pass (ExtraFiles enforce it), refused-cwd pin release, mount-mode
  promises per `test_bind_policy_table`, cwd mount before user binds.
- Caps probed once in main, never lazily; userns combo probed per launch,
  fallback note at most once a day.
- Output filter: allowlist (drop, never rewrite), split-invariant incl.
  strict_cr lookahead, pty slave only stdio, exact non-tty stdin fd,
  untameable tty refused, termios restore first.
- Signals: early → forward → SIG_IGN-during-cleanup; die-with-parent.
- `OPTS_WITH_VALUE` trap: any new value-taking flag lands in cliutil's
  list (single source of truth, `SHORT_WITH_VALUE` derived from it).
- Spec duplication rule: behavior changes update the package doc comments
  (the Go analog of the module docstring), the help/epilog, and the tests
  together.
