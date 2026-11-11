# AGENTS.md

`sbox` is a Linux Go command at the repository root. It runs a command in
bubblewrap with network access restricted by a host-side SOCKS5/HTTP CONNECT
proxy. The Go module uses only the standard library; build with Go >= 1.26 and
`CGO_ENABLED=0`. Host runtime dependencies are `bwrap` and `socat` (`--net`
needs only bwrap). There is no separate interpreter or reference implementation.

## Development

Run from the repository root:

```sh
go vet ./...
go test ./...
CGO_ENABLED=0 go build ./...
go test -race ./...           # requires a C compiler
```

Tests use local TCP/Unix sockets and PTYs. A restricted runner may block
these; do not mistake permission failures for application failures. Live
sandbox tests require unprivileged user namespaces. Seccomp tests install
filters in a re-executed child and also interpret bytecode without bwrap.
Missing foreign architecture headers or ausyscall may skip cross-checks;
native contract tests and checked-in golden fixtures must always run.

Useful live checks, after building `./sbox`:

```sh
./sbox -a example.com -v -- curl -sI https://example.com
./sbox -- curl -sI https://example.com                  # must be denied
./sbox --filter-output -- printf 'visible\n'
./sbox --shell
```

Use gofmt. Keep prose near 100 columns. Behavior changes must update package
comments, the root README, CLI help/epilog in `internal/cliutil`, and relevant
tests together. Every new value-taking CLI option MUST appear in
`cliutil.OptsWithValue`; `SplitArgv` otherwise misidentifies the command.
ShortWithValue is derived from it. Reject abbreviated options and clustered
short flags; attached short values such as `-bPATH` remain supported.

## Architecture

- `cmd/sbox`: CLI, dependency/capability checks, and hidden `--_selfprobe` dispatch.
- `internal/allow`: allowlist, SSRF filtering, and no_proxy routing.
- `internal/proxy`: host-side in-process proxy and fail-closed protocol self-test.
  Upstream credentials remain in memory. Its Unix socket is read-only bound at
  `/run/proxy.sock`; the sandbox's socat bridge exposes `127.0.0.1:1080`.
- `internal/sandbox`: backend-neutral mount specification and supervisor.
  Only `internal/sandbox/bwrap` knows bwrap flag spellings and fd numbering.
  Default Overlay ops render as a TWO-LEVEL launch there (trusted staging
  sandbox + the real sandbox); staging is invisible to the payload.
  Explicit --overlay-mode single uses PathOverlay ops with documented source
  races and no configurable storage cap; never select it as a fallback.
- `internal/bindpolicy`: path protection, fd-first validation, pinned mounts,
  and overlay validation.
- `internal/outputfilter`: sanitizer, PTY, and input/output pump.
- `internal/seccomp`: syscall tables, cBPF compiler, and launch-time self-probe.
- `internal/notes`: advisory notes suppressed for 24 hours under the cache dir.

## Network invariants

- Check the allowlist BEFORE DNS. Denied names must never be resolved.
- Resolve allowed names host-side and reject private, loopback, link-local,
  CGNAT, multicast, reserved and unspecified answers. IPv4-mapped IPv6, NAT64
  and 6to4 are checked against the embedded IPv4; Teredo is refused entirely.
  Only explicit IP/CIDR entries and names marked `!private` bypass this guard.
- Reject catch-all/effectively-global entries, malformed names and CIDRs with
  host bits set. Warn about single-label suffix entries such as `com`.
- no_proxy selects direct/upstream routing only; it never bypasses the allowlist
  or SSRF checks. Lowercase no_proxy takes precedence over NO_PROXY.
- Upstreams receive locally checked IP literals, never the requested hostname.
  Preserve any tunnel bytes buffered during the HTTP/SOCKS handshake.
- Plain HTTP forwards exactly one declared Content-Length body, rewrites Host
  from the checked URL, rejects ambiguous framing/Transfer-Encoding/invalid
  headers, and drops hop-by-hop headers. Forward responses concurrently with
  uploads so 100 Continue and early rejections work. A pipelined second request
  must never reach the origin. Half-close only transports that support it;
  never send a raw TCP half-close underneath a TLS connection.
- Quote attacker-controlled names, redact upstream credentials, and sanitize
  X-Sbox-Error to a single line. Never emit untrusted terminal controls raw.

## Binds and capabilities

- Probe `bwrap --help` once in main, never lazily in the supervisor. Tests use
  shims whose --help can hang. Capabilities are probed, not inferred from
  versions: options are backported. Unknown caps have conservative defaults.
- With supporting bwrap, probe the SAME namespace/pid/session flags as launch
  before adding `--unshare-user --disable-userns --assert-userns-disabled`.
  Explicit --unshare-user is necessary: --unshare-all only requests a try.
  Unsupported combinations fall back to the seccomp namespace deny rules with
  a note; lack of seccomp support fails closed unless --no-seccomp is explicit.
- Resolve user paths to absolute realpaths, pin FIRST with component-by-component
  `openat(O_PATH|O_NOFOLLOW)`, then validate that pinned object. Reject every
  symlink encountered by the pin walk. fstat, socket scanning rooted at the fd,
  and the kernel's /proc/self/fd readlink must describe the validated source.
  The object validated is the object mounted. Rename/swap/delete or pin errors
  fail closed. Missing -b/-r sources fail; only --bind-socket may remain missing
  and use bwrap's path-based not-found error.
- Only fds NAMED in bwrap argv may reach the child through ExtraFiles. Release
  refused/unused cwd pins. A leaked O_PATH fd lets /proc/self/fd/N/.. walk the
  HOST mount tree (CVE-2024-21626 class). Repeated uses of one pin get distinct
  duplicated fds so bwrap's per-operation closes cannot invalidate later mounts.
- System trees, private work dirs and runtime sockets use path-based mounts.
  Old bwrap uses path-based user mounts with a loud TOCTOU note.
- Refuse binds covering protected paths and all descendants of /proc, /sys and
  /dev. The resolved XDG_RUNTIME_DIR is a protected root even outside /run.
- Match known control sockets/directories in BOTH directions after realpath:
  parent dirs and sibling files in daemon dirs are equally dangerous. These
  protections are never overridden by --bind-socket.
- Also refuse socket files, runtime-dir paths and directories containing sockets
  by default. Socket scanning is depth/entry bounded, counts directories, and
  reports incomplete scans (the accepted residual limit). --bind-socket opts
  into these shape/scan rules: socket files/runtime paths always read-only;
  plain socket-bearing directories read-write unless explicitly -r. Never allow
  -b PATH --bind-socket PATH to make connect-only ground writable.
- The automatic cwd goes through the same validator. A refusal warns and falls
  back to /tmp, except when an explicit bind covers cwd (then chdir uses it and
  the fallback warning would be wrong). Cwd under HOME requires --home or an
  explicit bind. --home exposure and -b HOME --home get appropriate notes.
- Emit automatic cwd mounts BEFORE explicit user binds, so -r "$PWD" wins.
- --overlay sources reuse the whole bind validation (protected paths,
  control sockets, socket shape, bounded scan) with NO opt-in, must be
  pinned directories for validation (a nil pin refuses),
  and may not overlap each other, --home, or any explicit bind. An
  overlay covering cwd replaces the automatic cwd mount (chdir lands in
  the merged view); a cwd outside every overlay auto-mounts READ-ONLY
  while overlays are in use — that downgrade is noted loudly.
- bwrap (0.11) resolves overlay sources by PATHNAME and its --size only
  bounds --tmpfs. Default --overlay-mode staged launches a two-level arrangement:
  an unprivileged STAGING bwrap (fresh pid/ipc/uts/net namespaces, own
  /proc and /dev, host root mirrored read-only) creates a private staging
  tmpfs at /tmp. ALL mount sources get independent staging paths: validated
  pins mount from their fds, overlay lowers are read-only, and ordinary
  binds retain their requested modes. Never reuse original host paths as
  staging destinations: even a read-only host-root mirror follows renames.
  A separate single size-bounded tmpfs holds fresh upper/work dirs per
  overlay; the staging payload is the real
  sandbox bwrap, which re-binds the staged paths and overlays them. The
  seccomp filter rides along as staged bytes (--file) that a FIXED
  shell bridge opens as fd 3; the real bwrap still installs it as its
  last step before exec. Staging paths, pivot leftovers and setup
  descriptors must never reach the payload. A bounded runtime probe
  runs the complete arrangement with the production system runtime mounts,
  network mode, namespace flags and filter before any overlay launch;
  on failure REFUSE — never substitute path-based
  overlay sources.
- Explicit --overlay-mode single is the only exception to overlay mount pinning:
  retain fd-first validation, then release overlay pins and emit PathOverlay ops.
  A single bwrap reopens these sources by pathname with --tmp-overlay; warn on
  EVERY run that a concurrent host swap can redirect the mount to unvalidated
  ground and that only the kernel default tmpfs limit applies. Reject explicit
  --overlay-size in this mode. Never pass overlay source fds into the child.
  Ordinary bind pins, seccomp, namespace/session flags and network policy stay
  intact. Probe this exact mode with production mounts/flags/filter and refuse
  on failure. Neither mode may fall back to the other.
- Warn on read-write mounts overlapping known home persistence paths in BOTH
  directions, including --bind-socket directories. Read-only binds stay silent.
  These warnings are keyed on final mount mode, not the CLI label.

## Seccomp invariants

- bwrap installs the raw cBPF filter through --add-seccomp-fd/--seccomp as its
  LAST step before exec. The pipe contains 8-byte sock_filter instructions,
  with NO length prefix. Never install it from an in-sandbox helper: the shell,
  bridge, command and every descendant must be filtered from first instruction.
- Keep --as-pid-1. Otherwise bwrap leaves an unfiltered reaper inside, injectable
  through /proc/1/mem on ptrace_scope=0 hosts. The filtered command may also
  access its descendants on ptrace_scope=1 hosts: no unfiltered descendants.
- Hand-typed syscall numbers must be checked against kernel headers/ausyscall,
  compiled-bytecode fixtures, and interpreter cases. Extend tests with rules.
  A wrong number silently denies the wrong syscall. Every launch also self-probes
  using a re-executed, OS-thread-locked child and kernel-derived syscall.SYS_*
  constants. Probe failure, unsupported architecture or failed installation dies.
- Deny-list: unlisted syscalls remain allowed. ENOSYS only where callers have
  fallbacks (clone3/io_uring), EPERM otherwise. Socket families are limited to
  AF_UNIX/INET/INET6/NETLINK. Foreign ABIs and x32 are killed with KILL_PROCESS.
- Reload the syscall-number accumulator before falling through argument rules.
  ioctl and personality compare low 32 bits, matching kernel truncation.
  personality(0xffffffff) queries stay allowed; changes are denied.
- ptrace/process_vm_* are defense in depth. Debuggers require --no-seccomp.

## Output and lifecycle

- Interactive stdin/stdout/stderr automatically use a private PTY with raw output.
  A private read-only copy of sbox runs --_terminal-exec after bwrap installs
  seccomp, claims the fresh slave as its controlling terminal, then execs the
  bridge in place as PID 1. Terminal sessions (automatic interactive and
  --filter-output with a host tty on stdin) run the payload as the bridge's
  foreground child instead of exec'ing it (PID 1 drops default-disposition tty
  signals; exec-in-place silently swallowed Ctrl-C for direct commands; the
  child tail also echoes the status so dash/bash cannot tail-exec the payload
  back into PID 1). Keep --new-session and --as-pid-1; do not introduce an
  unfiltered helper or reaper. No host terminal descriptor may enter this mode.
  Forward input/resizes and restore host termios on every exit.
  Preserve direct I/O for pipes/redirections unless --filter-output is explicit.
- Explicit --env values never appear in argv: the bwrap backend receives them
  as Spec.EnvData and hands them over by fd (--ro-bind-data; staged overlays
  ferry the pipe through the staging sandbox like the seccomp filter). A
  read-only helper copy (/run/sbox-envexec --_env-exec) applies the
  NUL-framed records over the --setenv defaults and execs the bridge in place,
  still PID 1 and filtered. A --setenv VALUE would publish forwarded secrets
  in the world-readable /proc/<pid>/cmdline for the whole sandbox run; fail
  closed when bwrap lacks --ro-bind-data.
- Under --filter-output, stdout/stderr are a PTY slave; the host terminal fd must
  NEVER enter the sandbox. Stdin uses that slave only for a host tty successfully
  put in raw mode; non-tty input is inherited byte-exact. An untameable tty is a
  loud refusal before spawn. Closed output pipes must not kill the supervisor.
- Restore termios FIRST during cleanup. Forward SIGWINCH. Backpressure terminal
  input at a bounded backlog instead of dropping bytes. Queue shutdown must be
  synchronized with in-flight writes. Post-exit drain has a deadline because a
  daemonized child can keep the slave open indefinitely.
- Sanitization is an ALLOWLIST: printable text, newline/carriage return/tab,
  and safe SGR parameters ([0-9;]{0,64}, no conceal). Drop other controls and
  dangerous/invisible characters. C1 characters are not sequence starters.
  Controls interleaved with pending escapes follow the documented state machine.
  --strict-crlf implies filtering and holds CR until the NEXT byte: only CRLF
  passes. Flush drops a pending bare CR. Both modes must be chunk-split invariant.
  Matching foreground/background colors can still hide text; document this limit.
- Startup signals, signal forwarding, and cleanup suppression are distinct phases.
  bwrap does not relay signals: killing it triggers --die-with-parent teardown.
  This is hard termination, not graceful payload shutdown. The in-process proxy
  dies with the launcher. Serialize sanitizer state separately from sink writes;
  teardown must not wait for a blocked log sink.
- Work-tree cleanup uses O_PATH|O_NOFOLLOW fds and fstat before chmod through
  /proc/self/fd/N. Never chmod a sandbox-planted symlink's target. Mode-0000
  directories must still be removable; skip sockets/FIFOs and vanished entries.
