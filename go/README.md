# sbox (Go port)

Run a command in a bubblewrap sandbox whose only network egress is a
host-side, allowlist-checking SOCKS5 + HTTP-CONNECT proxy.

This is a faithful Go port of `sbox.py` — same spec, same flags, same
fail-closed guarantees. It does **not** replace `sbox.py`; the two
implementations live side by side and are cross-checked against each other
by the differential test suite. Stdlib + `syscall` only, no third-party
libraries, built `CGO_ENABLED=0` as a hermetic static binary.

## Requirements

- Linux (the supervisor uses bwrap namespaces, ptys and seccomp)
- `bwrap` and `socat` on `$PATH` (probed at launch; see `sbox --help`)
- unprivileged user namespaces, for real sandbox runs (the unit tests do
  not need bwrap; several live tests skip inside containers)
- Go >= 1.22 to build

## Install

From this directory:

```sh
CGO_ENABLED=0 go build -o ~/.local/bin/sbox ./cmd/sbox
```

(The toolchain used to develop this port is installed via goenv; if a
non-interactive shell cannot find `go`, put
`~/.local/share/goenv/versions/<ver>/bin` on `$PATH` first.)

## Usage

The CLI is flag-compatible with `sbox.py` — `sbox --help` prints the full
epilog. The short version:

```sh
sbox -a example.com -v -- curl -sI https://example.com   # allow + log
sbox -- curl -sI https://example.com                     # must be denied
sbox --shell
```

## Deliberate deltas vs sbox.py

Everything not listed here is a faithful port (allowlist semantics,
sanitizer output, bwrap argv shape, seccomp filter bytes are pinned
byte-exact by the differential tests):

1. **In-process proxy.** sbox.py re-executes itself as a separate asyncio
   proxy process and passes credentials through a 0600 `proxy.json` under
   `$WORK`. Here the proxy is a goroutine in the launcher process: no
   re-exec, no `proxy.json`, upstream credentials never touch disk, and
   any launcher death (including SIGKILL) kills the proxy with it.
2. **Seccomp self-probe as self re-exec.** sbox.py forks to probe its
   filter; Go cannot safely return from a raw fork, so the binary
   re-executes itself with the hidden `--_selfprobe` flag. The probe
   syscalls use `syscall.SYS_*` numbers (kernel-header-derived ground
   truth), the analog of sbox.py's libc-wrapper guarantee. Same
   fail-closed exit-code vocabulary.
3. **Pure-Go DNS resolver** (`CGO_ENABLED=0`): exotic nsswitch backends
   (mdns, myhostname) will not resolve host-side. A cgo build is possible
   but not the default.
4. **Binary name `sbox`** — messages say `sbox:`; the Python original
   stays `sbox.py`. (Consequently the usage-line wrap differs — argparse
   wraps for the 7-char name — and `--help` is a fixed 80-column
   snapshot where argparse re-wraps to the terminal width. Everything
   else in the help text is oracle-pinned byte-exact, including the
   epilog's real control bytes, by `TestDifferentialUsage`.)
5. **Unicode table age**: Go's `unicode` tables trail CPython's, so a few
   recently assigned characters print for sbox.py and are dropped here —
   the fail-closed direction. The differential test tolerates exactly
   that direction and fails hard on the reverse.
6. **Message-shape micro-deltas**, each accepted during phase review and
   pinned by a normalized differential: `%q` where sbox.py uses `!r`
   (`"host":80` vs `'host':80`); Go-native OS-error text where sbox.py
   embeds an `OSError` string (no `[Errno N]` emulation); ASCII-only
   digit parsing in the proxy, with a Content-Length of more than 18
   digits refused.
7. **Once-a-day note stamps** live under `~/.cache/sbox/notes/` instead
   of `~/.cache/sbox/*.note`: the state does not interoperate with
   sbox.py's, so each binary shows a given note once a day
   independently.
8. **Two `--filter-output` corners**: no `UnicodeEncodeError` re-encode
   arm on non-UTF-8 host locales (output is UTF-8 regardless), and a
   stdin of a *closed* fd 0 is inherited as-is rather than replaced by
   `/dev/null` (python's `sys.stdin is None` corner cannot arise —
   `os.Stdin` always wraps fd 0).

## Development

```sh
go vet ./... && go test ./... && go build ./...
go test ./internal/seccomp -run CrossCheck    # needs kernel headers / ausyscall
go test ./... -run Differential               # needs python3 + sbox.py
```

The differential tests feed identical inputs to this port and to a real
`sbox.py` (located via `$SBOX_PY`, the repo's `sbox.py` found by walking up
from the test package, or `~/.local/bin/sbox.py`) and compare outputs
byte-exact; they skip cleanly when the oracle is absent. Live smoke tests
need a real host with unprivileged user namespaces, exactly like sbox.py:

```sh
go run ./cmd/sbox -a example.com -v -- curl -sI https://example.com  # allow + log
go run ./cmd/sbox -- curl -sI https://example.com                    # must be denied
go run ./cmd/sbox --filter-output -- sh -c 'printf "\033]52;c:aGk=\033\\visible\033[31m!\033[0m\n"'
go run ./cmd/sbox --shell
```

## Layout

One command (`cmd/sbox`: launcher + supervisor + hidden `--_selfprobe`
child) over backend-neutral packages — only `internal/sandbox/bwrap`
knows bwrap's flag spellings. `PLAN.md` is the full design document and
phase-by-phase history, including the invariant checklist from
`AGENTS.md` that every change must keep.

| Package | What it ports from sbox.py |
| --- | --- |
| `internal/cliutil` | `split_argv` / `parse_cli` (argparse semantics, no abbreviations, loud clustered-flag rejection) |
| `internal/allow` | allowlist parsing/matching, SSRF guard, `no_proxy` |
| `internal/proxy` | SOCKS5 + HTTP-CONNECT server, upstream chaining, self-test |
| `internal/seccomp` | syscall tables, cBPF builder, self-probe, filter fd |
| `internal/bindpolicy` | fd-first bind validation, control sockets, persistence warnings |
| `internal/sandbox` | Spec/Provider/Caps + the supervisor (signals, teardown) |
| `internal/sandbox/bwrap` | caps/userns probes, argv builder, fd accounting |
| `internal/outputfilter` | output sanitizer, pty pump, stdin filtering |
| `internal/notes` | once-a-day notes |
| `internal/oracle` | test support: runs sbox.py for the differential suites |
