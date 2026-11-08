// Command sbox is the launcher: the CLI front end (cliutil), the
// dependency/capability probes, the --shell resolution, the allowlist
// and upstream parsing, and the driver for sandbox.Supervisor — plus,
// via the hidden --_selfprobe re-exec, the seccomp probe child
// (internal/seccomp.ProbeChild, the Go analog of sbox.py's fork-based
// seccomp_selfprobe). A faithful port of sbox.py's main(); the
// supervisor (internal/sandbox) owns everything from $WORK creation to
// teardown.
//
// The ONLY other argv this binary honors specially is --_selfprobe as
// argv[0]: like python's --_proxy re-exec, a --_selfprobe seen anywhere
// else is just a hidden, inert option (the tokenizer stays correct for
// any placement).
package main

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"sbox/internal/allow"
	"sbox/internal/cliutil"
	"sbox/internal/outputfilter"
	"sbox/internal/proxy"
	"sbox/internal/sandbox"
	"sbox/internal/sandbox/bwrap"
	"sbox/internal/seccomp"
)

func main() { os.Exit(run(os.Args[1:])) }

func run(argv []string) int {
	// The ONLY legitimate --_selfprobe caller is this binary re-executing
	// itself as the host-side seccomp probe child with exactly this argv
	// shape (the filter bytes arrive on stdin).
	if len(argv) > 0 && argv[0] == "--_selfprobe" {
		if len(argv) != 1 {
			return die("internal error: --_selfprobe takes no arguments")
		}
		seccomp.ProbeChild() // never returns
	}

	opts, command, err := cliutil.ParseCLI(argv)
	if err != nil {
		return parserError(err.Error())
	}
	if opts.Help {
		fmt.Print(cliutil.Usage)
		return 0
	}

	// Armed before anything slow (python relies on KeyboardInterrupt →
	// 130 for the pre-sandbox window; here the supervisor's early path
	// owns the same window — cleanup included — from Run() on).
	sigs := make(chan os.Signal, 4)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)

	if _, err := exec.LookPath("bwrap"); err != nil {
		return die("missing dependency: bwrap (needed on the host)")
	}
	// Probe bwrap's capabilities ONCE here (never lazily inside the
	// supervisor: a test shim on $PATH would not survive a second
	// `bwrap --help`); the provider carries the cached result.
	backend := bwrap.New("")
	_, probeErr := backend.Probe()
	// Python warns only when the PROBE FAILED (`not opts._bwrap_caps`
	// is true only for the {} the failure path returns — a bwrap whose
	// --help simply lacks every option still yields a truthy dict and
	// stays quiet here; the seccomp gate below then speaks with the
	// dedicated fail-closed message).
	if probeErr != nil && !opts.NoSeccomp {
		errf("warning: cannot determine this bwrap's capabilities (bwrap --help failed)")
	}
	if !opts.Net {
		if _, err := exec.LookPath("socat"); err != nil {
			return die("missing dependency: socat (needed on the host for the in-sandbox bridge)")
		}
	}
	if _, ok := os.LookupEnv("HOME"); !ok {
		return die("HOME is not set")
	}
	home := os.Getenv("HOME")

	if opts.Shell && len(command) > 0 {
		return parserError("--shell takes no command")
	}
	if opts.Shell {
		command = []string{pickShell(opts.Home, home, errf)}
	}
	if len(command) == 0 {
		return parserError("no command given (or use --shell)")
	}

	if opts.Net && (len(opts.Allow) > 0 || len(opts.AllowFile) > 0 || opts.HasUpstream) {
		errf("warning: --net shares the host network directly; -a/-A/--upstream are ignored")
	}

	allows, err := allow.LoadAllows(opts.Allow, opts.AllowFile, errf)
	if err != nil {
		return die(err.Error())
	}
	if !opts.Net && len(allows) == 0 {
		errf("warning: no --allow entries — ALL outbound connections will be denied")
	}

	raw := ""
	if opts.HasUpstream {
		raw = opts.Upstream
	} else {
		raw = firstNonEmpty(os.Getenv("SBOX_UPSTREAM"),
			os.Getenv("https_proxy"), os.Getenv("HTTPS_PROXY"))
	}
	upstream, err := proxy.ParseUpstream(raw,
		opts.UpstreamInsecure || envFlag("SBOX_UPSTREAM_INSECURE"))
	if err != nil {
		return die(err.Error())
	}

	exe, err := os.Executable()
	if err != nil {
		return die(fmt.Sprintf("cannot determine my own executable path (seccomp self-probe re-exec): %v", err))
	}

	sup := &sandbox.Supervisor{
		Opts:     opts,
		Command:  command,
		Allows:   allows,
		Upstream: upstream,
		Provider: backend,
		Exe:      exe,
		Warn:     errf,
		SigCh:    sigs,
		Home:     home,
	}
	return sup.Run()
}

// pickShell resolves --shell: $SHELL when it will exist inside the
// sandbox (a /usr//bin/ path, or anywhere under a --home-bound $HOME),
// else a loud fallback (python's note names the fallback shell).
func pickShell(homeBound bool, home string, errf func(string)) string {
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}
	usable := strings.HasPrefix(shell, "/usr/") || strings.HasPrefix(shell, "/bin/") ||
		(homeBound && strings.HasPrefix(shell, home+"/"))
	if !usable || !isRegularFile(shell) {
		fallback := "/bin/sh"
		if isRegularFile("/bin/bash") {
			fallback = "/bin/bash"
		}
		shell = fallback
		errf(fmt.Sprintf("note: $SHELL is not available inside the sandbox — falling back to %s", shell))
	}
	return shell
}

func isRegularFile(p string) bool {
	st, err := os.Stat(p) // like python's os.path.isfile: symlinks resolve
	return err == nil && st.Mode().IsRegular()
}

// envFlag is _env_flag: true only for explicit affirmative values
// (1/true/yes/on, case-insensitive, surrounding spaces stripped) — a
// bare SBOX_UPSTREAM_INSECURE=0 must not silently disable TLS
// verification; any non-empty string used to count as yes.
func envFlag(name string) bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(name))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}

// errf is python's err(): host-side diagnostic on stderr, best-effort
// (a closed stderr must not crash the launcher). Routed through
// outputfilter.EmitDiag so --filter-output's raw-mode phase CRs every
// newline (OPOST is off — sbox.py's _emit_diag/_raw_term).
func errf(msg string) {
	outputfilter.EmitDiag(fmt.Sprintf("%s: %s\n", cliutil.Prog, msg))
}

// die is python's die(): the message, then exit status 1.
func die(msg string) int {
	errf(msg)
	return 1
}

// parserError mirrors argparse's parser.error(): the usage block and
// "prog: error: msg" on stderr, exit status 2.
func parserError(msg string) int {
	fmt.Fprintf(os.Stderr, "%s\n%s: error: %s\n", usageBlock(), cliutil.Prog, msg)
	return 2
}

// usageBlock is the usage portion of the help text (argparse's
// print_usage prints just this part).
func usageBlock() string {
	if i := strings.Index(cliutil.Usage, "\n\n"); i >= 0 {
		return cliutil.Usage[:i]
	}
	return cliutil.Usage
}
