// Package oracle gives the differential cross-check tests a handle on the
// Python reference implementation (sbox.py): where to find it, how to run
// batch one-shot probes against it, and how to start its proxy server as a
// real subprocess.
//
// The Go port is the future; sbox.py is the present that users still run.
// While both exist, every package that ports a Python surface keeps a
// *_diff_test.go that feeds identical inputs to both implementations and
// compares the outputs — the zzdiff scratch harness of the porting effort,
// made permanent. Everything here fails soft: when python3 or sbox.py is
// not available the tests skip (override with $SBOX_PY / $SBOX_PYTHON), so
// the suite stays green on machines without the oracle.
//
// This package is test support and imports nothing from sbox itself.
package oracle

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// SboxPy returns the path of the Python reference implementation, if one
// is installed. Precedence: $SBOX_PY, then the repo's sbox.py found by
// walking up from the working directory (packages live at
// go/internal/<pkg>, so the repo root is three levels up — a fixed
// one-or-two-level lookup silently picks up an older INSTALLED sbox.py
// from ~/.local/bin, which is not the spec under port), then
// ~/.local/bin/sbox.py (where config/sync.py installs it). The bool is
// false when no candidate exists — callers skip.
func SboxPy() (string, bool) {
	if p := os.Getenv("SBOX_PY"); p != "" {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, true
		}
		return "", false
	}
	if wd, err := os.Getwd(); err == nil {
		for d, i := wd, 0; i < 8 && d != string(filepath.Separator); d, i = filepath.Dir(d), i+1 {
			c := filepath.Join(d, "sbox.py")
			if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
				return c, true
			}
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		c := filepath.Join(home, ".local", "bin", "sbox.py")
		if st, err := os.Stat(c); err == nil && st.Mode().IsRegular() {
			return c, true
		}
	}
	return "", false
}

// Python returns the interpreter to use ($SBOX_PYTHON, default python3).
func Python() (string, bool) {
	bin := os.Getenv("SBOX_PYTHON")
	if bin == "" {
		bin = "python3"
	}
	p, err := exec.LookPath(bin)
	if err != nil {
		return "", false
	}
	return p, true
}

// Available reports whether the whole oracle can run.
func Available() bool {
	_, okPy := SboxPy()
	_, okBin := Python()
	return okPy && okBin
}

// RunBatch runs a python driver script with sbox.py importable as module
// "sbox", feeding it one JSON request per stdin line and collecting one
// JSON response per stdout line. The script sees sys.argv[1] = the sbox.py
// path. This is the shape of the scratch zzdiff harness: one interpreter
// startup for the whole corpus, deterministic JSONL in and out.
func RunBatch(script, stdin string) (string, error) {
	py, ok := Python()
	if !ok {
		return "", fmt.Errorf("no python3")
	}
	sbox, ok := SboxPy()
	if !ok {
		return "", fmt.Errorf("no sbox.py")
	}
	// -B: never write __pycache__ next to whichever sbox.py resolved —
	// the repo root is the normal resolution target and test runs must
	// not litter it (a go/sbox.py COPY was once left behind to dodge
	// this and silently shadowed the repo's file in the walk-up — the
	// stale-spec trap this comment is a headstone for).
	cmd := exec.Command(py, "-B", "-c", script, sbox)
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("oracle failed: %v: %s", err, ee.Stderr)
		}
		return "", err
	}
	return string(out), nil
}

// Driver is the batch driver every differential test uses. It imports
// sbox.py under the fixed name "sbox" and evaluates the given expression
// per stdin line, where "req" is the decoded JSON request. Responses are
// ["OK", value] or ["ERR", message]; die() is patched to raise ValueError
// so error paths return instead of exiting.
const Driver = `
import sys, json, importlib.util
spec = importlib.util.spec_from_file_location("sbox", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.die = lambda msg: (_ for _ in ()).throw(ValueError(msg))
expr = EXPR
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        r = eval(expr, {"m": m, "req": json.loads(line)})
        print(json.dumps(["OK", r], sort_keys=True))
    except SystemExit:
        print(json.dumps(["ERR", "SystemExit"]))
    except Exception as e:
        print(json.dumps(["ERR", str(e)]))
`

// DriverFor returns Driver with EXPR replaced.
func DriverFor(expr string) string {
	return replaceOnce(Driver, "EXPR", jsonQuote(expr))
}

func replaceOnce(s, old, new string) string {
	for i := 0; i+len(old) <= len(s); i++ {
		if s[i:i+len(old)] == old {
			return s[:i] + new + s[i+len(old):]
		}
	}
	return s
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// Help renders sbox.py's own --help through THIS interpreter's argparse
// with PROG patched to "sbox" and COLUMNS pinned to 80 (the deterministic
// piped rendering; argparse re-wraps on a real terminal). The Go port's
// help snapshot is byte-compared against this by TestDifferentialUsage.
func Help() (string, error) {
	py, ok := Python()
	if !ok {
		return "", fmt.Errorf("no python3")
	}
	sbox, ok := SboxPy()
	if !ok {
		return "", fmt.Errorf("no sbox.py")
	}
	const script = `import sys, io, contextlib, importlib.util
spec = importlib.util.spec_from_file_location("sbox", sys.argv[1])
m = importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)
m.PROG = "sbox"
buf = io.StringIO()
with contextlib.redirect_stdout(buf):
    try:
        m.parse_cli(["--help"])
    except SystemExit:
        pass
sys.stdout.write(buf.getvalue())
`
	cmd := exec.Command(py, "-B", "-c", script, sbox)
	cmd.Env = append(os.Environ(), "COLUMNS=80")
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("oracle help failed: %v: %s", err, ee.Stderr)
		}
		return "", err
	}
	return string(out), nil
}

// StartProxy starts sbox.py's proxy as a subprocess, exactly the way the
// production launcher does: `sbox.py --_proxy SOCK CFG PPID` with the
// config (allows/upstream/verbose) in a 0600 JSON file. cfg must marshal
// to the proxy's config dict. The returned process serves the Unix socket
// at sockPath; callers must Kill it and remove the socket when done.
func StartProxy(sockPath, cfgJSON string) (*exec.Cmd, error) {
	py, ok := Python()
	if !ok {
		return nil, fmt.Errorf("no python3")
	}
	sbox, ok := SboxPy()
	if !ok {
		return nil, fmt.Errorf("no sbox.py")
	}
	cfgPath := sockPath + ".cfg"
	if err := os.WriteFile(cfgPath, []byte(cfgJSON), 0o600); err != nil {
		return nil, err
	}
	cmd := exec.Command(py, sbox, "--_proxy", sockPath, cfgPath,
		fmt.Sprint(os.Getpid()))
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return cmd, nil
}

// WaitListening polls the socket with a real connect, like sbox.py's
// wait_for_socket: the socket file appears at bind() time, before
// listen(), so existence alone is not enough.
func WaitListening(sockPath string, proc *exec.Cmd, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(sockPath); err == nil {
			if c, derr := net.DialTimeout("unix", sockPath, time.Second); derr == nil {
				_ = c.Close()
				return nil
			}
		}
		if proc != nil && proc.ProcessState != nil {
			return fmt.Errorf("the oracle proxy died at startup")
		}
		time.Sleep(20 * time.Millisecond)
	}
	return fmt.Errorf("the oracle proxy did not come up")
}
