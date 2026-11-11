package sandbox

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"

	"sbox/internal/cliutil"
)

// EnvFileDst is the in-sandbox path where the backend materializes the
// explicit --env records from the launcher fd (bwrap --ro-bind-data):
// the file's contents never appear in any process's command line, and
// only the sandbox ever sees them.
const EnvFileDst = "/run/.sbox-env"

// envExecHelperPath is the in-sandbox mount point of the private
// read-only copy of this executable that applies the handoff and execs
// the bridge (same arrangement as the terminal helper).
const envExecHelperPath = "/run/sbox-envexec"

// maxEnvData bounds the handoff file: the pipe feeding bwrap is written
// concurrently, but a handoff past 1 MiB could never survive execve's
// environment limits anyway — refuse it loudly at build time.
const maxEnvData = 1 << 20

// composeEnvData renders the explicit --env pairs as NUL-separated
// NAME\0VALUE\0 records for the fd handoff. NUL framing keeps values
// byte-exact (newlines, '=', quotes, control bytes) without ever
// interpolating them into shell code. Order is CLI order: the helper
// applies records sequentially, so a repeated name keeps the last
// value, and every record overrides the bwrap --setenv defaults.
func composeEnvData(pairs []cliutil.EnvVar) ([]byte, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	var b bytes.Buffer
	for _, p := range pairs {
		if p.Name == "" || bytes.ContainsAny([]byte(p.Name), "=\x00") ||
			bytes.ContainsAny([]byte(p.Value), "\x00") {
			// cliutil.parseEnv already enforces this; refuse here too
			// rather than emit a record the helper must misread.
			return nil, fmt.Errorf("internal: invalid --env record for %q", p.Name)
		}
		b.WriteString(p.Name)
		b.WriteByte(0)
		b.WriteString(p.Value)
		b.WriteByte(0)
	}
	if b.Len() > maxEnvData {
		return nil, fmt.Errorf("--env: the sandbox environment handoff exceeds %d bytes", maxEnvData)
	}
	return b.Bytes(), nil
}

// EnvExec is the hidden --_env-exec entry. It runs INSIDE the sandbox,
// after the backend installed the seccomp filter: read the handoff
// records at EnvFileDst, export each over the --setenv defaults, and
// exec argv in place — no values pass through a shell, a command line,
// or an unfiltered helper.
func EnvExec(argv []string) error {
	return envExec(EnvFileDst, argv)
}

// EnvExecFile is EnvExec against an explicit handoff file — the test
// seam for driving the exact production path (/bin/sh payload, applied
// records, exec) without a sandbox.
func EnvExecFile(file string, argv []string) error {
	return envExec(file, argv)
}

func envExec(file string, argv []string) error {
	if len(argv) == 0 {
		return errors.New("internal: --_env-exec requires a command")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("cannot read the sandbox environment handoff (%s): %w", file, err)
	}
	if err := applyEnvRecords(data); err != nil {
		return err
	}
	path, err := exec.LookPath(argv[0])
	if err != nil {
		return err
	}
	return syscall.Exec(path, argv, os.Environ())
}

// applyEnvRecords exports every NAME\0VALUE\0 record in order (later
// records with the same name win) and refuses malformed input: a
// handoff the launcher did not compose must fail loudly, not silently
// drop half the environment.
func applyEnvRecords(data []byte) error {
	nul := []byte{0}
	for len(data) > 0 {
		name, rest, ok := bytes.Cut(data, nul)
		if !ok {
			return errors.New("environment handoff ends mid-name")
		}
		value, rest, ok := bytes.Cut(rest, nul)
		if !ok {
			return fmt.Errorf("environment handoff has no value for %q", name)
		}
		if len(name) == 0 || bytes.ContainsAny(name, "=/") {
			return fmt.Errorf("environment handoff carries an invalid name %q", name)
		}
		if err := os.Setenv(string(name), string(value)); err != nil {
			return err
		}
		data = rest
	}
	return nil
}
