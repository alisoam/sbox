package sandbox

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"sbox/internal/cliutil"
)

func TestBuildSpecExplicitEnvironment(t *testing.T) {
	root, home, proj, _ := overlaySpec(t)
	t.Setenv("SBOX_NOT_FORWARDED", "host only")
	t.Setenv("HOME", home)
	value := "spaces ' quotes $(not-executed) =\nnext"
	opts := &cliutil.Options{Env: []cliutil.EnvVar{
		{Name: "SBOX_ENV", Value: "first"}, {Name: "SBOX_ENV", Value: value},
		{Name: "HOME", Value: "/tmp/custom-home"}, {Name: "EMPTY", Value: ""},
		{Name: "http_proxy", Value: "http://127.0.0.1:4321"},
		{Name: "SSH_AUTH_SOCK", Value: "/tmp/custom-agent"},
	}}
	spec, err := BuildSpec(opts, proj, filepath.Join(root, "sand"), filepath.Join(root, "sock"), home,
		nil, nil, "/host/agent.sock", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	// The explicit pairs ride the fd handoff: NONE of them may appear
	// as a Setenv op value, whose rendered bwrap argv
	// (/proc/<pid>/cmdline) is world-readable for the whole sandbox
	// run. (HOME/http_proxy/SSH_AUTH_SOCK also exist as DEFAULTS with
	// different values — those stay, the explicit values must not.)
	got := map[string]string{}
	privateHome := false
	for _, op := range spec.Ops {
		switch o := op.(type) {
		case Setenv:
			got[o.Name] = o.Value
		case Tmpfs:
			if o.Path == home {
				privateHome = true
			}
		}
	}
	for _, env := range opts.Env {
		if v, ok := got[env.Name]; ok && v == env.Value {
			t.Errorf("%s leaked its explicit value into the bwrap --setenv argv (%q)", env.Name, v)
		}
	}
	if _, ok := got["SBOX_NOT_FORWARDED"]; ok {
		t.Fatal("unrequested host variable forwarded")
	}
	// The sandbox defaults are still Setenv ops...
	for _, name := range []string{"HOME", "USER", "TERM", "PATH", "LANG"} {
		if _, ok := got[name]; !ok {
			t.Errorf("default Setenv %s missing", name)
		}
	}
	if !privateHome || os.Getenv("HOME") != home {
		t.Fatal("--env HOME changed host configuration or mount selection")
	}
	if spec.Bridge != InnerProxy+"exec \"$@\"\n" {
		t.Fatal("environment values changed the bridge script")
	}

	// ...and the handoff carries every pair in CLI order, byte-exact.
	want := bytes.NewBuffer(nil)
	for _, env := range opts.Env {
		want.WriteString(env.Name)
		want.WriteByte(0)
		want.WriteString(env.Value)
		want.WriteByte(0)
	}
	if !bytes.Equal(spec.EnvData, want.Bytes()) {
		t.Fatalf("EnvData = %q, want NUL-framed %q", spec.EnvData, want.Bytes())
	}
}

func TestBuildSpecNoEnvHandoff(t *testing.T) {
	root, home, proj, _ := overlaySpec(t)
	spec, err := BuildSpec(&cliutil.Options{}, proj, filepath.Join(root, "sand"),
		filepath.Join(root, "sock"), home, nil, nil, "", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if spec.EnvData != nil {
		t.Fatal("no --env flags must mean no handoff data")
	}
}

func TestComposeEnvDataRejects(t *testing.T) {
	if _, err := composeEnvData([]cliutil.EnvVar{{Name: "A", Value: "v"}}); err != nil {
		t.Fatalf("valid pair rejected: %v", err)
	}
	for _, bad := range []cliutil.EnvVar{
		{Name: "", Value: "v"},
		{Name: "A=B", Value: "v"},
		{Name: "A\x00B", Value: "v"},
		{Name: "A", Value: "v\x00"},
	} {
		if _, err := composeEnvData([]cliutil.EnvVar{bad}); err == nil {
			t.Errorf("composeEnvData(%q) accepted", bad.Name)
		}
	}
	big := strings.Repeat("v", maxEnvData)
	if _, err := composeEnvData([]cliutil.EnvVar{{Name: "A", Value: big}}); err == nil {
		t.Error("oversized handoff accepted")
	}
}

func TestApplyEnvRecords(t *testing.T) {
	t.Setenv("SBOX_ENV_ORDER", "default")
	data := bytes.NewBuffer(nil)
	for _, p := range [][2]string{
		{"SBOX_ENV_ORDER", "first"}, {"SBOX_ENV_ORDER", "last"},
		{"SBOX_ENV_BYTES", "new\nline \x1b[31m= quotes"},
		{"SBOX_EMPTY", ""},
	} {
		data.WriteString(p[0])
		data.WriteByte(0)
		data.WriteString(p[1])
		data.WriteByte(0)
	}
	if err := applyEnvRecords(data.Bytes()); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("SBOX_ENV_ORDER"); got != "last" {
		t.Errorf("repeated name = %q, want the last value", got)
	}
	if got := os.Getenv("SBOX_ENV_BYTES"); got != "new\nline \x1b[31m= quotes" {
		t.Errorf("byte-exact value mangled: %q", got)
	}
	if got, ok := os.LookupEnv("SBOX_EMPTY"); !ok || got != "" {
		t.Errorf("empty value = %q (present %t)", got, ok)
	}

	for _, bad := range []string{
		"NAME",      // ends mid-name
		"NAME\x00",  // no value terminator
		"\x00v\x00", // empty name
		"N=AME\x00v\x00",
		"N/AME\x00v\x00",
	} {
		if err := applyEnvRecords([]byte(bad)); err == nil {
			t.Errorf("applyEnvRecords(%q) accepted malformed records", bad)
		}
	}
}
