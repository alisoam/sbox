package sandbox

import (
	"os"
	"path/filepath"
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
	for _, env := range opts.Env[1:] {
		if v, ok := got[env.Name]; !ok || v != env.Value {
			t.Errorf("%s = %q (present %t), want %q", env.Name, v, ok, env.Value)
		}
	}
	if _, ok := got["SBOX_NOT_FORWARDED"]; ok {
		t.Fatal("unrequested host variable forwarded")
	}
	if !privateHome || os.Getenv("HOME") != home {
		t.Fatal("--env HOME changed host configuration or mount selection")
	}
	if spec.Bridge != InnerProxy+"exec \"$@\"\n" {
		t.Fatal("environment values changed the bridge script")
	}
}
