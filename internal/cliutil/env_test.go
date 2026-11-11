package cliutil

import (
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestEnvOptions(t *testing.T) {
	t.Setenv("SBOX_ENV_TEST", "host value=with equals\nand newline")
	t.Setenv("SBOX_ENV_EMPTY", "")
	literal := "literal ' $HOME $(touch nope) `whoami` =\nnext"
	opts, cmd := parseOK(t, []string{
		"--env", "SBOX_ENV_TEST", "--env=SBOX_ENV_EMPTY", "--env", "SBOX_LITERAL=" + literal,
		"--env", "SBOX_ENV_TEST=last", "--env", "SBOX_EXPLICIT_EMPTY=", "--env", "_a9=valid",
		"/bin/echo", "--env", "payload",
	})
	want := []EnvVar{
		{"SBOX_ENV_TEST", os.Getenv("SBOX_ENV_TEST")}, {"SBOX_ENV_EMPTY", ""},
		{"SBOX_LITERAL", literal}, {"SBOX_ENV_TEST", "last"}, {"SBOX_EXPLICIT_EMPTY", ""}, {"_a9", "valid"},
	}
	if !reflect.DeepEqual(opts.Env, want) {
		t.Fatalf("env = %#v, want %#v", opts.Env, want)
	}
	if !sliceEq(cmd, []string{"/bin/echo", "--env", "payload"}) {
		t.Fatalf("command = %q", cmd)
	}
	if os.Getenv("SBOX_ENV_TEST") != "host value=with equals\nand newline" {
		t.Fatal("parser changed host environment")
	}
}

func TestEnvErrors(t *testing.T) {
	t.Setenv("SBOX_ENV_MISSING", "temporary")
	if err := os.Unsetenv("SBOX_ENV_MISSING"); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--env"}, "expected one argument"},
		{[]string{"--env", "SBOX_ENV_MISSING"}, "host variable \"SBOX_ENV_MISSING\" is not set"},
		{[]string{"--env", "=secret"}, "invalid variable name"},
		{[]string{"--env", "9NAME=secret"}, "invalid variable name"},
		{[]string{"--env", "BAD-NAME=secret"}, "invalid variable name"},
		{[]string{"--env", "BAD NAME=secret"}, "invalid variable name"},
		{[]string{"--env", "BAD\nNAME=secret"}, "invalid variable name"},
		{[]string{"--env", "NAME=secret\x00"}, "contains a NUL byte"},
		{[]string{"--en", "NAME=value"}, "unrecognized arguments"},
	} {
		_, _, err := ParseCLI(tc.args)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%q: %v, want %q", tc.args, err, tc.want)
		}
		if strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "\n") {
			t.Fatalf("unsafe error: %q", err)
		}
	}
}
