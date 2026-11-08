package cliutil

import (
	"reflect"
	"strings"
	"testing"
)

func sliceEq(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSplitArgv pins sbox.py's split_argv behavior, including the quirky
// bits: a value token may swallow a "--", and only exact OPTS_WITH_VALUE
// spellings consume two tokens (attached values and "=" forms are single
// tokens by construction).
func TestSplitArgv(t *testing.T) {
	cases := []struct {
		name string
		argv []string
		pre  []string
		cmd  []string
	}{
		{"empty", nil, nil, nil},
		{"bare --", []string{"--"}, nil, nil},
		{"-- then command", []string{"--", "curl"}, nil, []string{"curl"}},
		{"flags then --", []string{"-a", "example.com", "--", "curl", "-v"},
			[]string{"-a", "example.com"}, []string{"curl", "-v"}},
		{"value flag at end", []string{"-a", "example.com"}, []string{"-a", "example.com"}, nil},
		{"lone value flag", []string{"--allow"}, []string{"--allow"}, nil},
		{"attached short value", []string{"-b/path", "--", "sh"}, []string{"-b/path"}, []string{"sh"}},
		{"= form", []string{"--allow=example.com", "--", "sh"}, []string{"--allow=example.com"}, []string{"sh"}},
		{"= form is one token", []string{"--allow=x", "curl"}, []string{"--allow=x"}, []string{"curl"}},
		{"first positional wins", []string{"curl", "-a", "x"}, nil, []string{"curl", "-a", "x"}},
		{"dash is positional", []string{"-"}, nil, []string{"-"}},
		{"bool then positional", []string{"-v", "curl"}, []string{"-v"}, []string{"curl"}},
		{"cluster is one token (parser rejects)", []string{"-va", "curl"}, []string{"-va"}, []string{"curl"}},
		{"value token may be --", []string{"--allow", "--", "x"}, []string{"--allow", "--"}, []string{"x"}},
		{"hidden --_selfprobe takes no value", []string{"-a", "x", "--_selfprobe", "y"},
			[]string{"-a", "x", "--_selfprobe"}, []string{"y"}},
		{"bind-socket consumes value", []string{"--bind-socket", "/run/user/1000/bus", "--", "sh"},
			[]string{"--bind-socket", "/run/user/1000/bus"}, []string{"sh"}},
		{"upstream consumes value", []string{"--upstream", "http://p:3128", "--", "curl"},
			[]string{"--upstream", "http://p:3128"}, []string{"curl"}},
		{"-- after everything", []string{"-v", "--"}, []string{"-v"}, nil},
		{"multiple --", []string{"-v", "--", "a", "--", "b"}, []string{"-v"}, []string{"a", "--", "b"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pre, cmd := SplitArgv(c.argv)
			if !sliceEq(pre, c.pre) {
				t.Errorf("SplitArgv(%q) pre = %q, want %q", c.argv, pre, c.pre)
			}
			if !sliceEq(cmd, c.cmd) {
				t.Errorf("SplitArgv(%q) cmd = %q, want %q", c.argv, cmd, c.cmd)
			}
		})
	}
}

// TestShortWithValueDerived ensures the short-with-value table stays
// derived from OptsWithValue (the trap-list invariant).
func TestShortWithValueDerived(t *testing.T) {
	want := map[byte]bool{'a': true, 'A': true, 'b': true, 'r': true}
	if !reflect.DeepEqual(ShortWithValue, want) {
		t.Errorf("ShortWithValue = %v, want %v", ShortWithValue, want)
	}
	for _, o := range OptsWithValue {
		if len(o) == 2 && o[0] == '-' && o[1] != '-' && !ShortWithValue[o[1]] {
			t.Errorf("value option %q missing from ShortWithValue", o)
		}
	}
}

func parseOK(t *testing.T, argv []string) (*Options, []string) {
	t.Helper()
	opts, cmd, err := ParseCLI(argv)
	if err != nil {
		t.Fatalf("ParseCLI(%q): %v", argv, err)
	}
	return opts, cmd
}

func TestParseCLIFlags(t *testing.T) {
	opts, cmd := parseOK(t, []string{
		"-a", "example.com", "-a", "example.org",
		"-A", "/path/allows", "--allow-file", "/other",
		"-b", "/src", "-b", "/dst", "-r", "/ro", "--ro-bind", "/ro2",
		"--bind-socket", "/run/user/1000/bus",
		"--ro-cwd", "--home", "--gui", "--ssh-agent", "--net", "-v", "--verbose", "--shell",
		"--upstream-insecure", "--no-seccomp", "--filter-output", "--strict-crlf",
		"--", "curl", "-v", "example.com",
	})
	if want := []string{"example.com", "example.org"}; !sliceEq(opts.Allow, want) {
		t.Errorf("Allow = %q, want %q", opts.Allow, want)
	}
	if want := []string{"/path/allows", "/other"}; !sliceEq(opts.AllowFile, want) {
		t.Errorf("AllowFile = %q, want %q", opts.AllowFile, want)
	}
	if want := []string{"/src", "/dst"}; !sliceEq(opts.Bind, want) {
		t.Errorf("Bind = %q, want %q", opts.Bind, want)
	}
	if want := []string{"/ro", "/ro2"}; !sliceEq(opts.RoBind, want) {
		t.Errorf("RoBind = %q, want %q", opts.RoBind, want)
	}
	if want := []string{"/run/user/1000/bus"}; !sliceEq(opts.BindSocket, want) {
		t.Errorf("BindSocket = %q, want %q", opts.BindSocket, want)
	}
	for _, c := range []struct {
		name string
		got  bool
	}{
		{"RoCwd", opts.RoCwd}, {"Home", opts.Home}, {"Gui", opts.Gui},
		{"SSHAgent", opts.SSHAgent}, {"StrictCrlf", opts.StrictCrlf},
		{"Net", opts.Net}, {"Verbose", opts.Verbose}, {"Shell", opts.Shell},
		{"UpstreamInsecure", opts.UpstreamInsecure}, {"NoSeccomp", opts.NoSeccomp},
		{"FilterOutput", opts.FilterOutput},
	} {
		if !c.got {
			t.Errorf("%s = false, want true", c.name)
		}
	}
	if opts.Upstream != "" || opts.HasUpstream {
		t.Errorf("Upstream = %q HasUpstream = %v, want unset", opts.Upstream, opts.HasUpstream)
	}
	if want := []string{"curl", "-v", "example.com"}; !sliceEq(cmd, want) {
		t.Errorf("command = %q, want %q", cmd, want)
	}
}

func TestParseCLIValues(t *testing.T) {
	// attached short values (argparse "-afoo" semantics)
	opts, _ := parseOK(t, []string{"-aexample.com", "-b/src", "-r/ro", "-A/file", "--", "sh"})
	if want := []string{"example.com"}; !sliceEq(opts.Allow, want) {
		t.Errorf("Allow = %q, want %q", opts.Allow, want)
	}
	if want := []string{"/src"}; !sliceEq(opts.Bind, want) {
		t.Errorf("Bind = %q, want %q", opts.Bind, want)
	}
	if want := []string{"/ro"}; !sliceEq(opts.RoBind, want) {
		t.Errorf("RoBind = %q, want %q", opts.RoBind, want)
	}
	if want := []string{"/file"}; !sliceEq(opts.AllowFile, want) {
		t.Errorf("AllowFile = %q, want %q", opts.AllowFile, want)
	}

	// "=" forms; empty --upstream means "force direct", not "unset"
	opts, _ = parseOK(t, []string{"--allow=example.com", "--upstream=", "--", "sh"})
	if want := []string{"example.com"}; !sliceEq(opts.Allow, want) {
		t.Errorf("Allow = %q, want %q", opts.Allow, want)
	}
	if !opts.HasUpstream || opts.Upstream != "" {
		t.Errorf("Upstream = %q HasUpstream = %v, want \"\"/true", opts.Upstream, opts.HasUpstream)
	}

	// unset --upstream (env fallback applies in the caller)
	opts, _ = parseOK(t, []string{"--", "sh"})
	if opts.HasUpstream {
		t.Errorf("HasUpstream = true, want false")
	}

	// --upstream with URL; last value wins (argparse store semantics)
	opts, _ = parseOK(t, []string{"--upstream", "http://a:1", "--upstream=http://b:2", "--", "sh"})
	if opts.Upstream != "http://b:2" || !opts.HasUpstream {
		t.Errorf("Upstream = %q HasUpstream = %v", opts.Upstream, opts.HasUpstream)
	}

	// hidden --_selfprobe parses as a valueless flag
	opts, cmd := parseOK(t, []string{"--_selfprobe"})
	if !opts.SelfProbe || len(cmd) != 0 {
		t.Errorf("SelfProbe = %v cmd = %q", opts.SelfProbe, cmd)
	}

	// -h / --help
	for _, argv := range [][]string{{"-h"}, {"--help"}, {"-v", "--help"}} {
		opts, _, err := ParseCLI(argv)
		if err != nil || !opts.Help {
			t.Errorf("ParseCLI(%q) Help = %v err = %v, want true/nil", argv, opts.Help, err)
		}
	}
}

func TestParseCLIShortEquals(t *testing.T) {
	// argparse splits an attached short value at the FIRST '=': "-a=x" is
	// "x", "-a==x" is "=x", "-b=" is "" (verified against Python argparse).
	opts, _ := parseOK(t, []string{"-a=x", "-a==y", "-b=", "-b=/p", "--", "sh"})
	if want := []string{"x", "=y"}; !sliceEq(opts.Allow, want) {
		t.Errorf("Allow = %q, want %q", opts.Allow, want)
	}
	if want := []string{"", "/p"}; !sliceEq(opts.Bind, want) {
		t.Errorf("Bind = %q, want %q", opts.Bind, want)
	}
}

func TestParseCLIOptionLikeValues(t *testing.T) {
	// argparse never consumes an option-like token as an option's value —
	// "-a -b x -- cmd" and "-a -- cmd" are "expected one argument" errors
	// there (and in sbox.py, which inherits argparse).
	for _, argv := range [][]string{
		{"-a", "-b", "x", "--", "cmd"},
		{"-a", "--", "cmd"},
		{"--allow", "--bind", "/src", "--", "cmd"},
		{"--bind", "-r", "/ro", "--", "cmd"},
		{"--upstream", "--shell"},
	} {
		if _, _, err := ParseCLI(argv); err == nil ||
			!strings.HasPrefix(err.Error(), "argument ") ||
			!strings.HasSuffix(err.Error(), ": expected one argument") {
			t.Errorf("ParseCLI(%q) err = %v, want \"argument ...: expected one argument\"", argv, err)
		}
	}
	// ... except a bare "-" (stdin convention) and negative numbers
	// (argparse's negative-number exception; sbox defines no numeric
	// options, so it always applies).
	opts, cmd := parseOK(t, []string{"-a", "-5", "-b", "-", "--", "sh"})
	if want := []string{"-5"}; !sliceEq(opts.Allow, want) {
		t.Errorf("Allow = %q, want %q", opts.Allow, want)
	}
	if want := []string{"-"}; !sliceEq(opts.Bind, want) {
		t.Errorf("Bind = %q, want %q", opts.Bind, want)
	}
	if want := []string{"sh"}; !sliceEq(cmd, want) {
		t.Errorf("command = %q, want %q", cmd, want)
	}
	opts, _ = parseOK(t, []string{"--allow", "-.5", "--", "sh"})
	if want := []string{"-.5"}; !sliceEq(opts.Allow, want) {
		t.Errorf("Allow = %q, want %q", opts.Allow, want)
	}
}

func TestParseCLIStrictCrlfImpliesFilterOutput(t *testing.T) {
	// --strict-crlf is a --filter-output MODE (sbox.py: main() sets
	// opts.filter_output right after parse_cli).
	opts, _ := parseOK(t, []string{"--strict-crlf", "--", "sh"})
	if !opts.StrictCrlf || !opts.FilterOutput {
		t.Errorf("StrictCrlf = %v FilterOutput = %v, want true/true", opts.StrictCrlf, opts.FilterOutput)
	}
}

func TestParseCLIErrors(t *testing.T) {
	cases := []struct {
		argv []string
		want string
	}{
		{[]string{"-va", "x"}, "clustered short flags are not supported: -va"},
		{[]string{"-vh"}, "clustered short flags are not supported: -vh"},
		{[]string{"-a"}, "argument -a/--allow: expected one argument"},
		{[]string{"--allow"}, "argument -a/--allow: expected one argument"},
		{[]string{"--upstream"}, "argument --upstream: expected one argument"},
		{[]string{"--bind-socket"}, "argument --bind-socket: expected one argument"},
		{[]string{"--foo"}, "unrecognized arguments: --foo"},
		{[]string{"--all", "x"}, "unrecognized arguments: --all"}, // no abbreviations
		{[]string{"-x"}, "unrecognized arguments: -x"},
		{[]string{"--net=1"}, `argument --net: ignored explicit argument "1"`},
		{[]string{"--verbose=x"}, `argument --verbose: ignored explicit argument "x"`},
		{[]string{"--ssh-agent=1"}, `argument --ssh-agent: ignored explicit argument "1"`},
		{[]string{"--strict-crlf=1"}, `argument --strict-crlf: ignored explicit argument "1"`},
	}
	for _, c := range cases {
		_, _, err := ParseCLI(c.argv)
		if err == nil {
			t.Errorf("ParseCLI(%q) = nil error, want %q", c.argv, c.want)
			continue
		}
		if err.Error() != c.want && !strings.HasPrefix(err.Error(), c.want) {
			t.Errorf("ParseCLI(%q) err = %q, want %q", c.argv, err, c.want)
		}
	}
}

func TestUsage(t *testing.T) {
	for _, want := range []string{
		"usage: sbox [-h]",
		Description,
		"options:",
		"-a, --allow HOST", // argparse renders the metavar once, after the long form
		"--ssh-agent",
		"--strict-crlf",
		"Examples:\n  sbox -a pypi.org",
		"--net drops the proxy and shares the host network namespace instead.",
	} {
		if !strings.Contains(Usage, want) {
			t.Errorf("Usage missing %q", want)
		}
	}
	if strings.Contains(Usage, "--_selfprobe") {
		t.Errorf("Usage must not document the hidden --_selfprobe flag")
	}
	if strings.Contains(Usage, "sbox.py") {
		t.Errorf("Usage must say sbox, not sbox.py")
	}
}
