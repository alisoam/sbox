package cliutil

import (
	"strings"
	"testing"
)

func TestOverlayMode(t *testing.T) {
	for _, tc := range []struct {
		name   string
		args   []string
		single bool
		err    string
	}{
		{"default", []string{"--overlay", "/proj"}, false, ""},
		{"single", []string{"--overlay-mode", "single", "--overlay", "/proj"}, true, ""},
		{"attached", []string{"--overlay=/proj", "--overlay-mode=single"}, true, ""},
		{"last wins", []string{"--overlay-mode=single", "--overlay-mode=staged", "--overlay=/proj", "--overlay-size=1GiB"}, false, ""},
		{"invalid", []string{"--overlay-mode=auto"}, false, "invalid mode"},
		{"missing", []string{"--overlay-mode"}, false, "expected one argument"},
		{"no source", []string{"--overlay-mode=single"}, false, "requires --overlay"},
		{"cap before", []string{"--overlay-size=1GiB", "--overlay=/proj", "--overlay-mode=single"}, false, "--overlay-size is not supported"},
		{"cap after", []string{"--overlay-mode=single", "--overlay=/proj", "--overlay-size=1MiB"}, false, "--overlay-size is not supported"},
		{"abbreviated", []string{"--overlay-mod=single"}, false, "unrecognized arguments"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			opts, _, err := ParseCLI(tc.args)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("error = %v, want %q", err, tc.err)
				}
				return
			}
			if err != nil || opts.OverlaySingle != tc.single {
				t.Fatalf("options = %+v, error = %v", opts, err)
			}
		})
	}
	flags, command := SplitArgv([]string{"--overlay-mode", "single", "--overlay", "/proj", "zsh", "-i"})
	if !sliceEq(flags, []string{"--overlay-mode", "single", "--overlay", "/proj"}) || !sliceEq(command, []string{"zsh", "-i"}) {
		t.Fatalf("split: flags %q command %q", flags, command)
	}
}
