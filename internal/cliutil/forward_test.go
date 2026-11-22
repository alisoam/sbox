package cliutil

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func TestParseForwardOptions(t *testing.T) {
	opts, cmd, err := ParseCLI([]string{"-L8080:80", "--remote-forward", "[::1]:9000:localhost:5432",
		"--local-forward=127.0.0.2:81:[::1]:82", "-R", "83:127.0.0.3:84", "cmd", "-R"})
	if err != nil {
		t.Fatal(err)
	}
	ap := netip.MustParseAddrPort
	want := []Forward{
		{false, ap("127.0.0.1:8080"), ap("127.0.0.1:80")},
		{true, ap("[::1]:9000"), ap("127.0.0.1:5432")},
		{false, ap("127.0.0.2:81"), ap("[::1]:82")},
		{true, ap("127.0.0.1:83"), ap("127.0.0.3:84")},
	}
	if !reflect.DeepEqual(opts.Forwards, want) || !reflect.DeepEqual(cmd, []string{"cmd", "-R"}) {
		t.Fatalf("forwards %v, command %q", opts.Forwards, cmd)
	}
	if _, _, err := ParseCLI([]string{"-L", "80:80", "--net", "true"}); err == nil {
		t.Error("accepted a shared-network forward to itself")
	}
	for _, bad := range []string{"", "80", "80:", ":80", "0:80", "1:65536", "-1:2", "80:host:123",
		"host:80:127.0.0.1:80", "80:0.0.0.0:80", "80:::1:80", "99:127.0.0.1,exec=sh:80"} {
		if _, _, err := ParseCLI([]string{"-R", bad, "true"}); err == nil {
			t.Errorf("accepted %q", bad)
		}
	}
}

func TestForwardLoopValidation(t *testing.T) {
	ok := func(args ...string) {
		t.Helper()
		if _, _, err := ParseCLI(append(args, "true")); err != nil {
			t.Errorf("%v: %v", args, err)
		}
	}
	bad := func(args ...string) {
		t.Helper()
		if _, _, err := ParseCLI(append(args, "true")); err == nil {
			t.Errorf("accepted %v", args)
		}
	}
	// --net shares one namespace: every dial can land on every listener.
	bad("-L", "80:80", "--net")                       // exact self-dial
	bad("-L", "0.0.0.0:8080:127.0.0.1:8080", "--net") // wildcard listener captures its own dial
	bad("-R", "[::]:8080:127.0.0.1:8080", "--net")    // v6 wildcard takes v4-mapped dials
	bad("-L", "[::1]:8080:[::1]:8080", "--net")       // v6 exact self-dial
	bad("-L", "8080:127.0.0.1:9090", "-L", "9090:127.0.0.1:8080", "--net")
	bad("-L", "1:127.0.0.1:2", "-L", "2:127.0.0.1:3", "-L", "3:127.0.0.1:1", "--net")
	bad("-L", "8080:127.0.0.1:9090", "-R", "9090:127.0.0.1:8080", "--net") // mixed flags, one namespace
	ok("-L", "8080:127.0.0.1:9090", "-L", "9091:127.0.0.1:8080", "--net")  // chain, no cycle
	// Isolated mode: -L listens on the host and dials in the sandbox, -R the
	// reverse — a cycle needs one rule of each kind crossing the same ports.
	bad("-L", "8080:127.0.0.1:9090", "-R", "9090:127.0.0.1:8080") // sandbox dial meets the -R listener
	bad("-R", "8080:127.0.0.1:9090", "-L", "9090:127.0.0.1:8080") // the mirrored pair
	bad("-L", "8080:0.0.0.0:9090", "-R", "9090:127.0.0.1:8080")   // connect() to 0.0.0.0 lands on loopback
	ok("-L", "8080:127.0.0.1:9090", "-L", "9090:127.0.0.1:8080")  // both dials are sandbox-side
	ok("-R", "8080:127.0.0.1:9090", "-R", "9090:127.0.0.1:8080")  // both dials are host-side
	ok("-L", "80:80")                                             // same endpoint, different namespaces
	ok("-L", "0.0.0.0:8080:127.0.0.1:8080")
	ok("-L", "20000:18081", "-R", "18082:20000") // the live-test chain: one pass, no cycle
	if _, _, err := ParseCLI([]string{"-L", "8080:127.0.0.1:9090", "-R", "9090:127.0.0.1:8080", "true"}); err == nil ||
		!strings.Contains(err.Error(), "forwarding loop") {
		t.Errorf("loop error does not name the cycle: %v", err)
	}
}
