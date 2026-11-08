package allow

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func mustEntry(t *testing.T, raw string) Entry {
	t.Helper()
	e, err := ParseAllowEntry(raw)
	if err != nil {
		t.Fatalf("ParseAllowEntry(%q): %v", raw, err)
	}
	return e
}

// TestParseAllowEntryOK pins sbox.py's parse_allow_entry results (values
// verified against the Python implementation), plus the !private marker.
func TestParseAllowEntryOK(t *testing.T) {
	cases := []struct {
		raw     string
		kind    string
		value   string
		port    int
		private bool
	}{
		{"example.com", "name", "example.com", 0, false},
		{"*.example.com", "name", "example.com", 0, false},
		{"*.*.example.com", "name", "example.com", 0, false}, // leading "*." repeatedly
		{"example.com.", "name", "example.com", 0, false},
		{".example.com.", "name", "example.com", 0, false},
		{"EXAMPLE.COM", "name", "example.com", 0, false},
		{"example.com # comment", "name", "example.com", 0, false},
		{"  example.com  ", "name", "example.com", 0, false},
		{"example.com:443", "name", "example.com", 443, false},
		{"localhost", "name", "localhost", 0, false},
		{"xn--fo-0ja.com", "name", "xn--fo-0ja.com", 0, false},
		{"_dmarc.example.com", "name", "_dmarc.example.com", 0, false},
		{"sub_domain.example.com", "name", "sub_domain.example.com", 0, false},

		{"203.0.113.7", "net", "203.0.113.7/32", 0, false},
		{"203.0.113.0/24", "net", "203.0.113.0/24", 0, false},
		{"10.0.0.0/8", "net", "10.0.0.0/8", 0, false},
		{"10.0.0.0/08", "net", "10.0.0.0/8", 0, false}, // Python takes leading-zero plens
		{"255.255.255.255/32", "net", "255.255.255.255/32", 0, false},
		{"[2001:db8::]/32", "net", "2001:db8::/32", 0, false},
		{"[2001:db8::]", "net", "2001:db8::/128", 0, false},
		{"[2001:db8::]:443", "net", "2001:db8::/128", 443, false},
		{"2001:db8::/32", "net", "2001:db8::/32", 0, false},
		{"[2001:DB8::]/32", "net", "2001:db8::/32", 0, false},
		{"a::b", "net", "a::b/128", 0, false},
		{"2001:db8::", "net", "2001:db8::/128", 0, false},

		{"example.com!private", "name", "example.com", 0, true},
		{"*.example.com!private", "name", "example.com", 0, true},
		{"example.com:443!private", "name", "example.com", 443, true},
		{"example.com !private", "name", "example.com", 0, true},
	}
	for _, c := range cases {
		e := mustEntry(t, c.raw)
		if e.Kind != c.kind || e.Value != c.value || e.Port != c.port || e.Private != c.private {
			t.Errorf("ParseAllowEntry(%q) = {%s %q port:%d private:%v}, want {%s %q port:%d private:%v}",
				c.raw, e.Kind, e.Value, e.Port, e.Private, c.kind, c.value, c.port, c.private)
		}
	}
}

// TestParseAllowEntryErrors pins sbox.py's exact error messages (verified
// against the Python implementation). Fail-closed: loud, never widened.
func TestParseAllowEntryErrors(t *testing.T) {
	cases := []struct{ raw, want string }{
		{"", "empty entry"},
		{"   ", "empty entry"},
		{"# only a comment", "empty entry"},
		{"*.", "empty entry"},
		{".", "empty entry"},
		{"*", "wildcard-only entry would allow everything; use --net for unrestricted egress"},
		{"*.*", "wildcard-only entry would allow everything; use --net for unrestricted egress"},
		{"example.*.com", "wildcards are only supported as a leading '*.' in \"example.*.com\""},
		{"0.0.0.0/0", "\"0.0.0.0/0\" is an effectively catch-all network (/0); add narrower entries or use --net for unrestricted egress"},
		{"0.0.0.0/1", "\"0.0.0.0/1\" is an effectively catch-all network (/1); add narrower entries or use --net for unrestricted egress"},
		{"10.0.0.0/7", "\"10.0.0.0/7\" is an effectively catch-all network (/7); add narrower entries or use --net for unrestricted egress"},
		{"240.0.0.0/4", "\"240.0.0.0/4\" is an effectively catch-all network (/4); add narrower entries or use --net for unrestricted egress"},
		{"::/0", "\"::/0\" is an effectively catch-all network (/0); add narrower entries or use --net for unrestricted egress"},
		{"::/15", "\"::/15\" is an effectively catch-all network (/15); add narrower entries or use --net for unrestricted egress"},
		{"2001:db8::/15", "\"2001:db8::/15\": host bits set — refusing to widen to 2000::/15; write 2000::/15 instead"},
		{"[2001:db8::1]/32", "\"[2001:db8::1]/32\": host bits set — refusing to widen to 2001:db8::/32; write 2001:db8::/32 instead"},
		{"203.0.113.7/24", "not a valid hostname, IP or CIDR: \"203.0.113.7/24\""}, // Python quirk: host-bits message needs a digits-dots/colon host
		{"300.1.2.3", "invalid IP/CIDR entry: \"300.1.2.3\""},
		{"1.2.3", "invalid IP/CIDR entry: \"1.2.3\""},
		{"010.1.2.3", "invalid IP/CIDR entry: \"010.1.2.3\""},
		{"example.com:0", "bad port in allow entry \"example.com:0\" (expected 1-65535)"},
		{"example.com:99999", "bad port in allow entry \"example.com:99999\" (expected 1-65535)"},
		{"example.com:443x", "bad port in allow entry \"example.com:443x\" (expected host:port)"},
		{"example.com:443:80", "invalid IP/CIDR entry: \"example.com:443:80\""}, // two colons -> v6-ish path
		{"[notv6]", "malformed IPv6 entry: \"[notv6]\""},
		{"[1.2.3.4]", "malformed IPv6 entry: \"[1.2.3.4]\""},
		{"[2001:db8::/33]", "malformed IPv6 entry: \"[2001:db8::/33]\""},
		{"-bad.example.com", "not a valid hostname, IP or CIDR: \"-bad.example.com\""},
		{"bad-.example.com", "not a valid hostname, IP or CIDR: \"bad-.example.com\""},
		{"ex..ample", "not a valid hostname, IP or CIDR: \"ex..ample\""},
		{"exämple.com", "not a valid hostname, IP or CIDR: \"exämple.com\""},
		{"10.0.0.0/33", "not a valid hostname, IP or CIDR: \"10.0.0.0/33\""},
		{"10.0.0.0/0x8", "not a valid hostname, IP or CIDR: \"10.0.0.0/0x8\""},
		{":8080", "not a valid hostname, IP or CIDR: \":8080\""},
		// !private on IP/CIDR entries is rejected loudly — the guard never
		// applies to them (verified against sbox.py)
		{"[2001:db8::]/32!private", "\"[2001:db8::]/32!private\": !private only applies to name entries — literal IP/CIDR entries bypass the private-range guard anyway"},
		{"10.0.0.0/8!private", "\"10.0.0.0/8!private\": !private only applies to name entries — literal IP/CIDR entries bypass the private-range guard anyway"},
		{"1.2.3.4!private", "\"1.2.3.4!private\": !private only applies to name entries — literal IP/CIDR entries bypass the private-range guard anyway"},
		{"::1!private", "\"::1!private\": !private only applies to name entries — literal IP/CIDR entries bypass the private-range guard anyway"},
		// the catch-all check fires BEFORE the !private check (sbox.py order)
		{"0.0.0.0/0!private", "\"0.0.0.0/0!private\" is an effectively catch-all network (/0); add narrower entries or use --net for unrestricted egress"},
	}
	for _, c := range cases {
		_, err := ParseAllowEntry(c.raw)
		if err == nil {
			t.Errorf("ParseAllowEntry(%q) = nil error, want %q", c.raw, c.want)
			continue
		}
		if err.Error() != c.want {
			t.Errorf("ParseAllowEntry(%q) err:\n got %q\nwant %q", c.raw, err.Error(), c.want)
		}
	}
}

func TestLoadAllows(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "a.allows")
	os.WriteFile(good, []byte("# header comment\n\npypi.org  # inline\nfiles.pythonhosted.org\nlocalhost\n"), 0o600)
	bad := filepath.Join(dir, "bad.allows")
	os.WriteFile(bad, []byte("example.com\nnot an entry!\n"), 0o600)

	var warns []string
	entries, err := LoadAllows([]string{"example.com"}, []string{good}, func(w string) { warns = append(warns, w) })
	if err != nil {
		t.Fatalf("LoadAllows: %v", err)
	}
	// files load first, then -a values, in order
	wantValues := []string{"pypi.org", "files.pythonhosted.org", "localhost", "example.com"}
	var got []string
	for _, e := range entries {
		got = append(got, e.Value)
	}
	if !reflect.DeepEqual(got, wantValues) {
		t.Errorf("entries = %q, want %q", got, wantValues)
	}
	if len(warns) != 1 || !strings.Contains(warns[0], "localhost") {
		t.Errorf("warns = %q, want one single-label warning for localhost", warns)
	}

	// nil warn callback is fine
	if _, err := LoadAllows([]string{"example.com"}, nil, nil); err != nil {
		t.Errorf("LoadAllows no files: %v", err)
	}

	// missing file
	_, err = LoadAllows(nil, []string{filepath.Join(dir, "nope")}, nil)
	if err == nil || err.Error() != "cannot read allow file: "+filepath.Join(dir, "nope") {
		t.Errorf("missing file err = %v", err)
	}
	// directory as allow file
	_, err = LoadAllows(nil, []string{dir}, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "cannot read allow file: ") {
		t.Errorf("dir as file err = %v", err)
	}
	// bad line: path:lineno: message
	_, err = LoadAllows(nil, []string{bad}, nil)
	if err == nil || err.Error() != bad+":2: not a valid hostname, IP or CIDR: \"not an entry!\"" {
		t.Errorf("bad line err = %v", err)
	}
	// bad -a value: --allow: message
	_, err = LoadAllows([]string{"*"}, nil, nil)
	if err == nil || !strings.HasPrefix(err.Error(), "--allow: wildcard-only entry") {
		t.Errorf("-a err = %v", err)
	}
}

func TestDestinationAllowed(t *testing.T) {
	allows := []Entry{}
	for _, raw := range []string{
		"example.com", "example.org:443", "203.0.113.0/24", "[2001:db8::]/32", "198.51.100.7:80",
	} {
		allows = append(allows, mustEntry(t, raw))
	}
	cases := []struct {
		host string
		port int
		ok   bool
		why  string
	}{
		{"example.com", 80, true, "matches allowed name example.com"},
		{"sub.example.com", 80, true, "matches allowed name example.com"},
		{"SUB.Example.COM.", 8080, true, "matches allowed name example.com"},
		{"notexample.com", 80, false, "hostname not on the allowlist"},       // no dot-boundary match
		{"example.com.evil.com", 80, false, "hostname not on the allowlist"}, // suffix must be on dot boundary
		{"example.org", 443, true, "matches allowed name example.org"},
		{"example.org", 80, false, "hostname not on the allowlist"}, // port-scoped
		{"203.0.113.9", 80, true, "matches allowed network 203.0.113.0/24"},
		{"203.0.113.9", 443, true, "matches allowed network 203.0.113.0/24"}, // net entry without port: any port
		{"198.51.100.7", 80, true, "matches allowed network 198.51.100.7/32"},
		{"198.51.100.7", 81, false, "IP destination not in any allowed network"},
		{"198.51.100.8", 80, false, "IP destination not in any allowed network"},
		{"2001:db8::1", 80, true, "matches allowed network 2001:db8::/32"},
		{"2001:db9::1", 80, false, "IP destination not in any allowed network"},
		{"8.8.8.8", 80, false, "IP destination not in any allowed network"},
	}
	for _, c := range cases {
		ok, why := DestinationAllowed(allows, c.host, c.port)
		if ok != c.ok || (c.why != "" && why != c.why) {
			t.Errorf("DestinationAllowed(%q,%d) = %v, %q; want %v, %q", c.host, c.port, ok, why, c.ok, c.why)
		}
	}

	// a hostname that looks like an IP (leading zeros) is a NAME for
	// matching purposes, exactly like Python's ip_address() failure path
	ok, _ := DestinationAllowed(allows, "010.1.2.3", 80)
	if ok {
		t.Errorf("010.1.2.3 must not match 10/8 entries")
	}
	// v4 destinations never match v6 entries and vice versa
	v6only := []Entry{mustEntry(t, "[::ffff:203.0.113.5]/128")}
	if ok, _ := DestinationAllowed(v6only, "203.0.113.5", 80); ok {
		t.Errorf("v4 destination matched a v6-mapped entry")
	}
}

func TestPrivateAllowed(t *testing.T) {
	allows := []Entry{}
	for _, raw := range []string{"example.com!private", "split.other.org:8443!private", "plain.com"} {
		allows = append(allows, mustEntry(t, raw))
	}
	cases := []struct {
		host string
		port int
		want bool
	}{
		{"example.com", 80, true},
		{"sub.example.com", 80, true},
		{"notexample.com", 80, false},
		{"split.other.org", 8443, true},
		{"split.other.org", 80, false}, // port-scoped marker
		{"plain.com", 80, false},
		{"other.com", 80, false},
	}
	for _, c := range cases {
		if got := PrivateAllowed(allows, c.host, c.port); got != c.want {
			t.Errorf("PrivateAllowed(%q,%d) = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}
