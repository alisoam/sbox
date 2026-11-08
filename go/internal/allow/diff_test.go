package allow

// The differential cross-check against the Python reference — the REPO's
// sbox.py (the spec under port; oracle.SboxPy() walks up to it so an
// older installed copy never silently takes its place), covering the
// allowlist layer: parse_allow_entry, destination_allowed and bad_ip.
// This is the old scratch zzdiff harness (a throwaway Go binary + a
// Python oracle script) made permanent, so the port keeps proving itself
// against the reference implementation for as long as it exists.
//
// Error messages are compared after quote normalization — Python writes
// {raw!r} (repr) where the port writes %q; the never-print-attacker-
// bytes-raw guarantee is the same, the quote character is not.
//
// bad_ip is compared against the LIVE Python 3.15 ipaddress module the
// oracle runs on — the same module the port's pinned tables were
// derived from, so any drift in either direction shows up here.
//
// Skips cleanly without python3/sbox.py ($SBOX_PY / $SBOX_PYTHON).

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"sbox/internal/oracle"
)

func requireOracle(t *testing.T) {
	t.Helper()
	if !oracle.Available() {
		t.Skip("differential oracle unavailable: python3 + sbox.py not found (set $SBOX_PY / $SBOX_PYTHON)")
	}
}

func runOracle(t *testing.T, expr string, reqs []any) [][2]any {
	t.Helper()
	var sb strings.Builder
	for _, r := range reqs {
		b, err := json.Marshal(r)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		sb.Write(b)
		sb.WriteByte('\n')
	}
	out, err := oracle.RunBatch(oracle.DriverFor(expr), sb.String())
	if err != nil {
		t.Fatalf("oracle: %v", err)
	}
	var res [][2]any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var pair [2]any
		if err := json.Unmarshal([]byte(line), &pair); err != nil {
			t.Fatalf("oracle line %q: %v", line, err)
		}
		res = append(res, pair)
	}
	if len(res) != len(reqs) {
		t.Fatalf("oracle returned %d results for %d requests", len(res), len(reqs))
	}
	return res
}

// normQuotes collapses quote-delimited spans so %q("x") and repr('x')
// compare equal.
func normQuotes(s string) string {
	var out []byte
	inQuote := false
	var q byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !inQuote {
			if c == '\'' || c == '"' {
				inQuote, q = true, c
				out = append(out, '«')
				continue
			}
			out = append(out, c)
			continue
		}
		// inside quotes: skip content, honor escapes, close on the quote
		if c == '\\' && i+1 < len(s) {
			i++
			continue
		}
		if c == q {
			inQuote = false
			out = append(out, '»')
		}
	}
	return string(out)
}

func TestDifferentialParseAllowEntry(t *testing.T) {
	requireOracle(t)
	raws := []string{
		// names
		"example.com", "*.example.com", "*.*.example.com", "example.com.",
		".example.com.", "EXAMPLE.COM", "localhost", "xn--fo-0ja.com",
		"_dmarc.example.com", "sub_domain.example.com",
		"example.com # comment", "  example.com  ", "# only", "", "   ",
		"exämple.com", "-bad.example.com", "bad-.example.com", "ex..ample",
		"example.*.com", "*", "*.", "*.*", ".",
		// ports
		"example.com:443", "example.com:0", "example.com:99999",
		"example.com:443x", "example.com:443:80", "example.com:",
		// ipv4 / cidr
		"203.0.113.7", "203.0.113.0/24", "10.0.0.0/8", "10.0.0.0/08",
		"255.255.255.255/32", "203.0.113.7/24", "300.1.2.3", "1.2.3",
		"010.1.2.3", "10.0.0.0/33", "10.0.0.0/0x8", "0.0.0.0/0",
		"0.0.0.0/1", "128.0.0.0/1", "10.0.0.0/7", "240.0.0.0/4",
		// ipv6
		"[2001:db8::]/32", "[2001:db8::]", "[2001:db8::]:443",
		"2001:db8::/32", "[2001:DB8::]/32", "a::b", "2001:db8::",
		"[notv6]", "[1.2.3.4]", "[2001:db8::/33]", "[2001:db8::1]/32",
		"::/0", "::/15", "2001:db8::/15", "::1", "::1/128",
		"64:ff9b::/96", "2002::/16",
		// junk
		":8080", "http://example.com", "example.com/",
		// !private marker: names carry it, IP/CIDR entries reject it
		"example.com!private", "*.example.com!private", "example.com:443!private",
		"EXAMPLE.COM!PRIVATE", "example.com !private", "10.0.0.0/8!private",
		"1.2.3.4!private", "[2001:db8::]/32!private", "::1!private",
		"0.0.0.0/0!private", "example.com!PRIVATE!",
	}
	got := runOracle(t, `m.parse_allow_entry(req)`, toIface(raws))
	for i, raw := range raws {
		py := got[i]
		e, err := ParseAllowEntry(raw)
		var goRes [2]any
		if err != nil {
			goRes = [2]any{"ERR", err.Error()}
		} else {
			var port any
			if e.Port != 0 {
				port = e.Port
			}
			// Python's dicts: name entries carry "private", net entries
			// do not (the repo sbox.py's exact shapes).
			d := map[string]any{"kind": e.Kind, "value": e.Value, "port": port}
			if e.Kind == "name" {
				d["private"] = e.Private
			}
			goRes = [2]any{"OK", d}
		}
		if !sameResult(t, goRes, py) {
			t.Errorf("parse_allow_entry(%q):\n  go   = %v\n  py   = %v", raw, goRes, py)
		}
	}
}

func TestDifferentialDestinationAllowed(t *testing.T) {
	requireOracle(t)
	allowLists := [][]string{
		{"example.com"},
		{"example.com:443"},
		{"sub.example.com"},
		{"203.0.113.0/24"},
		{"203.0.113.7"},
		{"example.com", "10.0.0.0/8"},
		{"[2001:db8::]/32"},
	}
	type req struct {
		Allows []string `json:"allows"`
		Host   string   `json:"host"`
		Port   int      `json:"port"`
	}
	var reqs []any
	cases := []struct {
		list []string
		host string
		port int
	}{}
	for _, l := range allowLists {
		for _, host := range []string{
			"example.com", "EXAMPLE.com.", "sub.example.com",
			"deep.sub.example.com", "notexample.com", "example.com.evil.net",
			"203.0.113.7", "203.0.113.8", "203.0.114.1", "10.1.2.3",
			"2001:db8::1", "2001:db9::1", "", "localhost",
		} {
			for _, port := range []int{80, 443} {
				cases = append(cases, struct {
					list []string
					host string
					port int
				}{l, host, port})
				reqs = append(reqs, req{l, host, port})
			}
		}
	}
	got := runOracle(t,
		`list(m.destination_allowed([m.parse_allow_entry(a) for a in req["allows"]], req["host"], req["port"]))`,
		reqs)
	for i, tc := range cases {
		py := got[i]
		entries, err := LoadAllows(tc.list, nil, nil)
		if err != nil {
			t.Fatalf("LoadAllows(%v): %v", tc.list, err)
		}
		ok, why := DestinationAllowed(entries, tc.host, tc.port)
		goRes := [2]any{"OK", [2]any{ok, why}}
		if !sameResult(t, goRes, py) {
			t.Errorf("destination_allowed(%v, %q, %d):\n  go   = %v\n  py   = %v",
				tc.list, tc.host, tc.port, goRes, py)
		}
	}
}

func TestDifferentialBadIP(t *testing.T) {
	requireOracle(t)
	addrs := []string{
		// v4 boundaries and interesting points
		"0.0.0.0", "0.1.2.3", "0.255.255.255",
		"9.255.255.255", "10.0.0.1", "10.255.255.255",
		"100.63.255.255", "100.64.0.1", "100.127.255.255", // CGNAT
		"126.255.255.255", "127.0.0.1", "127.255.255.255",
		"169.254.0.1", "169.254.169.254", "169.255.0.1",
		"172.15.255.255", "172.16.0.1", "172.31.255.255", "172.32.0.1",
		"192.0.0.1", "192.0.0.8", "192.0.0.9", "192.0.0.10", "192.0.0.11", // anycast holes
		"192.0.1.1", "192.0.2.1",
		"192.88.99.1",
		"192.168.0.1", "192.169.0.1",
		"198.17.255.255", "198.18.0.1", "198.19.255.255",
		"198.51.100.1", "203.0.113.1",
		"223.255.255.255", "224.0.0.1", "239.1.1.1",
		"240.0.0.1", "255.255.255.254", "255.255.255.255",
		"1.1.1.1", "8.8.8.8", "93.184.216.34",
		// v6 basics
		"::", "::1", "::ffff:1.2.3.4", "::ffff:127.0.0.1", "::ffff:8.8.8.8",
		"64:ff9b::", "64:ff9b::8.8.8.8", "64:ff9b::127.0.0.1", "64:ff9b:1::1",
		"100::1", "2001::", "2001:1::1", "2001:1::2", "2001:2::1",
		"2001:3::1", "2001:4:112::1", "2001:10::1", "2001:20::1", "2001:30::1",
		"2001:db8::1", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
		"2002::", "2002::8.8.8.8", "2002:7f00:1::", "2002:c000:201::", "2002:0a00:0001::",
		"3fff::1", "3fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", "4000::1",
		"fc00::1", "fd12:3456:789a::1", "fe80::1", "febf::1", "fec0::1",
		"ff00::1", "ff02::1", "ff0e::1",
		"2001:200::1", "2606:4700::1111", "2620:fe::fe",
	}
	got := runOracle(t, `m.bad_ip(__import__("ipaddress").ip_address(req))`, toIface(addrs))
	for i, s := range addrs {
		py := got[i]
		addr, err := parseAddrForTest(s)
		if err != nil {
			t.Fatalf("parse %q: %v", s, err)
		}
		goRes := [2]any{"OK", BadIP(addr)}
		if !sameResult(t, goRes, py) {
			t.Errorf("bad_ip(%s): go=%v py=%v", s, goRes[1], py)
		}
	}
}

// sameResult compares a Go result against the oracle's, normalizing
// quoted spans inside error messages (repr vs %q).
func sameResult(t *testing.T, goRes, pyRes [2]any) bool {
	t.Helper()
	if fmt.Sprint(goRes[0]) != fmt.Sprint(pyRes[0]) {
		return false
	}
	g, p := fmt.Sprint(goRes[1]), fmt.Sprint(pyRes[1])
	if fmt.Sprint(goRes[0]) == "ERR" {
		return normQuotes(g) == normQuotes(p)
	}
	return g == p
}

func toIface[T any](s []T) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = v
	}
	return out
}

func parseAddrForTest(s string) (netip.Addr, error) { return netip.ParseAddr(s) }
