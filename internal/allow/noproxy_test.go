package allow

import (
	"reflect"
	"testing"
)

func TestParseNoProxy(t *testing.T) {
	np := ParseNoProxy("example.com, .corp.example , [::1]:3128, 10.0.0.0/8, 10.1.2.3, host:8080, *, NOProxy.Org")
	if !np.Any {
		t.Errorf("'*' entry must set Any")
	}
	if want := []string{"example.com", "corp.example", "host", "noproxy.org"}; !reflect.DeepEqual(np.Names, want) {
		t.Errorf("Names = %q, want %q", np.Names, want)
	}
	var got []string
	for _, n := range np.Nets {
		got = append(got, n.String())
	}
	// CIDRs are supported and normalized with host bits masked.
	if want := []string{"::1/128", "10.0.0.0/8", "10.1.2.3/32"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Nets = %q, want %q", got, want)
	}
}

func TestParseNoProxySeparatorsAndStripping(t *testing.T) {
	// whitespace separates entries too
	if want := []string{"a.com", "b.com", "corp.example"}; !reflect.DeepEqual(ParseNoProxy("a.com b.com\tcorp.example").Names, want) {
		t.Errorf("whitespace split: Names = %q", ParseNoProxy("a.com b.com\tcorp.example").Names)
	}
	// trailing dots and leading "*." are stripped (tok.strip("*."))
	if want := []string{"example.com"}; !reflect.DeepEqual(ParseNoProxy("example.com.").Names, want) {
		t.Errorf("trailing dot: Names = %q", ParseNoProxy("example.com.").Names)
	}
	if want := []string{"example.com"}; !reflect.DeepEqual(ParseNoProxy("*.example.com").Names, want) {
		t.Errorf("leading *.: Names = %q", ParseNoProxy("*.example.com").Names)
	}
	// "10.0.0.5/8" widens to 10.0.0.0/8 (host bits masked)
	if np := ParseNoProxy("10.0.0.5/8"); len(np.Nets) != 1 || np.Nets[0].String() != "10.0.0.0/8" {
		t.Errorf("widen: Nets = %q", np.Nets)
	}
	// invalid entries are dropped, never kept as dead name entries; junk
	// with spaces splits into valid single-label names.
	np := ParseNoProxy("not a valid host!!, 10.0.0.0/8?")
	if want := []string{"not", "a", "valid"}; !reflect.DeepEqual(np.Names, want) {
		t.Errorf("junk drop: Names = %q, want %q", np.Names, want)
	}
	if len(np.Nets) != 0 {
		t.Errorf("junk drop: Nets = %q, want none", np.Nets)
	}
}

func TestNoProxyMatches(t *testing.T) {
	np := ParseNoProxy("example.com, corp.example:8080, 10.0.0.5, [2001:db8::1], *")

	// '*' matches everything
	if !np.Matches("anything.example.org") {
		t.Errorf("* must match any host")
	}
	if !np.Matches("8.8.8.8") {
		t.Errorf("* must match literal IPs")
	}

	np = ParseNoProxy("example.com, corp.example:8080, 10.0.0.5, [2001:db8::1], 172.16.0.0/12")

	cases := []struct {
		host string
		want bool
	}{
		// name entries: exact or dot-boundary suffix, any port
		{"example.com", true},
		{"EXAMPLE.com.", true},
		{"sub.example.com", true},
		{"notexample.com", false},
		{"example.com.evil.com", false},
		// host:port entries lose their port
		{"corp.example", true},
		{"sub.corp.example", true},
		{"other.example", false},
		// IP-literal hosts are matched against IP/CIDR entries only —
		// parsing the host decides its kind, so "10.0.0.5" matches net
		// entries no matter how the caller classified it.
		{"10.0.0.5", true},
		{"10.0.0.6", false},
		{"2001:db8::1", true},
		{"2001:db8::2", false},
		// CIDR entries match IP-literal destinations
		{"172.16.3.4", true},
		{"172.20.9.9", true},
		{"172.32.0.1", false},
		// names never match IP entries and vice versa
		{"8.8.8.8", false},
	}
	for _, c := range cases {
		if got := np.Matches(c.host); got != c.want {
			t.Errorf("Matches(%q) = %v, want %v", c.host, got, c.want)
		}
	}
}

func TestNoProxyFromEnv(t *testing.T) {
	env := map[string]string{}
	get := func(k string) string { return env[k] }

	if np := NoProxyFromEnv(get); np != nil {
		t.Errorf("no env: got %v, want nil", np)
	}
	env["NO_PROXY"] = "a.com"
	if np := NoProxyFromEnv(get); np == nil || !np.Matches("a.com") {
		t.Errorf("NO_PROXY fallback broken: %v", np)
	}
	// lowercase wins over uppercase
	env["no_proxy"] = "b.com"
	np := NoProxyFromEnv(get)
	if np == nil || !np.Matches("b.com") || np.Matches("a.com") {
		t.Errorf("lowercase no_proxy must win: %v", np)
	}
	// set-but-empty lowercase falls through to uppercase (like https_proxy)
	env["no_proxy"] = ""
	if np := NoProxyFromEnv(get); np == nil || !np.Matches("a.com") {
		t.Errorf("empty no_proxy must fall through to NO_PROXY: %v", np)
	}
}
