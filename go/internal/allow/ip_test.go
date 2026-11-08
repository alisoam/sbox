package allow

import (
	"net/netip"
	"testing"
)

// TestBadIPv4 and TestBadIPv6 pin bad_ip's verdicts. The expected values
// were derived by running sbox.py's bad_ip() on CPython 3.15 (the union of
// is_private/is_reserved/is_loopback/is_link_local/is_multicast/
// is_unspecified plus CGNAT), so the Go port is pinned to one deterministic
// ground truth.
func TestBadIPv4(t *testing.T) {
	cases := []struct {
		addr string
		bad  bool
	}{
		{"0.0.0.0", true},  // "this network" (unspecified lives here too)
		{"0.1.2.3", true},  //
		{"10.0.0.1", true}, // RFC 1918
		{"100.63.255.255", false},
		{"100.64.0.1", true}, // CGNAT
		{"100.127.255.254", true},
		{"100.128.0.1", false}, //
		{"127.0.0.1", true},    // loopback
		{"169.253.1.1", false}, //
		{"169.254.0.1", true},  // link-local
		{"169.254.169.254", true},
		{"169.255.1.1", false}, //
		{"172.15.255.255", false},
		{"172.16.0.1", true}, // RFC 1918
		{"172.31.255.255", true},
		{"172.32.0.1", false},  //
		{"192.0.0.1", true},    // IETF protocol assignments
		{"192.0.0.8", true},    //
		{"192.0.0.9", false},   // PCP anycast: globally reachable hole
		{"192.0.0.10", false},  // NAT64 anycast: globally reachable hole
		{"192.0.0.170", true},  // NAT64 anycast counterpart pair
		{"192.0.1.1", false},   //
		{"192.0.2.1", true},    // TEST-NET-1
		{"192.88.99.1", false}, // 6to4 relay anycast: reachable
		{"192.168.0.1", true},  // RFC 1918
		{"198.17.1.1", false},  //
		{"198.18.0.1", true},   // benchmarking
		{"198.19.255.255", true},
		{"198.20.0.1", false},  //
		{"198.51.100.1", true}, // TEST-NET-2
		{"203.0.113.1", true},  // TEST-NET-3
		{"223.255.255.255", false},
		{"224.0.0.1", true}, // multicast
		{"239.255.255.255", true},
		{"240.0.0.1", true}, // reserved for future use
		{"250.0.0.1", true}, //
		{"255.255.255.254", true},
		{"255.255.255.255", true},
		{"8.8.8.8", false}, //
		{"1.1.1.1", false}, //
	}
	for _, c := range cases {
		if got := BadIP(netip.MustParseAddr(c.addr)); got != c.bad {
			t.Errorf("BadIP(%s) = %v, want %v", c.addr, got, c.bad)
		}
	}
}

func TestBadIPv6(t *testing.T) {
	cases := []struct {
		addr string
		bad  bool
	}{
		// plain predicates
		{"::", true},              // unspecified (+ ::/8)
		{"::1", true},             // loopback
		{"::2", true},             // ::/8 reserved
		{"::00ff:1", true},        // last block of ::/8
		{"::0100:1", true},        // still ::/8 (leading zeros are address zeros)
		{"::1.2.3.4", true},       // compat form, inside ::/8
		{"::ffff:0:0", true},      // v4-mapped 0.0.0.0 -> judged as v4
		{"::ffff:1.2.3.4", false}, // judged as public 1.2.3.4
		{"::ffff:8.8.8.8", false}, //
		{"::ffff:127.0.0.1", true},
		{"100::", true},          // discard-only
		{"2001:1::1", false},     // globally reachable hole (Teredo ports)
		{"2001:1::2", false},     //
		{"2001:2::1", true},      // inside 2001::/23 (benchmarking v6)
		{"2001:3::1", false},     // AMT hole
		{"2001:4:112::1", false}, // AS112-v6 hole
		{"2001:20::1", false},    // ORCHIDv2 hole
		{"2001:30::1", false},    // Drone Remote ID hole
		{"2001:db8::1", true},    // documentation
		{"2001:4860:4860::8888", false},
		{"3fff::1", true},       // benchmarking (new registry)
		{"3fff:ffff::1", false}, //
		{"4000::1", true},       // reserved unallocated space
		{"5fff::1", true},       //
		{"64:ff9b:1::", true},   // local-use NAT64
		{"fc00::1", true},       // ULA
		{"fd00::1", true},       //
		{"fe80::1", true},       // link-local
		{"fe80::ffff", true},    //
		{"fec0::1", false},      // deprecated site-local: NOT guarded
		{"ff00::1", true},       // multicast
		{"ff02::1", true},       //
		{"ffff::1", true},       //
		{"2606:4700::1111", false},
		// NAT64 (64:ff9b::/96): judge the embedded IPv4, not the prefix
		{"64:ff9b::", true},          // embedded 0.0.0.0
		{"64:ff9b::1.2.3.4", false},  // public embedded
		{"64:ff9b::8.8.8.8", false},  //
		{"64:ff9b::127.0.0.1", true}, // loopback embedded
		{"64:ff9b::10.0.0.1", true},  // RFC 1918 embedded
		{"64:ff9b::0.0.0.0", true},   //
		{"64:ff9b::255.255.255.255", true},
		{"64:ff9b::192.0.2.1", true}, // TEST-NET-1 embedded
		// (no "outside 64:ff9b::/96 but global" address exists to test:
		// the whole 00xx first-hextet space is ::/8 reserved anyway)
		// 6to4 (2002::/16): judge bits 16..47
		{"2002::", true},           // embedded 0.0.0.0
		{"2002:101:101::", false},  // embedded 1.1.1.1
		{"2002:101:101::1", false}, //
		{"2002:7f00:1::", true},    // embedded 127.0.0.1 (SSRF vector)
		{"2002:0a00:0001::", true}, // embedded 10.0.0.1
		{"2002:c000:0201::", true}, // embedded 192.0.2.1
		// Teredo (2001:0::/32): refuse the whole prefix
		{"2001:0::1", true},
		{"2001::", true}, // == 2001:0000::, inside the Teredo /32
	}
	for _, c := range cases {
		if got := BadIP(netip.MustParseAddr(c.addr)); got != c.bad {
			t.Errorf("BadIP(%s) = %v, want %v", c.addr, got, c.bad)
		}
	}
}

func TestBadIPInvalid(t *testing.T) {
	if !BadIP(netip.Addr{}) {
		t.Errorf("BadIP(zero Addr) = false, want true (unusable answers are bad)")
	}
}

// TestZoneEntries pins zone-scoped entries: the canonical value keeps the
// zone like str(ip_network(...)) in Python, while matching is zone-blind
// like ipaddress's integer __contains__.
func TestZoneEntries(t *testing.T) {
	e := mustEntry(t, "fe80::1%eth0")
	if e.Kind != "net" || e.Value != "fe80::1%eth0/128" {
		t.Errorf("zoned entry = {%s %q}, want net fe80::1%%eth0/128", e.Kind, e.Value)
	}
	allows := []Entry{e}
	if ok, _ := DestinationAllowed(allows, "fe80::1", 80); !ok {
		t.Errorf("zone-blind matching: zone-less destination must match zoned entry (python semantics)")
	}
	if ok, _ := DestinationAllowed(allows, "fe80::1%other", 80); !ok {
		t.Errorf("zone-blind matching: zoned destination must match zoned entry")
	}
	if ok, _ := DestinationAllowed(allows, "fe80::2", 80); ok {
		t.Errorf("fe80::2 must not match the fe80::1 zoned entry")
	}
	// ... and vice versa: a zone-less entry matches zoned destinations
	allows = []Entry{mustEntry(t, "fe80::1")}
	if ok, _ := DestinationAllowed(allows, "fe80::1%eth0", 80); !ok {
		t.Errorf("zone-less entry must match zoned destination")
	}
}
