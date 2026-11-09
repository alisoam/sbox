package allow

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// The checked-in corpus fixes parsing, matching, diagnostic and address
// classification behavior independently of the host's installed software.
func readCorpus[T any](t *testing.T, name string) []T {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	var cases []T
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) == 0 {
		t.Fatal("empty contract corpus")
	}
	return cases
}

func TestParseAllowContract(t *testing.T) {
	for _, tc := range readCorpus[struct {
		Raw   string
		Entry *Entry
		Error string
	}](t, "parse_allow.json") {
		t.Run(tc.Raw, func(t *testing.T) {
			got, err := ParseAllowEntry(tc.Raw)
			if tc.Error != "" {
				if err == nil || err.Error() != tc.Error {
					t.Fatalf("error = %v, want %q", err, tc.Error)
				}
				return
			}
			if err != nil || tc.Entry == nil {
				t.Fatalf("entry = %+v, error = %v, want %+v", got, err, tc.Entry)
			}
			want := *tc.Entry
			if got.Kind != want.Kind || got.Value != want.Value ||
				got.Port != want.Port || got.Private != want.Private {
				t.Fatalf("entry = %+v, want %+v", got, want)
			}
		})
	}
}

func TestDestinationAllowedContract(t *testing.T) {
	for _, tc := range readCorpus[struct {
		Allows  []string
		Host    string
		Port    int
		Allowed bool
		Reason  string
	}](t, "destination_allowed.json") {
		entries, err := LoadAllows(tc.Allows, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		ok, why := DestinationAllowed(entries, tc.Host, tc.Port)
		if ok != tc.Allowed || why != tc.Reason {
			t.Errorf("allows %v, %q:%d = (%v, %q), want (%v, %q)",
				tc.Allows, tc.Host, tc.Port, ok, why, tc.Allowed, tc.Reason)
		}
	}
}

func TestBlockedAddressesContract(t *testing.T) {
	for _, tc := range readCorpus[struct {
		Address string
		Blocked bool
	}](t, "blocked_addresses.json") {
		if got := BadIP(netip.MustParseAddr(tc.Address)); got != tc.Blocked {
			t.Errorf("BadIP(%s) = %v, want %v", tc.Address, got, tc.Blocked)
		}
	}
}
