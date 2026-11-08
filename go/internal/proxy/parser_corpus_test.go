package proxy

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

// This corpus preserves accepted inputs and failure cases for CONNECT targets
// and upstream URLs, including legacy spellings and ambiguous delimiters.
func TestParserCorpus(t *testing.T) {
	var corpus struct {
		HostPort []struct {
			Input string
			Host  string
			Port  int
			Error bool
		} `json:"host_port"`
		Upstream []struct {
			Input    string
			Upstream *Upstream
			Error    bool
		} `json:"upstream"`
	}
	data, err := os.ReadFile("testdata/parsing.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	for _, tc := range corpus.HostPort {
		t.Run("target/"+tc.Input, func(t *testing.T) {
			host, port, err := ParseHostPort(tc.Input, 80)
			if (err != nil) != tc.Error || (!tc.Error && (host != tc.Host || port != tc.Port)) {
				t.Errorf("got (%q, %d, %v), want (%q, %d), error=%v",
					host, port, err, tc.Host, tc.Port, tc.Error)
			}
		})
	}
	for _, tc := range corpus.Upstream {
		t.Run("upstream/"+tc.Input, func(t *testing.T) {
			got, err := ParseUpstream(tc.Input, false)
			if (err != nil) != tc.Error || (!tc.Error && !reflect.DeepEqual(got, tc.Upstream)) {
				t.Errorf("got (%+v, %v), want %+v, error=%v", got, err, tc.Upstream, tc.Error)
			}
		})
	}
}
