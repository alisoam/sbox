package outputfilter

// Golden attack streams cover terminal escapes, malformed UTF-8,
// strict CR handling and deterministic random input. Expected output is
// committed with the inputs, so the suite needs no external interpreter.
import (
	"encoding/json"
	"math/rand"
	"os"
	"strings"
	"syscall"
	"testing"
	"unicode"
)

type outputCase struct {
	Input   []byte `json:"input"`
	Default string `json:"default"`
	Strict  string `json:"strict"`
	Decoded string `json:"decoded"`
}

func outputCorpus(t *testing.T) []outputCase {
	t.Helper()
	data, err := os.ReadFile("testdata/corpus.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus []outputCase
	if err := json.Unmarshal(data, &corpus); err != nil {
		t.Fatal(err)
	}
	if len(corpus) < 80 {
		t.Fatalf("truncated attack corpus: %d cases", len(corpus))
	}
	return corpus
}

// Exercise whole streams, fixed splits and deterministic random splits.
func chunkings(b []byte, seed int64) [][]([]byte) {
	var out [][]([]byte)
	out = append(out, [][]byte{b})
	odd := func(n int) [][]byte {
		var cs [][]byte
		for i := 0; i < len(b); i += n {
			e := i + n
			if e > len(b) {
				e = len(b)
			}
			cs = append(cs, b[i:e])
		}
		return cs
	}
	out = append(out, odd(1), odd(2), odd(7))
	rng := rand.New(rand.NewSource(seed))
	var cs [][]byte
	for len(b) > 0 {
		n := rng.Intn(9)
		if n > len(b) {
			n = len(b)
		}
		cs = append(cs, b[:n])
		b = b[n:]
	}
	out = append(out, cs)
	return out
}

func TestSanitizerGoldenCorpus(t *testing.T) {
	for i, c := range outputCorpus(t) {
		for _, strict := range []bool{false, true} {
			want := c.Default
			if strict {
				want = c.Strict
			}
			for split, chunks := range chunkings(c.Input, int64(i)) {
				sanitizer := NewSanitizer(strict)
				var out strings.Builder
				for _, b := range chunks {
					out.WriteString(sanitizer.Feed(b))
				}
				out.WriteString(sanitizer.Flush())
				if got := out.String(); got != want {
					t.Errorf("case %d strict=%v split=%d: got %q, want %q", i, strict, split, got, want)
				}
			}
		}
	}
}

func TestDecoderGoldenCorpus(t *testing.T) {
	for i, c := range outputCorpus(t) {
		for split, chunks := range chunkings(c.Input, int64(i)+1000) {
			var decoder incDecoder
			var out strings.Builder
			for _, b := range chunks {
				out.WriteString(decoder.decode(b, false))
			}
			out.WriteString(decoder.decode(nil, true))
			if got := out.String(); got != c.Decoded {
				t.Errorf("case %d split=%d: got %q, want %q", i, split, got, c.Decoded)
			}
		}
	}
}

func TestCharacterAllowlistSafety(t *testing.T) {
	// Across the entire Unicode range, an accepted character must be
	// printable; controls, private-use and unassigned runes stay out.
	for ch := rune(0); ch <= unicode.MaxRune; ch++ {
		if charAllowed(ch) && !unicode.IsPrint(ch) {
			t.Errorf("non-printable character U+%04X accepted", ch)
		}
	}
}

func TestMakeRawGoldenFlags(t *testing.T) {
	cases := []struct{ before, after [4]uint32 }{
		{[4]uint32{0, 0, 0, 0}, [4]uint32{0, 0, 0x30, 0}},
		{[4]uint32{0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff},
			[4]uint32{0xffffe200, 0xfffffffe, 0xfffffeff, 0xffff7e04}},
		{[4]uint32{0x5fff, 0x5, 0x1af, 0x8afb}, [4]uint32{0x4200, 0x4, 0xbf, 0xa00}},
	}
	for _, c := range cases {
		term := syscall.Termios{Iflag: c.before[0], Oflag: c.before[1],
			Cflag: c.before[2], Lflag: c.before[3]}
		term.Cc[syscall.VMIN], term.Cc[syscall.VTIME] = 7, 7
		makeRaw(&term)
		got := [4]uint32{term.Iflag, term.Oflag, term.Cflag, term.Lflag}
		if got != c.after {
			t.Errorf("raw flags from %#x = %#x, want %#x", c.before, got, c.after)
		}
		if term.Cc[syscall.VMIN] != 1 || term.Cc[syscall.VTIME] != 0 {
			t.Errorf("raw reads must wait for one byte with no timer")
		}
	}
}
