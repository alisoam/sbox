package outputfilter

// The sanitizer behavior table — the ported essence of the
// test_sandbox.py sanitizer suite (the module docstring, the
// OutputSanitizer docstring and the epilog are the spec): allowlist
// semantics in both strict_cr modes, the SGR grammar, conceal
// detection, C0 interleaving, the string/escape states, the pending
// cap, stateful UTF-8 replacement, and the chunk-boundary equivalence
// property (filter identically no matter how the stream is split).
// Every expectation that looked surprising was verified byte-exact
// against the repo's sbox.py before being pinned here.

import (
	"math/rand"
	"strings"
	"testing"
)

// feedAll feeds chunks through a fresh sanitizer and flushes.
func feedAll(t *testing.T, strict bool, chunks ...[]byte) string {
	t.Helper()
	s := NewSanitizer(strict)
	var out strings.Builder
	for _, c := range chunks {
		out.WriteString(s.Feed(c))
	}
	out.WriteString(s.Flush())
	return out.String()
}

func TestSanitizerPlainPasses(t *testing.T) {
	for _, in := range []string{
		"hello world", "unicode: äöü é 漢字 😀", "tabs\tand\nnewlines\r\nmixed",
		"printable symbols !@#$%^&*()_+-=[]{}|;':\",./<>?`~",
	} {
		if got := feedAll(t, false, []byte(in)); got != in {
			t.Errorf("Feed(%q) = %q, want unchanged", in, got)
		}
	}
}

func TestSanitizerControls(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"a\x00b", "ab"},     // NUL dropped
		{"a\x07b", "ab"},     // BEL dropped in plain text
		{"a\x1fb", "ab"},     // C0 dropped
		{"a\x7fb", "ab"},     // DEL dropped
		{"ab", "ab"},        // C1 CSI (U+009B) dropped as a character
		{"ab", "ab"},        // C1 OSC (U+009D) dropped, opens no string
		{"a b", "ab"},        // NBSP dropped (Zs, not printable)
		{"a­b", "ab"},        // soft hyphen dropped (Cf)
		{"a‏b", "ab"},        // RLM dropped
		{"a b", "ab"},        // line separator dropped (Zl)
		{"a\x0bb", "ab"},     // VT dropped
		{"a\x0cb", "ab"},     // FF dropped
		{"a\rb", "a\rb"},     // \r passes (non-strict)
		{"a\nb", "a\nb"},     // \n passes
		{"a\tb", "a\tb"},     // \t passes
		{"a\x1b", "a"},       // trailing lone ESC dropped at flush
		{"\ufffd", "\ufffd"}, // U+FFFD itself is printable: passes
		{"a\xadb", "a�b"},    // raw byte 0xAD: stray continuation → U+FFFD, passes
	}
	for _, c := range cases {
		if got := feedAll(t, false, []byte(c.in)); got != c.want {
			t.Errorf("Feed(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizerBidiZeroWidthBlankFillers(t *testing.T) {
	// The whole smuggler list from _char_allowed, each dropped in
	// place; U+FE0F is the ONE variation selector kept.
	dropped := []rune{
		0x200B, 0x200C, 0x200D, 0x200E, 0x200F, // ZWSP ZWNJ ZWJ LRM RLM
		0x202A, 0x202B, 0x202C, 0x202D, 0x202E, // bidi overrides
		0x2060, 0x2066, 0x2067, 0x2068, 0x2069, // word joiner, isolates
		0xFEFF,                                 // BOM
		0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0, // blank fillers
		0x034F,                                   // combining grapheme joiner
		0xFE00, 0xFE01, 0xFE0E, 0xE0100, 0xE01EF, // variation selectors
	}
	for _, r := range dropped {
		if charAllowed(r) {
			t.Errorf("charAllowed(U+%04X) = true, want dropped", r)
		}
		in := "a" + string(r) + "b"
		if got := feedAll(t, false, []byte(in)); got != "ab" {
			t.Errorf("Feed(%q) = %q, want %q", in, got, "ab")
		}
	}
	for _, r := range []rune{0xFE0F, 'x', 'ö', '😀', '中', ' ', 0x180B} {
		if !charAllowed(r) {
			t.Errorf("charAllowed(U+%04X) = false, want kept", r)
		}
	}
}

func TestSanitizerSGR(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"\x1b[31mred\x1b[0m", "\x1b[31mred\x1b[0m"},     // plain SGR
		{"\x1b[m", "\x1b[m"},                             // empty params = reset
		{"\x1b[0;1;38;5;9m", "\x1b[0;1;38;5;9m"},         // extended color, index 9 fine
		{"\x1b[48;2;10;20;30m", "\x1b[48;2;10;20;30m"},   // truecolor bg
		{"\x1b[38;5;8m", "\x1b[38;5;8m"},                 // color index 8 is NOT conceal
		{"\x1b[007m", "\x1b[007m"},                       // leading zeros, param 7
		{"\x1b[8m", ""},                                  // conceal
		{"\x1b[08m", ""},                                 // conceal, leading zero
		{"\x1b[0008m", ""},                               // conceal, more zeros
		{"\x1b[1;8m", ""},                                // bold+conceal: whole seq dropped
		{"\x1b[38;5;8;8m", ""},                           // index 8 THEN conceal: dropped
		{"\x1b[48;2;1;2;3;8m", ""},                       // truecolor args then 8: dropped
		{"\x1b[3:4m", ""},                                // colon subparameters fail the grammar
		{"\x1b[?25l", ""},                                // private marker (DECTCEM)
		{"\x1b[>c", ""},                                  // secondary device attrs query
		{"\x1b[2J", ""},                                  // clear screen
		{"\x1b[1;2H", ""},                                // cursor move
		{"\x1b[38;5;8m\x1b[31m", "\x1b[38;5;8m\x1b[31m"}, // each sequence judged alone
	}
	for _, c := range cases {
		if got := feedAll(t, false, []byte(c.in)); got != c.want {
			t.Errorf("Feed(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// >64 parameter chars: the grammar itself fails.
	long := "\x1b[" + strings.Repeat("1;", 33) + "m"
	if got := feedAll(t, false, []byte(long)); got != "" {
		t.Errorf("66-char SGR params = %q, want dropped", got)
	}
	// exactly 64 passes
	ok := "\x1b[" + strings.Repeat("1", 64) + "m"
	if got := feedAll(t, false, []byte(ok)); got != ok {
		t.Errorf("64-char SGR params = %q, want kept", got)
	}
}

func TestSanitizerStringsAndEscapes(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		// OSC, BEL-terminated (the OSC 52 clipboard attack from the epilog)
		{"\x1b]52;c:aGk=\x07visible", "visible"},
		// OSC with ST terminator
		{"\x1b]0;window title\x1b\\visible", "visible"},
		// DCS / APC / PM / SOS, ST-terminated
		{"\x1bP1;2q payload\x1b\\ok", "ok"},
		{"\x1b_seq\x1b\\ok", "ok"},
		{"\x1b^pm\x1b\\ok", "ok"},
		{"\x1bXsos\x1b\\ok", "ok"},
		// ESC ESC inside a string is not a terminator
		{"\x1b]0;t\x1b\x1b\\ok", "ok"},
		// 2-byte escapes: never allowed
		{"\x1bMok", "ok"},        // RI
		{"\x1b7ok", "ok"},        // save cursor
		{"\x1b(Bok", "ok"},       // intermediate + final (charset)
		{"\x1b(0\x1b)Bok", "ok"}, // two charsets
		{"\x1b#8ok", "ok"},       // DECALN: intermediate '#'
		// CAN aborts a pending CSI; the rest is plain text
		{"\x1b[3\x18m", "m"},
		// SUB aborts too
		{"\x1b[3\x1am", "m"},
		// CAN aborts a pending string
		{"\x1b]52;c:aGk=\x18ok", "ok"},
		// a new ESC restarts a pending CSI
		{"\x1b[3\x1b[31m", "\x1b[31m"},
		// a new ESC restarts a pending ESC-intermediate
		{"\x1b(\x1b[31m", "\x1b[31m"},
		// C0 interleaved in a pending CSI is EXECUTED, not swallowed
		{"\x1b[3\n1m", "\n\x1b[31m"},
		{"\x1b[3\t1m", "\t\x1b[31m"},
		{"\x1b[3\x001m", "\x1b[31m"}, // NUL executed (dropped), sequence survives
		// a stray ESC before \n must not eat the newline — but the
		// character AFTER the newline is a legitimate 2-byte-escape
		// final byte and goes with it (python-verified)
		{"\x1b\nx", "\n"},
		{"\x1b[\n", "\n"},
		// C0 inside an ESC-intermediate waits too
		{"\x1b(\nBok", "\nok"},
		// C1 swallowed inside a sequence body (never an initiator): the
		// sequence keeps waiting and the following bytes complete it
		// (python-verified)
		{"\x1b[31m", "\x1b[31m"},
		// non-ASCII swallowed in the ESC state, then a fresh CSI builds
		{"\x1bä[31m", "\x1b[31m"},
		// unterminated sequences dropped at flush
		{"\x1b[31", ""},
		{"\x1b]0;title", ""},
		{"\x1b(", ""},
		{"\x1b", ""},
		{"ok\x1b]0;t", "ok"},
	}
	for _, c := range cases {
		if got := feedAll(t, false, []byte(c.in)); got != c.want {
			t.Errorf("Feed(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizerPendingCapASCII(t *testing.T) {
	// An unterminated CSI sequence past 4096 pending bytes is dropped
	// wholesale — the drop lands mid-pair ('1' of pair 2048 pushes the
	// byte counter to 4097) — and everything after the drop point is
	// plain text: ';' plus the remaining pairs, then "after"
	// (python-verified: len 110).
	in := "\x1b[" + strings.Repeat("1;", 2100) + "after"
	want := ";" + strings.Repeat("1;", 52) + "after"
	if got := feedAll(t, false, []byte(in)); got != want {
		t.Errorf("ascii cap: got len %d %q..., want len %d %q...",
			len(got), firstN(got, 20), len(want), firstN(want, 20))
	}
}

func TestSanitizerPendingCapCountsBytes(t *testing.T) {
	// The cap counts UTF-8 BYTES, not codepoints — only observable in
	// a STRING body (OSC content accepts any character; CSI bodies
	// only take 0x20..0x3F ASCII). 2048 é (2 bytes each) + "ESC ]"
	// crosses 4096 at é #2048; the remaining 952 é are plain text
	// (python-verified: 957 chars).
	in := "\x1b]" + strings.Repeat("é", 3000) + "\x07" + "after"
	want := strings.Repeat("é", 952) + "after" // BEL dropped as C0
	if got := feedAll(t, false, []byte(in)); got != want {
		t.Errorf("byte cap: got len %d, want len %d", len(got), len(want))
	}
}

func TestSanitizerNonASCIIInCSIBodyNeverCaps(t *testing.T) {
	// é in a CSI body is SWALLOWED (not appended — only 0x20..0x3F
	// bytes grow the sequence), so a thousand of them never reach the
	// cap; the 3000 semicolons do grow it, 'm' completes a >64-char
	// parameter string and the grammar drops it. Output: just the tail
	// (python-verified: " ok").
	in := "\x1b[" + strings.Repeat("é;", 3000) + "m ok"
	if got := feedAll(t, false, []byte(in)); got != " ok" {
		t.Errorf("csi body: got %q, want %q", firstN(got, 30), " ok")
	}
}

func firstN(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}

func TestSanitizerStrictCr(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"a\r\nb", "a\r\nb"},   // CRLF survives
		{"a\rb", "ab"},         // bare \r dropped
		{"\r\n", "\r\n"},       // leading CRLF
		{"a\r", "a"},           // trailing bare \r dropped at flush
		{"a\rb\rc", "abc"},     // multiple bare \r
		{"\ra\n", "a\n"},       // bare \r then newline: \r gone, \n kept
		{"a\r\r\nb", "a\r\nb"}, // \r \r \n: first \r bare (next is \r), CRLF kept
		{"\r", ""},             // lone \r at flush
	}
	for _, c := range cases {
		if got := feedAll(t, true, []byte(c.in)); got != c.want {
			t.Errorf("strict Feed(%q) = %q, want %q", c.in, got, c.want)
		}
	}
	// \r held across feed boundaries: split right after it, in both
	// directions.
	if got := feedAll(t, true, []byte("a\r"), []byte("\nb")); got != "a\r\nb" {
		t.Errorf("strict split CRLF = %q, want %q", got, "a\r\nb")
	}
	if got := feedAll(t, true, []byte("a\r"), []byte("b")); got != "ab" {
		t.Errorf("strict split bare CR = %q, want %q", got, "ab")
	}
	// \r interleaved in a pending sequence, strict mode: deferred with
	// the same one-byte lookahead, the sequence keeps waiting.
	if got := feedAll(t, true, []byte("\x1b[3\r\n1m")); got != "\r\n\x1b[31m" {
		t.Errorf("strict CSI CR = %q, want %q", got, "\r\n\x1b[31m")
	}
	// non-strict keeps every \r
	if got := feedAll(t, false, []byte("a\rb")); got != "a\rb" {
		t.Errorf("non-strict bare CR = %q", got)
	}
}

// The UTF-8 replacement table — byte-exact against CPython's
// incremental decoder with errors='replace' (pinned live by the
// differential test): one U+FFFD per invalid start byte, one per
// maximal subpart elsewhere, surrogates/overlongs/out-of-range one per
// byte, truncation one per maximal subpart at flush. NOTE these wants
// are SANITIZER-level: a decoded-but-nonprintable rune (U+FFFE, the
// U+10FFFF roof — both Cn) is then dropped by the character allowlist,
// exactly like Python.
func TestSanitizerUTF8Replacement(t *testing.T) {
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("h\xffi"), "h\ufffdi"},
		{[]byte("\xff\xff"), "\ufffd\ufffd"},
		{[]byte("\xc3\x28"), "\ufffd("},                          // 2-byte lead + '('
		{[]byte("\xc0\xaf"), "\ufffd\ufffd"},                     // overlong: C0 is an invalid start
		{[]byte("\xe0\x80\x80"), "\ufffd\ufffd\ufffd"},           // overlong 3-byte
		{[]byte("\xed\xa0\x80"), "\ufffd\ufffd\ufffd"},           // surrogate
		{[]byte("\xf4\x90\x80\x80"), "\ufffd\ufffd\ufffd\ufffd"}, // > U+10FFFF
		{[]byte("\xf5\x80\x80\x80"), "\ufffd\ufffd\ufffd\ufffd"}, // F5 out of range
		{[]byte("\xfe"), "\ufffd"},
		{[]byte("\x80"), "\ufffd"},
		{[]byte("\xef\xbf\xbe"), ""},     // U+FFFE decodes, then dropped (nonprintable Cn)
		{[]byte("\xf4\x8f\xbf\xbf"), ""}, // U+10FFFF ditto
		{[]byte("\xc2"), "\ufffd"},       // truncated at flush
		{[]byte("\xe0\xa0"), "\ufffd"},
		{[]byte("\xe2\x82"), "\ufffd"},
		{[]byte("\xf0\x9f"), "\ufffd"},
		{[]byte("\xf0\x9f\x98"), "\ufffd"},
		{[]byte("\xf0\x28\x8c\xbc"), "\ufffd(\ufffd\ufffd"}, // broken at byte 1
		{[]byte("\xf0\x9f\x98\x28"), "\ufffd("},             // broken at byte 3
		{[]byte("h\xc3\xa9llo"), "héllo"},                   // valid multibyte passes
		{[]byte("\xf0\x9f\x98\x80abc"), "😀abc"},             // astral passes
		{[]byte("a\xc2A"), "a\ufffdA"},                      // 'A' re-scanned after the broken pair
	}
	for _, c := range cases {
		if got := feedAll(t, false, c.in); got != c.want {
			t.Errorf("Feed(% X) = %q, want %q", c.in, got, c.want)
		}
	}
	// split multibyte characters survive across feed boundaries
	if got := feedAll(t, false, []byte("h\xc3"), []byte("\xa9llo")); got != "héllo" {
		t.Errorf("split é = %q", got)
	}
	if got := feedAll(t, false, []byte("\xf0\x9f"), []byte("\x98\x80!")); got != "😀!" {
		t.Errorf("split emoji = %q", got)
	}
	// held, then broken: an incomplete tail held across feeds is
	// judged when the next byte breaks it
	if got := feedAll(t, false, []byte("a\xc3"), []byte("b")); got != "a\ufffdb" {
		t.Errorf("held then broken = %q", got)
	}
}

// The chunk-boundary equivalence property, both modes: whole-stream ==
// every possible 2-way split == per-byte == random splits (empty
// chunks included — Feed with no data is a no-op).
func TestSanitizerChunkEquivalence(t *testing.T) {
	corpus := []string{
		"plain text, nothing special",
		"\x1b[31mred\x1b[0m and \x1b]52;c:zz\x07ok",
		"\x1bP data \x1b\\ \x1bX more \x1b^ pm \x1b_ apc",
		"a\rb\rc\r\nd\re",
		"\x1b[3\x18m\x1b[3\n1m\x1bM",
		"h\xc3\xa9llo \xed\xa0\x80 \xf0\x9f\x98\x80 \xf0\x9f\x98\xc2",
		"héllo \xc3 trailing\xc2",
		"emoji 😀❤️ with FE0F kept",
		"\u202Ereversed\u202E drop me",
		"\x1b]0;title with \x1b\\\x1b(Bok",
		"\x1b[\x1b[\x1b[31m",
		"\r\r\r\n\r\n\r",
		"\x1b[8m hidden \x1b[38;5;8;8m more",
	}
	rng := rand.New(rand.NewSource(7))
	for _, in := range corpus {
		for _, strict := range []bool{false, true} {
			want := feedAll(t, strict, []byte(in))
			b := []byte(in)
			// every 2-way split
			for i := 0; i <= len(b); i++ {
				got := feedAll(t, strict, b[:i], b[i:])
				if got != want {
					t.Fatalf("strict=%v split@%d %q: %q != %q", strict, i, in, got, want)
				}
			}
			// per-byte
			chunks := make([][]byte, len(b))
			for i := range b {
				chunks[i] = b[i : i+1]
			}
			if got := feedAll(t, strict, chunks...); got != want {
				t.Fatalf("strict=%v per-byte %q: %q != %q", strict, in, got, want)
			}
			// random splits with empty chunks sprinkled in
			for trial := 0; trial < 8; trial++ {
				var cs [][]byte
				src := b
				for len(src) > 0 {
					n := rng.Intn(5)
					if n == 0 {
						cs = append(cs, nil) // an empty chunk mid-stream
						continue
					}
					if n > len(src) {
						n = len(src)
					}
					cs = append(cs, src[:n])
					src = src[n:]
				}
				if got := feedAll(t, strict, cs...); got != want {
					t.Fatalf("strict=%v random %q: %q != %q", strict, in, got, want)
				}
			}
		}
	}
}

// A heavier randomized equivalence pass: arbitrary bytes through the
// full state machine (both modes), whole vs random splits. The
// expected value is the implementation against itself across chunking
// — the Python-exact values are pinned by the differential test.
func TestSanitizerRandomChunkEquivalence(t *testing.T) {
	rng := rand.New(rand.NewSource(42))
	interesting := []byte("\x1b[]P_^X\\07\x18\x1a\n\r\tm;?0123456789abÄé😀\xff\x80\xc0\xf0\x9f\xed")
	for round := 0; round < 200; round++ {
		n := rng.Intn(400)
		b := make([]byte, n)
		for i := range b {
			if rng.Intn(3) == 0 {
				b[i] = interesting[rng.Intn(len(interesting))]
			} else {
				b[i] = byte(rng.Intn(256))
			}
		}
		for _, strict := range []bool{false, true} {
			want := feedAll(t, strict, b)
			var cs [][]byte
			src := b
			for len(src) > 0 {
				k := rng.Intn(7)
				if k > len(src) {
					k = len(src)
				}
				cs = append(cs, src[:k])
				src = src[k:]
			}
			if got := feedAll(t, strict, cs...); got != want {
				t.Fatalf("round %d strict=%v: chunked differs (input % X)", round, strict, b)
			}
		}
	}
}

func TestSGRConceals(t *testing.T) {
	cases := []struct {
		params string
		want   bool
	}{
		{"", false},
		{"0", false},
		{"1", false},
		{"8", true},
		{"08", true},
		{"0008", true},
		{"888", false}, // 888 ≠ 8
		{"8;", true},   // first param 8
		{";8", true},
		{"1;8", true},
		{"38;5;8", false}, // color index 8
		{"38;5;08", false},
		{"48;2;1;2;3", false},  // truecolor args
		{"48;2;1;2;3;8", true}, // ...then a real 8
		{"38;5;8;8", true},     // index 8 then conceal
		{"38;2;1;2;3", false},  // RGB fg
		{"38;2;1;2;3;8", true}, // RGB fg then conceal
		{"38", false},          // no args: plain param 38
		{"38;8", true},         // unknown extended form degrades to scanning
		{"38;9;8", true},       // ditto
		{"48", false},
		{"1;38;5;8;0", false},     // conceal-free with 38;5;8 inside
		{"1;38;2;8;8;8;0", false}, // 38;2;8;8;8: the 8s are RGB args
	}
	for _, c := range cases {
		if got := sgrConceals(c.params); got != c.want {
			t.Errorf("sgrConceals(%q) = %v, want %v", c.params, got, c.want)
		}
	}
}

func TestSGRParamsGrammar(t *testing.T) {
	ok := []string{"", "0", "38;5;8", ";;;;", "0123456789", strings.Repeat(";", 64)}
	bad := []string{
		":", "3:4", "?25", "1 m", "1; m", "１", strings.Repeat("1", 65), "-1", "1.2",
	}
	for _, p := range ok {
		if !sgrParamsOK(p) {
			t.Errorf("sgrParamsOK(%q) = false, want true", p)
		}
	}
	for _, p := range bad {
		if sgrParamsOK(p) {
			t.Errorf("sgrParamsOK(%q) = true, want false", p)
		}
	}
}

func TestSanitizerFlushIsTerminal(t *testing.T) {
	// Everything the sanitizer holds back (incomplete sequence, held
	// \r, undecoded tail) is decided by Flush; a second Flush yields
	// nothing, and the sanitizer is reusable afterwards.
	s := NewSanitizer(true)
	out := s.Feed([]byte("a\r\x1b[31"))
	if out != "a" {
		t.Errorf("pre-flush = %q, want %q", out, "a")
	}
	if out := s.Flush(); out != "" {
		t.Errorf("flush = %q, want empty (the \\r was bare, the sequence malformed)", out)
	}
	if out := s.Flush(); out != "" {
		t.Errorf("second flush = %q, want empty", out)
	}
	if out := s.Feed([]byte("ok")); out != "ok" {
		t.Errorf("post-flush feed = %q", out)
	}
}

func TestDecoderByteForByteCPython(t *testing.T) {
	// The exact inputs probed against the live CPython 3.15 decoder
	// while writing the port — the algorithm's contract in one table.
	cases := []struct {
		in   []byte
		want string
	}{
		{[]byte("\xff"), "\ufffd"},
		{[]byte("\xff\xff"), "\ufffd\ufffd"},
		{[]byte("\xc3\x28"), "\ufffd("},
		{[]byte("\xc0\xaf"), "\ufffd\ufffd"},
		{[]byte("\xe0\x80\x80"), "\ufffd\ufffd\ufffd"},
		{[]byte("\xed\xa0\x80"), "\ufffd\ufffd\ufffd"},
		{[]byte("\xf4\x90\x80\x80"), "\ufffd\ufffd\ufffd\ufffd"},
		{[]byte("\xf0\x9f"), "\ufffd"},
		{[]byte("\xc2"), "\ufffd"},
		{[]byte("\xf0\x9f\x98"), "\ufffd"},
		{[]byte("\xe0\xa0"), "\ufffd"},
		{[]byte("\xf0\x28\x8c\xbc"), "\ufffd(\ufffd\ufffd"},
		{[]byte("\xf0\x9f\x98\x28"), "\ufffd("},
		{[]byte("\xe2\x82"), "\ufffd"},
		{[]byte("\xc2\x41"), "\ufffdA"},
		{[]byte("\xf5\x80\x80\x80"), "\ufffd\ufffd\ufffd\ufffd"},
		{[]byte("\xfe"), "\ufffd"},
		{[]byte("\x80"), "\ufffd"},
		{[]byte("\xed\xbf\xbf"), "\ufffd\ufffd\ufffd"},
		{[]byte("\xef\xbf\xbe"), "￾"},
		{[]byte("\xf4\x8f\xbf\xbf"), "\U0010ffff"},
		{[]byte("\xf0\x9f\x98\x80abc"), "😀abc"},
	}
	for _, c := range cases {
		var d incDecoder
		got := d.decode(c.in, true)
		if got != c.want {
			t.Errorf("decode(% X) = % X, want % X", c.in, got, c.want)
		}
		// 1-byte-at-a-time must agree (python's incremental contract)
		var d2 incDecoder
		var acc string
		for i := range c.in {
			acc += d2.decode(c.in[i:i+1], false)
		}
		acc += d2.decode(nil, true)
		if acc != c.want {
			t.Errorf("decode(% X) per-byte = % X, want % X", c.in, acc, c.want)
		}
	}
	// holding: a truncated prefix survives an empty feed
	var d incDecoder
	if out := d.decode([]byte("\xf0\x9f"), false); out != "" {
		t.Errorf("held prefix emitted %q", out)
	}
	if out := d.decode(nil, false); out != "" {
		t.Errorf("empty feed emitted %q", out)
	}
	if out := d.decode([]byte("\x98\x80"), false); out != "😀" {
		t.Errorf("completed emoji = %q", out)
	}
}

func TestCharAllowedBoundaries(t *testing.T) {
	// Each range edge of the drop list and the isprintable floor,
	// both sides (all python-verified).
	keep := []rune{
		0x20,   // space: the one allowed separator
		0x7E,   // '~' — top of printable ASCII, DEL starts at 0x7F
		0xA1,   // '¡' — first printable after the C1/NBSP block
		0x2010, // hyphen (Pd), just past the bidi block's Zs neighbor
		0x2030, // '‰' (Po), just past U+202F narrow NBSP (Zs)
		0x2160, // Ⅰ (Nl), just past the bidi override block
	}
	drop := []rune{
		0x1F,   // last C0
		0x7F,   // DEL
		0x9F,   // last C1
		0xA0,   // NBSP (Zs)
		0xAD,   // soft hyphen (Cf)
		0x200A, // hair space (Zs), just before the zero-width block
		0x200B, // ZWSP: the zero-width block starts
		0x2029, // paragraph separator (Zp)
		0x202A, // bidi block starts (LRE)
		0x202F, // narrow NBSP (Zs)
	}
	for _, r := range keep {
		if !charAllowed(r) {
			t.Errorf("charAllowed(U+%04X) = false, want true", r)
		}
	}
	for _, r := range drop {
		if charAllowed(r) {
			t.Errorf("charAllowed(U+%04X) = true, want false", r)
		}
	}
}

func TestSanitizerSGRPassesThroughVerbatim(t *testing.T) {
	// A passing SGR sequence must come out byte-identical (not
	// re-rendered): params with runs of semicolons and leading zeros
	// survive as-is.
	in := "\x1b[;;007;38;5;8;;;m"
	if got := feedAll(t, false, []byte(in)); got != in {
		t.Errorf("verbatim SGR: %q != %q", got, in)
	}
}

func TestSanitizerSplitEscapeStates(t *testing.T) {
	// Held-back incomplete sequences complete from a later chunk in
	// every state.
	cases := []struct{ first, rest, want string }{
		{"\x1b", "[31m", "\x1b[31m"},
		{"\x1b[", "31m", "\x1b[31m"},
		{"\x1b[3", "1m", "\x1b[31m"},
		{"\x1b[31", "m", "\x1b[31m"},
		{"\x1b", "]52;c:aGk=\x07", ""},
		{"\x1b]52;c:aGk=", "\x07", ""},
		{"\x1b]0;t", "\x1b\\", ""},
		{"\x1b]0;t\x1b", "\\", ""},
		{"\x1b", "(", ""},
		{"\x1b(", "B", ""},
		{"\x1bP1", "q x\x1b\\", ""},
		{"\x1bP", "\x18", ""}, // CAN from the next chunk aborts
	}
	for _, c := range cases {
		if got := feedAll(t, false, []byte(c.first), []byte(c.rest)); got != c.want {
			t.Errorf("split %q+%q = %q, want %q", c.first, c.rest, got, c.want)
		}
	}
}
