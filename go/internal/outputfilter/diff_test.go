package outputfilter

// The differential cross-check against the Python reference — the
// REPO's sbox.py (the spec under port), covering the whole output
// filter surface: the OutputSanitizer state machine (byte-exact, both
// strict_cr modes, whole-stream and chunked), the incremental UTF-8
// replacement decoder (invalid bytes included), _char_allowed (the
// isprintable allowlist, incl. any Unicode-table drift between this Go
// release and the live interpreter), and _sgr_conceals.
//
// This is the old scratch zzdiff harness made permanent: every package
// that ports a Python surface keeps proving itself against the
// reference implementation for as long as it exists. Skips cleanly
// without python3/sbox.py ($SBOX_PY / $SBOX_PYTHON).

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"strings"
	"syscall"
	"testing"

	"sbox/internal/oracle"
)

func requireOracle(t *testing.T) {
	t.Helper()
	if !oracle.Available() {
		t.Skip("differential oracle unavailable: python3 + sbox.py not found (set $SBOX_PY / $SBOX_PYTHON)")
	}
}

// runOracleBatch feeds JSON requests to a python driver and returns
// the JSON responses.
func runOracleBatch(t *testing.T, expr string, reqs []any) []any {
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
	var res []any
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if line == "" {
			continue
		}
		var pair [2]any
		if err := json.Unmarshal([]byte(line), &pair); err != nil {
			t.Fatalf("oracle line %q: %v", line, err)
		}
		if pair[0] == "ERR" {
			t.Fatalf("oracle error: %v", pair[1])
		}
		res = append(res, pair[1])
	}
	if len(res) != len(reqs) {
		t.Fatalf("oracle returned %d results for %d requests", len(res), len(reqs))
	}
	return res
}

// sanitizerCorpus is the differential corpus: every attack shape the
// filter exists for, the state-machine corners, invalid UTF-8, and a
// batch of deterministic random blobs.
func sanitizerCorpus() [][]byte {
	cases := []string{
		// the epilog's poster children
		"\x1b]52;c:aGk=\x07visible\x1b[31m!\x1b[0m\n",
		"\x1b]52;c:aGk=\x1b\\visible",
		// SGR pass/drop
		"\x1b[31mred\x1b[0m \x1b[m \x1b[0;1;38;5;9m \x1b[38;5;8m",
		"\x1b[8m \x1b[08m \x1b[0008m \x1b[1;8;31m \x1b[38;5;8;8m \x1b[48;2;1;2;3;8m",
		"\x1b[3:4m \x1b[?25l \x1b[>c \x1b[2J \x1b[1;2H \x1b[38;2;1;2;3;8m",
		strings.Repeat("1", 64) + "\x1b[" + strings.Repeat("1", 65) + "m",
		// strings in every opener and terminator shape
		"\x1b]0;title\x07 \x1b]0;t\x1b\\ \x1b]8;;http://x\x1b\\link\x1b]8;;\x1b\\",
		"\x1bP1;2q\x1b\\ \x1b_apc\x1b\\ \x1b^pm\x07 \x1bXsos\x1b\\",
		"\x1b]0;a\x1b\x1b\\b \x1b]never terminated",
		// 2-byte + intermediate escapes
		"\x1bM \x1b7 \x1b(B \x1b(0\x1b)B \x1b#8 \x1b%G",
		// aborts and restarts
		"\x1b[3\x18m \x1b[3\x1am \x1b[3\x1b[31m \x1b(\x1b[31m \x1b]x\x18y",
		// C0 interleaving
		"\x1b[3\n1m \x1b[3\t1m \x1b[3\x001m \x1b\nx \x1b[\n \x1b(\nBok",
		// C1 as characters and inside sequences
		"ab ab \x1b[31m \x1bä[31m",
		// bidi / zero width / fillers / variation selectors
		"​‌‍‎‏  ‮a​b ‏reversed‏ ‭ and ‬ and ⁠",
		"ᅟᅠ⠀ㅤﾠ \u034f ❤️ ❤︎ \U000E0100\U000E0101",
		"  ­ 	.line sep para sep  here",
		// CR shapes (strict mode exercises these)
		"a\r\nb a\rb \r\n \r a\r\r\nb \r\r\r\n\r\n\r",
		// invalid UTF-8 of every flavor
		"\xff \xc0\xaf \xe0\x80\x80 \xed\xa0\x80 \xf4\x90\x80\x80 \xf5\x80\x80\x80 \xfe \x80",
		"\xc3\x28 \xc2\x41 \xf0\x28\x8c\xbc \xf0\x9f\x98\x28 \xf0\x9f\x98 \xf0\x9f \xc2 \xe0\xa0 \xe2\x82",
		"h\xc3\xa9llo \xf0\x9f\x98\x80abc a\xc3b h\xc3\xa9\xff",
		"\xef\xbf\xbe \xf4\x8f\xbf\xbf \xed\xbf\xbf",
		// cap crossing
		"\x1b[" + strings.Repeat("1;", 2100) + "after",
		"\x1b]" + strings.Repeat("é", 3000) + "\x07after",
		"\x1b[" + strings.Repeat("é;", 3000) + "m ok",
		// split multibyte (the driver feeds these in pieces anyway)
		"h\xc3\xa9 é😀 \xf0\x9f",
		// plain boring text
		"just text\nwith lines\tand tabs\r\n",
	}
	rng := rand.New(rand.NewSource(20261107))
	interesting := []byte("\x1b[]P_^X\\07\x18\x1a\n\r\tm;?0123456789abÄé😀\xff\x80\xc0\xf0\x9f\xed")
	for i := 0; i < 60; i++ {
		b := make([]byte, rng.Intn(300))
		for j := range b {
			if rng.Intn(3) == 0 {
				b[j] = interesting[rng.Intn(len(interesting))]
			} else {
				b[j] = byte(rng.Intn(256))
			}
		}
		cases = append(cases, string(b))
	}
	out := make([][]byte, len(cases))
	for i, c := range cases {
		out[i] = []byte(c)
	}
	return out
}

// chunkings returns the chunk splits run on both sides: whole, odd
// fixed sizes, and a random split (the SAME split indices for both
// implementations — the equivalence across chunkings is the property).
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

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func unb64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad b64 from oracle: %v", err)
	}
	return b
}

func TestDifferentialSanitizer(t *testing.T) {
	requireOracle(t)

	type req struct {
		Strict bool     `json:"strict"`
		Chunks []string `json:"chunks"` // b64 of each chunk
	}
	var reqs []req
	type want struct {
		strict bool
		idx    int
		split  int
		got    string
	}
	var wants []want
	idx := 0
	for _, data := range sanitizerCorpus() {
		for _, strict := range []bool{false, true} {
			for si, chunks := range chunkings(data, int64(idx)) {
				var cs []string
				for _, c := range chunks {
					cs = append(cs, b64(c))
				}
				reqs = append(reqs, req{Strict: strict, Chunks: cs})
				wants = append(wants, want{strict: strict, idx: idx, split: si})
			}
		}
		idx++
	}

	// python: one OutputSanitizer per request, feed the chunks, flush.
	const expr = `__import__("base64").b64encode("".join(
    x for s in [m.OutputSanitizer(strict_cr=req["strict"])]
    for x in ([s.feed(__import__("base64").b64decode(c)) for c in req["chunks"]] + [s.flush()])
).encode("utf-8")).decode()`
	res := runOracleBatch(t, expr, toAny(reqs))

	for i, w := range wants {
		py := unb64(t, res[i].(string))
		s := NewSanitizer(w.strict)
		var sb strings.Builder
		for _, c := range chunkings(sanitizerCorpus()[w.idx], int64(w.idx))[w.split] {
			sb.WriteString(s.Feed(c))
		}
		sb.WriteString(s.Flush())
		goOut := sb.String()
		if goOut != string(py) {
			t.Errorf("corpus[%d] strict=%v split=%d: go %q != py %q (input % X)",
				w.idx, w.strict, w.split, goOut, string(py), sanitizerCorpus()[w.idx])
		}
	}
}

func toAny[T any](vs []T) []any {
	out := make([]any, len(vs))
	for i, v := range vs {
		out[i] = v
	}
	return out
}

// TestDifferentialCharAllowed pins the character allowlist (incl. the
// isprintable() tables of both runtimes) over a broad deterministic
// sweep: every corpus character plus thousands of random code points.
//
// Known, tolerated drift: Go's unicode tables are pinned to a Unicode
// release, CPython's to another (today 15.0.0 vs 17.0.0), so code
// points ASSIGNED between the two (CJK Extension H/I, Egyptian
// Hieroglyphs Ext-A, ...) are printable for Python and dropped here —
// dropping extra characters is the fail-closed direction. A divergence
// is accepted ONLY in that direction AND only when Python's
// unicodedata category really is printable (L/M/N/P/S); anything Go
// lets through that Python drops fails the test outright.
func TestDifferentialCharAllowed(t *testing.T) {
	requireOracle(t)
	rng := rand.New(rand.NewSource(99))
	cps := []int{0, 0x1F, 0x20, 0x7E, 0x7F, 0x9F, 0xA0, 0xA1, 0xAD, 0xAE,
		0x200A, 0x200B, 0x200F, 0x2010, 0x2029, 0x202A, 0x202E, 0x202F, 0x2160,
		0x2060, 0x2069, 0x206A, 0x2800, 0x3164, 0x034F, 0x115F, 0x1160, 0xFFA0,
		0xFE00, 0xFE0E, 0xFE0F, 0xFEFF, 0xE0100, 0xE01EF, 0xE01F0, 0xFFFD, 0xFFFE, 0xFFFF,
		0x10FFFF, 0xFDCF, 0xFDF0, 0x180B, 0x180E, 0x061C, 0x08E2, 0x1D173,
		0x2ED75, 0x32609, 0x143D6, 0x32786, // the drift class itself
	}
	for i := 0; i < 4000; i++ {
		cps = append(cps, rng.Intn(0x110000))
	}

	type req struct {
		CP int `json:"cp"`
	}
	reqs := make([]any, len(cps))
	for i, c := range cps {
		reqs[i] = req{CP: c}
	}
	res := runOracleBatch(t,
		`[m._char_allowed(chr(req["cp"])),
		  __import__("unicodedata").category(chr(req["cp"]))]`, reqs)
	bad, tolerated := 0, 0
	for i, c := range cps {
		pair := res[i].([]any)
		pyAllowed := pair[0].(bool)
		pyCat := pair[1].(string)
		if c > 0x10FFFF {
			continue // not representable as a rune
		}
		goAllowed := charAllowed(rune(c))
		if goAllowed == pyAllowed {
			continue
		}
		if !goAllowed && pyAllowed {
			// tolerable only as newer-Unicode assignment: python's
			// category must be printable (not C*/Z*)
			if len(pyCat) > 0 && pyCat[0] != 'C' && pyCat[0] != 'Z' {
				tolerated++
				continue
			}
		}
		bad++
		if bad <= 10 {
			t.Errorf("U+%04X: go allowed=%v, py allowed=%v (py category %s)",
				c, goAllowed, pyAllowed, pyCat)
		}
	}
	if bad > 0 {
		t.Errorf("%d/%d codepoints disagree beyond known table drift", bad, len(cps))
	}
	if tolerated > len(cps)/10 {
		t.Errorf("tolerated drift suspiciously high: %d/%d", tolerated, len(cps))
	}
	t.Logf("tolerated newer-Unicode-assignment drift: %d/%d codepoints", tolerated, len(cps))
}

// TestDifferentialSGRConceals pins the 38/48 subparameter walker.
func TestDifferentialSGRConceals(t *testing.T) {
	requireOracle(t)
	params := []string{
		"", "0", "1", "8", "08", "0008", "888", "8;", ";8", "1;8",
		"38;5;8", "38;5;08", "48;2;1;2;3", "48;2;1;2;3;8", "38;5;8;8",
		"38;2;1;2;3", "38;2;1;2;3;8", "38", "38;8", "38;9;8", "48",
		"1;38;5;8;0", "1;38;2;8;8;8;0", "38;5;8;1;8", "48;2;0;0;0;48;5;8",
		";;;", "0;0;0;8", "8;8;8", "38;2", "38;2;1", "38;2;1;2", "38;5",
		"38;5;", "48;5;8", "00038;5;8", "38;5;0008",
	}
	reqs := make([]any, len(params))
	for i, p := range params {
		reqs[i] = map[string]string{"p": p}
	}
	res := runOracleBatch(t, `m._sgr_conceals(req["p"])`, reqs)
	for i, p := range params {
		py := res[i].(bool)
		if got := sgrConceals(p); got != py {
			t.Errorf("sgrConceals(%q) = %v, python says %v", p, got, py)
		}
	}
}

// TestDifferentialDecoder pins the raw incremental decoder (before the
// character allowlist sees anything) against CPython's, over every
// corpus blob and every split — the replacement counts are the
// byte-exact part of the contract.
func TestDifferentialDecoder(t *testing.T) {
	requireOracle(t)
	type req struct {
		Chunks []string `json:"chunks"`
	}
	var reqs []any
	type want struct {
		idx, split int
	}
	var wants []want
	idx := 0
	for _, data := range sanitizerCorpus() {
		for si, chunks := range chunkings(data, int64(idx)+1000) {
			var cs []string
			for _, c := range chunks {
				cs = append(cs, b64(c))
			}
			reqs = append(reqs, req{Chunks: cs})
			wants = append(wants, want{idx, si})
		}
		idx++
	}
	const expr = `__import__("base64").b64encode("".join(
    x for d in [__import__("codecs").getincrementaldecoder("utf-8")(errors="replace")]
    for x in ([d.decode(__import__("base64").b64decode(c)) for c in req["chunks"]]
              + [d.decode(b"", final=True)])
).encode("utf-8")).decode()`
	res := runOracleBatch(t, expr, reqs)
	for i, w := range wants {
		py := unb64(t, res[i].(string))
		var d incDecoder
		var sb strings.Builder
		for _, c := range chunkings(sanitizerCorpus()[w.idx], int64(w.idx)+1000)[w.split] {
			sb.WriteString(d.decode(c, false))
		}
		sb.WriteString(d.decode(nil, true))
		if sb.String() != string(py) {
			t.Errorf("decoder corpus[%d] split=%d: go %q != py %q",
				w.idx, w.split, sb.String(), string(py))
		}
	}
}

var _ = fmt.Sprint // keep fmt for future debugging aids

// TestDifferentialMakeRaw pins makeRaw against the LIVE interpreter's
// tty.cfmakeraw (what its tty.setraw applies — a pure-Python
// POSIX.1-2017 implementation, not glibc's cfmakeraw: it also clears
// IGNPAR/INPCK/IXANY/IXOFF and ECHOE/ECHOK/NOFLSH/TOSTOP). A drift
// here would leave, e.g., a TOSTOP or IXOFF tty un-tamed on real
// hosts while the oracle clears it.
func TestDifferentialMakeRaw(t *testing.T) {
	requireOracle(t)
	termiosVMIN, termiosVTIME := syscall.VMIN, syscall.VTIME
	cc := func(vmin, vtime byte) [32]uint8 {
		var c [32]uint8
		c[termiosVMIN] = vmin
		c[termiosVTIME] = vtime
		return c
	}
	// A real fresh pty's defaults, plus the bit-for-bit extremes.
	master, slave, err := OpenPty()
	if err != nil {
		t.Skipf("no ptys here: %v", err)
	}
	defer master.Close()
	defer slave.Close()
	var fresh syscall.Termios
	if err := tcgetattr(slave.Fd(), &fresh); err != nil {
		t.Fatal(err)
	}
	patterns := []syscall.Termios{
		fresh,
		{Iflag: 0, Oflag: 0, Cflag: 0, Lflag: 0, Cc: cc(0, 0)},
		{Iflag: ^uint32(0), Oflag: ^uint32(0), Cflag: ^uint32(0), Lflag: ^uint32(0), Cc: cc(7, 7)},
		{Iflag: syscall.IGNBRK | syscall.BRKINT | syscall.IGNPAR | syscall.PARMRK |
			syscall.INPCK | syscall.ISTRIP | syscall.INLCR | syscall.IGNCR | syscall.ICRNL |
			syscall.IXON | syscall.IXANY | syscall.IXOFF | 0x5000,
			Oflag: syscall.OPOST | 0x4,
			Cflag: syscall.CS7 | syscall.PARENB | syscall.CREAD | syscall.B38400,
			Lflag: syscall.ECHO | syscall.ECHOE | syscall.ECHOK | syscall.ECHONL |
				syscall.ICANON | syscall.IEXTEN | syscall.ISIG | syscall.NOFLSH |
				syscall.TOSTOP | syscall.ECHOCTL | syscall.ECHOKE,
			Cc: cc(4, 0)},
	}

	const expr = `list(
    (t[0], t[1], t[2], t[3], t[6][VM], t[6][VT])
    for tm in [__import__("termios")]
    for VM, VT in [(tm.VMIN, tm.VTIME)]
    for t in [[req["iflag"], req["oflag"], req["cflag"], req["lflag"], 0, 0,
               [req["vmin"] if i == VM else req["vtime"] if i == VT else 0
                for i in range(32)]]]
    for _ in [__import__("tty").cfmakeraw(t)]
)`
	reqs := make([]any, len(patterns))
	for i, p := range patterns {
		reqs[i] = map[string]uint32{
			"iflag": p.Iflag, "oflag": p.Oflag, "cflag": p.Cflag, "lflag": p.Lflag,
			"vmin": uint32(p.Cc[termiosVMIN]), "vtime": uint32(p.Cc[termiosVTIME]),
		}
	}
	res := runOracleBatch(t, expr, reqs)
	for i, p := range patterns {
		got := res[i].([]any)[0].([]any) // the expr returns list([tuple])
		raw := p
		makeRaw(&raw)
		want := []uint32{raw.Iflag, raw.Oflag, raw.Cflag, raw.Lflag,
			uint32(raw.Cc[termiosVMIN]), uint32(raw.Cc[termiosVTIME])}
		for j := 0; j < 6; j++ {
			if uint64(got[j].(float64)) != uint64(want[j]) {
				t.Errorf("pattern[%d] field %d: go %#x, python %#x", i, j, want[j], uint64(got[j].(float64)))
			}
		}
	}
}
