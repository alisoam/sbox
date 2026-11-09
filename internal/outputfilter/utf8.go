// Incremental UTF-8 decoding with one replacement per maximal invalid
// subpart, and the printable-character predicate. Golden streams pin
// malformed-byte behavior independently of terminal escape parsing.

package outputfilter

import "unicode"

// replacement is U+FFFD REPLACEMENT CHARACTER for each maximal invalid subpart.
const replacement = '\ufffd'

// incDecoder preserves incomplete UTF-8 sequences between calls and
// replaces malformed input according to these rules:
//
//   - an invalid LEADING byte (stray continuation 0x80..0xBF, overlong
//     lead 0xC0/0xC1, out-of-range 0xF5..0xFF) costs one U+FFFD each;
//   - a lead whose SECOND byte breaks the sequence (not a continuation
//     byte, or an E0/ED/F0/F4 range violation: overlong, surrogate,
//     > U+10FFFF) costs one U+FFFD for the lead alone and the offender
//     is re-scanned fresh (so ED A0 80 — a surrogate encoding — costs
//     three, one per byte);
//   - a byte broken LATER in the sequence costs one U+FFFD for the
//     valid prefix (lead + good continuations, the "maximal subpart")
//     and scanning resumes at the offender (F0 9F 98 '(' → U+FFFD then
//     '(');
//   - truncation at end-of-stream (final=true) costs one U+FFFD for
//     the maximal subpart (F0 9F at EOF → one U+FFFD), while a
//     truncation mid-stream is HELD until the next chunk completes it;
//
// and chunk boundaries never change the result (the split multibyte
// character survives; everything else is decided byte-locally).
type incDecoder struct {
	pending []byte // held incomplete trailing sequence (≤ 3 bytes)
}

// decode consumes data; final=true ends the stream (leftovers become
// U+FFFD, nothing is held back).
func (d *incDecoder) decode(data []byte, final bool) string {
	buf := data
	if len(d.pending) > 0 {
		buf = make([]byte, 0, len(d.pending)+len(data))
		buf = append(buf, d.pending...)
		buf = append(buf, data...)
	}
	var out []rune
	i := 0
	for i < len(buf) {
		b0 := buf[i]
		if b0 < 0x80 {
			out = append(out, rune(b0))
			i++
			continue
		}
		if b0 < 0xC2 || b0 > 0xF4 { // invalid start byte
			out = append(out, replacement)
			i++
			continue
		}
		n, lo, hi := seqShape(b0)
		avail := len(buf) - i
		// A PRESENT second byte that breaks the sequence (not a
		// continuation, or an E0/ED/F0/F4 range violation) is not
		// truncation: one U+FFFD for the lead alone, and the offender
		// is re-scanned fresh — even at end-of-stream.
		if avail >= 2 {
			if b1 := buf[i+1]; b1 < lo || b1 > hi {
				out = append(out, replacement) // subpart = the lead alone
				i++
				continue
			}
		}
		if avail < n {
			if !final {
				// incomplete (and valid so far): hold for the next chunk
				d.pending = append(d.pending[:0], buf[i:]...)
				return string(out)
			}
			out = append(out, replacement) // truncated maximal subpart
			i = len(buf)
			break
		}
		k := 2
		for ; k < n; k++ {
			if c := buf[i+k]; c < 0x80 || c > 0xBF {
				break
			}
		}
		if k < n {
			out = append(out, replacement) // subpart = lead + k-1 good bytes
			i += k
			continue
		}
		out = append(out, decodeSeq(b0, buf[i+1:i+n]))
		i += n
	}
	d.pending = d.pending[:0]
	return string(out)
}

// seqShape returns the sequence length and the legal second-byte range
// for a valid lead byte (b0 in 0xC2..0xF4). The narrowed ranges kill
// overlong encodings (E0, F0), surrogates (ED) and > U+10FFFF (F4)
// without consuming a later valid starter.
func seqShape(b0 byte) (n int, lo, hi byte) {
	switch {
	case b0 < 0xE0:
		return 2, 0x80, 0xBF
	case b0 < 0xF0:
		lo, hi = 0x80, 0xBF
		if b0 == 0xE0 {
			lo = 0xA0
		} else if b0 == 0xED {
			hi = 0x9F
		}
		return 3, lo, hi
	default:
		lo, hi = 0x80, 0xBF
		if b0 == 0xF0 {
			lo = 0x90
		} else if b0 == 0xF4 {
			hi = 0x8F
		}
		return 4, lo, hi
	}
}

func decodeSeq(b0 byte, rest []byte) rune {
	var r rune
	switch 1 + len(rest) {
	case 2:
		r = rune(b0&0x1F)<<6 | rune(rest[0]&0x3F)
	case 3:
		r = rune(b0&0x0F)<<12 | rune(rest[0]&0x3F)<<6 | rune(rest[1]&0x3F)
	default:
		r = rune(b0&0x07)<<18 | rune(rest[0]&0x3F)<<12 |
			rune(rest[1]&0x3F)<<6 | rune(rest[2]&0x3F)
	}
	return r
}

// isPrintable accepts a single printable character:
// everything except the Unicode categories Other (C*) and Separator
// (Z*), with the ASCII space (U+0020) as the one spacing exception —
// the same category set Go's unicode.IsPrint implements (L, M, N, P, S
// + ASCII space).
func isPrintable(ch rune) bool {
	return unicode.IsPrint(ch)
}
