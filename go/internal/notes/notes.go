// Package notes implements once-a-day suppression for advisory notes
// (e.g. the bwrap caps fallback): a note whose stamp file was written less
// than 24 hours ago is not shown again. Stamp files live under
// $XDG_CACHE_HOME/sbox/notes (default ~/.cache/sbox/notes), one sanitized
// file per note key. Notes are cosmetic: every error is swallowed — a
// broken cache dir must never break a launch.
package notes

import (
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TTL is how long a note stays suppressed after it was shown once.
const TTL = 24 * time.Hour

// NoteRecentlyShown reports whether the note key was shown within the last
// 24 h (best effort: on any error it reports false, so the note is shown).
func NoteRecentlyShown(key string) bool {
	return noteRecentlyShownAt(stampPath(baseDir(), key), time.Now())
}

// MarkNoteShown stamps key as shown now (best effort; errors ignored).
func MarkNoteShown(key string) {
	_ = markNoteShownAt(stampPath(baseDir(), key), time.Now())
}

// baseDir is the notes directory: $XDG_CACHE_HOME/sbox/notes or
// ~/.cache/sbox/notes.
func baseDir() string {
	if d := os.Getenv("XDG_CACHE_HOME"); d != "" {
		return filepath.Join(d, "sbox", "notes")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		home = "/tmp" // unreachable in practice; keep it writable
	}
	return filepath.Join(home, ".cache", "sbox", "notes")
}

// stampPath sanitizes the key into a file name under dir.
func stampPath(dir, key string) string {
	var b strings.Builder
	for _, r := range key {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9',
			r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
		if b.Len() >= 64 { // keep names bounded
			break
		}
	}
	return filepath.Join(dir, b.String()+".stamp")
}

// noteRecentlyShownAt is the mtime check: a stamp that does not exist (or
// is unreadable) counts as not shown; a stamp in the future (clock skew)
// counts as shown, erring toward fewer notes.
func noteRecentlyShownAt(path string, now time.Time) bool {
	st, err := os.Stat(path)
	if err != nil || st.IsDir() {
		return false
	}
	return !st.ModTime().Before(now.Add(-TTL))
}

// markNoteShownAt records the note's mtime as now.
func markNoteShownAt(path string, now time.Time) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(now.UTC().Format(time.RFC3339)+"\n"), 0o600)
}
