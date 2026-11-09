package bindpolicy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sbox/internal/notes"
)

// scanNoteKey is the once-a-day stamp for the scan's gave-up note.
const scanNoteKey = "socket-scan-gaveup.note"

// DefaultScanDepth and DefaultScanEntries bound the scan so huge trees stay
// cheap. Directories count toward the entry cap too (a directory-heavy
// tree — node_modules at depth <= 3 — must not turn the cap into "walk
// everything").
const (
	DefaultScanDepth   = 3
	DefaultScanEntries = 5000
)

// ContainsSocket performs a bounded scan for a
// Unix socket inside root, returning the first socket path found ("" if
// none). Binding a directory that contains a socket usually means
// binding a control socket we simply do not know by name.
//
// root is often a /proc/self/fd/<fd> pin (fd-first: the directory whose
// contents were checked is the directory that gets mounted — a
// path-rooted scan could be steered to a different directory entirely;
// /proc/self/fd cannot); shown is the HOST-path spelling for notes.
//
// Hitting the entry cap is FAIL-OPEN by design (ordinary big trees must
// keep binding): it says so through warn, but at most once a day (or
// with verbose) — a large cwd would otherwise print on EVERY launch.
// Unreadable directories (a 0711 subdir the scan cannot list) are noted
// too — on every launch, under no stamp: unlike the cap this is rare,
// and a socket connectable by name could hide there, so an earlier
// gave-up note must not silence it. What stays racy is a socket
// appearing after the scan — a sandbox cannot create a host control
// socket, so that residual is accepted.
func ContainsSocket(root string, shown string, verbose bool, warn func(string)) string {
	if warn == nil {
		warn = func(string) {}
	}
	note := func(msg string) {
		// Lossy like the scan itself: at most once a day or with
		// --verbose, so an ordinary large cwd does not print on every
		// launch.
		if verbose || !notes.NoteRecentlyShown(scanNoteKey) {
			notes.MarkNoteShown(scanNoteKey)
			shownPath := shown
			if shownPath == "" {
				shownPath = root
			}
			warn(fmt.Sprintf("note: socket scan of %s %s — the bind is allowed, "+
				"but an unscanned socket could lurk there; --bind-socket is only "+
				"needed when you know there is one", shownPath, msg))
		}
	}

	n := 0
	var unreadable []string
	found := ""

	// visit lists one directory's entries (counted, socket-checked) and
	// recurses into subdirectories whose depth is still under the cap.
	// A directory AT the depth cap still has its entries counted, but is not descended
	// into. Returns false when the walk is done (socket found or cap).
	var visit func(dirpath string) bool
	visit = func(dirpath string) bool {
		entries, err := os.ReadDir(dirpath)
		if err != nil {
			unreadable = append(unreadable, dirpath)
			return true
		}
		for _, e := range entries {
			n++
			if n > DefaultScanEntries {
				note(fmt.Sprintf("gave up after %d entries (depth <= %d)", DefaultScanEntries, DefaultScanDepth))
				return false
			}
			p := filepath.Join(dirpath, e.Name())
			if IsSocket(p) { // stat follows symlinks — the name is what connects
				found = p
				return false
			}
		}
		for _, e := range entries {
			if !e.IsDir() {
				continue // symlinked dirs are not followed
			}
			child := filepath.Join(dirpath, e.Name())
			// A directory AT the depth cap still has its entries counted,
			// but is not descended
			// into — so stop at children deeper than the cap.
			if strings.Count(child[len(root):], "/") > DefaultScanDepth {
				continue
			}
			if !visit(child) {
				return false
			}
		}
		return true
	}
	visit(root)

	if found != "" {
		return found
	}
	if len(unreadable) > 0 {
		first := unreadable[0]
		if strings.HasPrefix(first, root) && shown != "" {
			first = shown + first[len(root):]
		}
		plural := "ies"
		if len(unreadable) == 1 {
			plural = "y"
		}
		warn(fmt.Sprintf("note: socket scan of %s could not read %d director%s (e.g. %s) — "+
			"the bind is allowed, but an unscanned socket could lurk there; "+
			"--bind-socket is only needed when you know there is one",
			shownOr(shown, root), len(unreadable), plural, first))
	}
	return ""
}

func shownOr(shown, root string) string {
	if shown != "" {
		return shown
	}
	return root
}
