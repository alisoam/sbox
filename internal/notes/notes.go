// Package notes implements once-a-day suppression for advisory notes
// (e.g. the bwrap caps fallback): a note whose stamp file was written less
// than 24 hours ago is not shown again. Stamp files live under
// $XDG_CACHE_HOME/sbox/notes (default ~/.cache/sbox/notes), one sanitized
// file per note key. Notes are cosmetic: every error is swallowed — a
// broken cache dir must never break a launch.
//
// The cache dir contents are attacker-writable in the sandbox threat
// model (a sandbox holding a writable cache bind can plant stamp
// symlinks), so stamp writes never follow symlinks: the walk to the
// notes dir crosses no symlinked component (openat with O_NOFOLLOW;
// missing components are created with mkdirat under the pinned fd, so
// creation cannot land behind a link either), the stamp metadata check
// uses an O_PATH handle (a planted FIFO cannot block it), the bytes
// land in a fresh O_EXCL|O_NOFOLLOW temp file, and the stamp is
// REPLACED by rename through the directory fd — rename never follows
// the destination — so a planted stamp symlink is replaced itself, and
// its target never touched.
package notes

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// TTL is how long a note stays suppressed after it was shown once.
const TTL = 24 * time.Hour

// NoteRecentlyShown reports whether the note key was shown within the last
// 24 h (best effort: on any error it reports false, so the note is shown).
func NoteRecentlyShown(key string) bool {
	dir, name := splitStampPath(stampPath(baseDir(), key))
	return noteRecentlyShownAt(dir, name, time.Now())
}

// MarkNoteShown stamps key as shown now (best effort; errors ignored).
func MarkNoteShown(key string) {
	dir, name := splitStampPath(stampPath(baseDir(), key))
	_ = markNoteShownAt(dir, name, time.Now())
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

// splitStampPath splits a stamp path into its directory and base name:
// both stamp operations address the file through a pinned directory fd,
// never through the full path.
func splitStampPath(path string) (dir, name string) {
	return filepath.Dir(path), filepath.Base(path)
}

// noteRecentlyShownAt is the mtime check (no-follow): a stamp that does
// not exist (or is unreadable, or is a symlink, or is not a regular
// file) counts as not shown; a stamp in the future (clock skew) counts
// as shown, erring toward fewer notes.
func noteRecentlyShownAt(dir, name string, now time.Time) bool {
	fd, err := openUnderNoFollow(dir, name)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return false
	}
	return !time.Unix(int64(st.Mtim.Sec), int64(st.Mtim.Nsec)).Before(now.Add(-TTL))
}

// markNoteShownAt records the note's mtime as now, symlink-hardened:
// the walk to the notes dir refuses every symlinked component (and
// CREATES missing ones with mkdirat along the way — a path-based
// MkdirAll would follow a swapped component and build the tree behind
// it before the walk could refuse the link), the bytes land in a fresh
// temp file, and the stamp is replaced by rename through the directory
// fd (rename never follows the destination), so a planted stamp symlink
// — or a swapped notes directory — fails or replaces the link itself
// instead of truncating a host file outside the cache.
func markNoteShownAt(dir, name string, now time.Time) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("notes dir %s is not absolute", dir)
	}
	dirFD, err := openDirNoFollow(dir, true)
	if err != nil {
		return err
	}
	defer syscall.Close(dirFD)
	tmp := fmt.Sprintf(".%s.%d.tmp", name, os.Getpid())
	if err := writeStampAt(dirFD, tmp, now); err != nil {
		_ = syscall.Unlinkat(dirFD, tmp)
		return err
	}
	// syscall.Renameat (not the raw SYS_RENAMEAT number, which the
	// syscall package does not export on every architecture, e.g.
	// riscv64): the destination is replaced without being followed.
	if err := syscall.Renameat(dirFD, tmp, dirFD, name); err != nil {
		_ = syscall.Unlinkat(dirFD, tmp)
		return err
	}
	return nil
}

// writeStampAt writes the timestamp to name under dirFD, refusing to
// follow an existing entry of that name (O_EXCL|O_NOFOLLOW).
func writeStampAt(dirFD int, name string, now time.Time) error {
	fd, err := syscall.Openat(dirFD, name,
		syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), name)
	_, werr := f.WriteString(now.UTC().Format(time.RFC3339) + "\n")
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// openDirNoFollow opens dir walking from the root and crossing NO
// symlinked component: every step is openat(O_NOFOLLOW|O_DIRECTORY), so
// a component replaced by a symlink (possible anywhere at or below the
// attacker-writable cache root) fails the walk instead of redirecting
// the stamp outside it. With create, a missing component is made with
// mkdirat under the fd already pinned — creation can never land behind
// a symlink it refused either.
func openDirNoFollow(dir string, create bool) (int, error) {
	fd, err := syscall.Open("/", syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return -1, err
	}
	openPart := func(parent int, part string) (int, error) {
		next, err := syscall.Openat(parent, part,
			syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		if errors.Is(err, syscall.ENOENT) && create {
			if mkErr := syscall.Mkdirat(parent, part, 0o700); mkErr != nil && !errors.Is(mkErr, syscall.EEXIST) {
				return -1, mkErr
			}
			next, err = syscall.Openat(parent, part,
				syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
		}
		return next, err
	}
	for _, part := range strings.Split(filepath.Clean(dir), "/") {
		if part == "" || part == "." {
			continue
		}
		next, err := openPart(fd, part)
		syscall.Close(fd)
		if err != nil {
			return -1, err
		}
		fd = next
	}
	return fd, nil
}

// oPath is O_PATH, which the syscall package does not name on this
// platform (internal/sandbox spells the same constant): open the dentry
// itself. An O_PATH open never touches file contents or a driver, so a
// planted FIFO or socket cannot block it the way a blocking O_RDONLY
// open would — the metadata check below needs nothing else.
const oPath = 0x200000

// openUnderNoFollow opens dir/name as an O_PATH handle without
// following the final component either (a planted symlink stamp reads
// as absent, and a planted FIFO cannot hang the launcher).
func openUnderNoFollow(dir, name string) (int, error) {
	dirFD, err := openDirNoFollow(dir, false)
	if err != nil {
		return -1, err
	}
	defer syscall.Close(dirFD)
	return syscall.Openat(dirFD, name, oPath|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
}
