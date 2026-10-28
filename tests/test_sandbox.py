#!/usr/bin/env python3
"""Launcher-logic tests for sbox.py (bind validation and friends).

Run without any dependencies:   python3 tests/test_sandbox.py
or under pytest, if installed:  pytest tests/
"""
import argparse
import os
import socket
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
            assert binds == [("--ro-bind", sock)], binds
        finally:
            s.close()

    # Shape rule opt-in for a path that need not exist (also ro).
    binds = check(bind_socket=["/run/netns"])
    assert binds == [("--ro-bind", "/run/netns")], binds

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
    # (realpath-resolved pairs are what build_bwrap mounts).
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        binds = check(bind=[tmp])
        assert binds == [("--bind", os.path.realpath(tmp))], binds


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
            binds = check(bind_socket=[tmp])
            assert binds == [("--ro-bind", os.path.realpath(tmp))], binds
        finally:
            s.close()
        # socket unlinked: the same dir binds normally again
        os.unlink(os.path.join(tmp, "dev.sock"))
        binds = check(bind=[tmp])
        assert binds == [("--bind", os.path.realpath(tmp))], binds
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
            assert binds == [("--bind", os.path.realpath(tmp))], binds
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
            assert binds == [("--bind", real)], binds
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
