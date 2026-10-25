#!/usr/bin/env python3
"""Launcher-logic tests for sbox.py (bind validation and friends).

Run without any dependencies:   python3 tests/test_sandbox.py
or under pytest, if installed:  pytest tests/
"""
import argparse
import os
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
    their own denylist — check_bind_paths must die() on each of them."""
    uid = os.getuid()
    sockets = [
        "/run/docker.sock", "/var/run/docker.sock",
        "/run/podman/podman.sock",
        "/run/containerd/containerd.sock",
        "/run/crio/crio.sock",
        "/run/dbus/system_bus_socket",
        "/run/systemd/private",
        "/run/libvirt/libvirt-sock",
        "/tmp/.X11-unix", "/tmp/.X11-unix/X0",
        f"/run/user/{uid}/bus",
        f"/run/user/{uid}/gnupg/S.gpg-agent",
        f"/run/user/{uid}/pipewire-0",
    ]
    for sock in sockets:
        opts = argparse.Namespace(bind=[sock], ro_bind=[], home=False)
        try:
            sbox.check_bind_paths(opts, "/home/sbox-test-user")
        except SystemExit:
            continue
        raise AssertionError(f"-b {sock} was not refused")
    # Ordinary children of non-protected trees must keep working
    # (realpath-resolved pairs are what build_bwrap mounts).
    with tempfile.TemporaryDirectory(prefix="sbox-test.") as tmp:
        opts = argparse.Namespace(bind=[tmp], ro_bind=[], home=False)
        binds = sbox.check_bind_paths(opts, "/home/sbox-test-user")
        assert binds == [("--bind", os.path.realpath(tmp))], binds


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
