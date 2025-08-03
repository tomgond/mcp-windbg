"""
Tests for the WinDbg-attach workflow added to mcp_server_windbg.server.

All tests run without a real WinDbg instance by monkey-patching
`WinDbgSession` with a Dummy implementation.  When WinDbg *is* available
(and the JS plug-in is initialised with `mcp_init`) the smoke-test at the
bottom runs against the live debugger instead.
"""

from pathlib import Path
import psutil
import pytest

import mcp_server_windbg.server as srv


# --------------------------------------------------------------------------- #
#                        Dummy implementation of WinDbgSession                #
# --------------------------------------------------------------------------- #
class DummyWinDbgSession:
    """Light-weight replacement that records commands."""

    def __init__(self, dump_path, *_, **__):
        # In attach mode the server passes dump_path=None
        assert dump_path is None
        self.dump_path = None
        self.session_id = "dummy-windbg-session"
        self.commands: list[str] = []

    def send_command(self, cmd: str):
        self.commands.append(cmd)
        # Return a predictable fake output line
        return [f"dummy-windbg-out for {cmd}"]

    def shutdown(self):
        self.commands.append("shutdown")


# --------------------------------------------------------------------------- #
#                            automatic fixture clean-up                       #
# --------------------------------------------------------------------------- #
@pytest.fixture(autouse=True)
def _clean_active_sessions():
    """Ensure global cache is pristine for each test in this module."""
    yield
    srv.active_sessions.clear()


# --------------------------------------------------------------------------- #
#                                   tests                                     #
# --------------------------------------------------------------------------- #
def test_attach_windbg_and_cache(monkeypatch):
    """
    `handle_attach_windbg` should create exactly one session, store it under
    the sentinel key, and return a banner mentioning the session_id.
    """
    monkeypatch.setattr(srv, "WinDbgSession", DummyWinDbgSession)

    banner = srv.handle_attach_windbg(arguments={}, timeout=5, verbose=False)

    # Banner contains the dummy session id
    assert banner and "dummy-windbg-session" in banner[0].text

    # Session is cached under the magic key
    assert "__windbg_attach__" in srv.active_sessions
    sess = srv.active_sessions["__windbg_attach__"]
    assert isinstance(sess, DummyWinDbgSession)


def test_run_command_after_attach(monkeypatch):
    """
    After attaching, running a command via the cached session should return
    legitimate (non-empty) output and record the command.
    """
    monkeypatch.setattr(srv, "WinDbgSession", DummyWinDbgSession)

    # First attach
    srv.handle_attach_windbg(arguments={}, timeout=5, verbose=False)
    sess = srv.active_sessions["__windbg_attach__"]

    # Simulate what run_windbg_cmd does when dump_path is omitted
    output = sess.send_command(".lastevent")

    assert output == ["dummy-windbg-out for .lastevent"]
    # Ensure the command was indeed recorded
    assert ".lastevent" in sess.commands


# ---------- optional live smoke-test (runs only when WinDbg is available) ---
@pytest.mark.skipif(srv.AttachWindbgParams is None
                    or
                    'dbgx.shell.exe' not in map(lambda x: x.name().lower(), psutil.process_iter(['name'])),
                    reason="Real WinDbg support not available on this machine or windbg not running for test")
def test_attach_and_command_live():
    """
    This smoke-test attaches to a *real* WinDbg instance (if the JS plug-in
    is already loaded and initialised) and runs a simple command to make
    sure we get back some output.
    """
    banner = srv.handle_attach_windbg(arguments={}, timeout=10, verbose=False)
    assert banner and "Attached to WinDbg session" in banner[0].text

    # Use the cached live session
    sess = srv.active_sessions["__windbg_attach__"]
    out = sess.send_command(".lastevent")
    print(out)
    k_out = sess.send_command("k")
    print(k_out)
    assert len(k_out) > 0          # Should return at least one line of output
