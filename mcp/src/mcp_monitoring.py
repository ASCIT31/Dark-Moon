#!/usr/bin/env python3
"""Live command output console behind ``darkmoon --log <session_id>`` (``darkmoon-cli``).

The MCP server (``DarkmoonDockerClient._broadcast``) writes the live output of each command to a UNIX socket:
``/tmp/darkmoon_mcp_stream_<session_id>.sock`` when the command carries the session id the agent got from
``darkmoon_get_session`` (the id the agent tells the operator to monitor), ``/tmp/darkmoon_mcp_stream.sock`` otherwise.
This console listens on both. It used to ignore its argument and listen only on the shared socket, so the output of a
session was never shown (a user report: « streaming MCP output... » and nothing else).

The sockets are mode 0660 (never world-writable). In Community the MCP server and this console both run as root in the
opencode container; when the image provides a ``darkmoon`` group (or DM_GID), the sockets are handed to it so an MCP
server running as that unprivileged group can still connect.

Only output produced while the console is open is shown (it is a live stream, not a replay). When nothing arrives,
a hint says so: a session whose agent has already ended, or never ran a command (e.g. the model declined the task),
has nothing to stream; its transcript is in the web dashboard (Live output / run history).
"""
import grp
import os
import re
import selectors
import signal
import socket
import sys
import time

STREAM_BASE = "/tmp/darkmoon_mcp_stream"
STREAM_SOCK = f"{STREAM_BASE}.sock"
SESSION_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
IDLE_HINT_AFTER_S = 20.0

running = True


def handle_signal(signum, frame):
    global running
    running = False


def session_sock_path(session_id: str) -> str:
    """Same path as DarkmoonDockerClient._broadcast for a command run with this session id."""
    return f"{STREAM_BASE}_{session_id}.sock"


def _stream_gid():
    """Group the MCP server runs with (DM_GID, else the image's ``darkmoon`` group); None when unknown."""
    raw = os.environ.get("DM_GID", "").strip()
    if raw.isdigit():
        return int(raw)
    try:
        return grp.getgrnam("darkmoon").gr_gid
    except KeyError:
        return None


def _unlink(path: str) -> None:
    """Remove a stale socket, or a dangling link planted in /tmp, without following anything."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass


def listen(path: str) -> socket.socket:
    _unlink(path)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(path)
    srv.listen(50)
    # 0o660 = owner+group rw, no world access (a world-writable socket lets any local user inject output).
    os.chmod(path, 0o660)
    gid = _stream_gid()
    if gid is not None and os.geteuid() == 0:
        try:
            os.chown(path, -1, gid)
        except OSError:
            pass
    return srv


def main(argv=None):
    global running
    argv = sys.argv[1:] if argv is None else argv
    session_id = argv[0].strip() if argv else ""
    if session_id and not SESSION_RE.match(session_id):
        sys.stderr.write(f"darkmoon(live)> invalid session id: {session_id!r}\n")
        return 2

    # Capture Ctrl+C and Docker stop
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    paths = [STREAM_SOCK] + ([session_sock_path(session_id)] if session_id else [])
    servers = [listen(p) for p in paths]
    # inode of each socket we bound: at exit, never delete a socket another console bound since
    inodes = [os.stat(p).st_ino for p in paths]

    sel = selectors.DefaultSelector()
    for srv in servers:
        sel.register(srv, selectors.EVENT_READ)

    clients = set()

    label = f" for session {session_id}" if session_id else ""
    sys.stdout.write(f"\n\033[1;32mdarkmoon(live)>\033[0m streaming MCP output{label}...\n\n")
    sys.stdout.flush()

    started = time.monotonic()
    received = False
    hinted = False

    try:
        while running:
            # IMPORTANT: timeout avoids blocking forever
            events = sel.select(timeout=0.5)

            if not received and not hinted and time.monotonic() - started >= IDLE_HINT_AFTER_S:
                hinted = True
                sys.stdout.write(
                    "\033[0;90mdarkmoon(live)> no command output yet. This console shows commands while they run; "
                    "if the session has already ended, or its agent never ran a command (for example the model "
                    "declined the task), there is nothing to stream: see the web dashboard (Live output / run "
                    "history). Ctrl+C to quit.\033[0m\n")
                sys.stdout.flush()

            for key, _ in events:
                if key.fileobj in servers:
                    c, _ = key.fileobj.accept()
                    c.setblocking(False)
                    clients.add(c)
                    sel.register(c, selectors.EVENT_READ)
                else:
                    c = key.fileobj
                    try:
                        data = c.recv(4096)
                        if not data:
                            sel.unregister(c)
                            clients.remove(c)
                            c.close()
                            continue

                        received = True
                        os.write(sys.stdout.fileno(), data)

                    except Exception:
                        try:
                            sel.unregister(c)
                        except Exception:
                            pass
                        try:
                            clients.remove(c)
                        except Exception:
                            pass
                        try:
                            c.close()
                        except Exception:
                            pass

    finally:
        sys.stdout.write("\n\033[1;31mdarkmoon(live)>\033[0m stopped.\n")
        sys.stdout.flush()

        for c in list(clients):
            try:
                sel.unregister(c)
                c.close()
            except Exception:
                pass

        for srv, path, ino in zip(servers, paths, inodes):
            try:
                sel.unregister(srv)
                srv.close()
            except Exception:
                pass
            try:
                if os.lstat(path).st_ino == ino:
                    os.unlink(path)
            except OSError:
                pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
