"""
Local pre-model tokenization endpoint (issue #40, section 3).

The launch prompt (TARGET / CREDS / SCOPE / TOKEN / IP / port) reaches the model
before any MCP tool call, so it must be tokenized up front. opencode's stable
plugin API has no hook that can call an MCP tool, so the Darkmoon opencode plugin
instead connects to THIS endpoint, which lives inside the SAME MCP server process
and therefore shares the exact per-session vault used by the tool calls and by
the local report renderer.

Transport: a unix-domain socket with a trivial line protocol — the client sends
one JSON object ``{"text": "...", "session_id": "..."}`` terminated by a newline,
and receives one JSON object ``{"tokenized": "..."}`` terminated by a newline.
A raw line protocol (rather than HTTP) is used because opencode's compiled Bun
runtime honours ``node:net`` unix sockets but not ``fetch({unix})`` /
``http.request({socketPath})``; ``node:net`` is what the plugin uses.

Design constraints:
- Local only: a unix socket, mode 0600, never a TCP port. The model never talks
  to it — only the local plugin.
- Non-breaking: runs in a daemon thread; if it cannot start, the MCP server keeps
  working exactly as before (the plugin then fails closed on its side).
"""

from __future__ import annotations

import json
import os
import socketserver
import threading
from typing import Callable, Optional

DEFAULT_SOCKET_PATH = os.getenv("DARKMOON_PRIVACY_SOCK", "/tmp/darkmoon-privacy.sock")

# TokenizeCallback(text, session_id) -> tokenized text. Supplied by the server so
# this module owns no privacy logic of its own (it only transports).
TokenizeCallback = Callable[[str, Optional[str]], str]


class _UnixServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True


def _make_handler(tokenize_cb: TokenizeCallback):
    class _Handler(socketserver.StreamRequestHandler):
        # Give a slow/half-open client a bounded lifetime.
        timeout = 20

        def handle(self):
            try:
                raw = self.rfile.readline()
                if not raw:
                    return
                line = raw.decode("utf-8", "replace").strip()
                text, session_id = line, None
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        text = obj.get("text", "")
                        session_id = obj.get("session_id")
                    except json.JSONDecodeError:
                        pass  # treat the whole line as the text
                try:
                    tokenized = tokenize_cb(text, session_id)
                    payload = {"tokenized": tokenized}
                except Exception as exc:  # never leak the prompt in the error
                    payload = {"error": exc.__class__.__name__}
                self.wfile.write((json.dumps(payload) + "\n").encode("utf-8"))
                self.wfile.flush()
            except Exception:
                return  # a broken client must never take the server down

    return _Handler


def start(tokenize_cb: TokenizeCallback, socket_path: str = DEFAULT_SOCKET_PATH):
    """Start the tokenization endpoint in a daemon thread. Returns the server.

    Best-effort: on any failure it logs to stderr and returns None so the MCP
    server startup is never blocked by it.
    """
    try:
        directory = os.path.dirname(socket_path)
        if directory:
            os.makedirs(directory, exist_ok=True)
        try:
            os.unlink(socket_path)
        except FileNotFoundError:
            pass
        server = _UnixServer(socket_path, _make_handler(tokenize_cb))
        try:
            os.chmod(socket_path, 0o600)
        except OSError:
            pass
        thread = threading.Thread(
            target=server.serve_forever, name="darkmoon-privacy-sock", daemon=True
        )
        thread.start()
        return server
    except Exception as exc:  # pragma: no cover - never break MCP startup
        import sys

        print(f"[darkmoon-privacy] socket endpoint unavailable: {exc.__class__.__name__}", file=sys.stderr)
        return None
