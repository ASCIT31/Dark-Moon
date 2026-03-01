#!/usr/bin/env python3
import os
import sys
import socket
import selectors
import signal

STREAM_SOCK = "/tmp/darkmoon_mcp_stream.sock"

running = True


def handle_signal(signum, frame):
    global running
    running = False


def main():
    global running

    # Capture Ctrl+C and Docker stop
    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    if os.path.exists(STREAM_SOCK):
        os.remove(STREAM_SOCK)

    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    srv.bind(STREAM_SOCK)
    srv.listen(50)
    os.chmod(STREAM_SOCK, 0o666)

    sel = selectors.DefaultSelector()
    sel.register(srv, selectors.EVENT_READ)

    clients = set()

    sys.stdout.write("\n\033[1;32mdarkmoon(live)>\033[0m streaming MCP output...\n\n")
    sys.stdout.flush()

    try:
        while running:
            # IMPORTANT: timeout avoids blocking forever
            events = sel.select(timeout=0.5)

            for key, _ in events:
                if key.fileobj is srv:
                    c, _ = srv.accept()
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

        try:
            sel.unregister(srv)
            srv.close()
        except Exception:
            pass

        if os.path.exists(STREAM_SOCK):
            os.remove(STREAM_SOCK)


if __name__ == "__main__":
    main()