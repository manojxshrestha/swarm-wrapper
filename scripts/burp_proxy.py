#!/usr/bin/env python3
import socket
import threading
import re
import sys

UPSTREAM_HOST = '127.0.0.1'
UPSTREAM_PORT = 9876


def _rewrite_http(data: bytes) -> bytes:
    """Rewrite Host header and strip Origin from an HTTP request."""
    text = data.decode('utf-8', errors='replace')
    text = re.sub(r'Host: [^\r\n]+', f'Host: localhost:{UPSTREAM_PORT}', text)
    text = re.sub(r'\r\nOrigin: [^\r\n]+', '', text)
    return text.encode('utf-8')


def _is_connect(data: bytes) -> bool:
    return data.startswith(b'CONNECT ')


def handle_connect(conn: socket.socket, target: socket.socket, first_chunk: bytes):
    """Handle HTTPS CONNECT tunnel: pass through raw bytes after initial rewrite."""
    target.sendall(first_chunk)
    resp = target.recv(65536)
    conn.sendall(resp)

    def pipe(src, dst):
        try:
            while True:
                buf = src.recv(65536)
                if not buf:
                    break
                dst.sendall(buf)
        except:
            pass
        finally:
            try:
                src.close()
            except:
                pass
            try:
                dst.close()
            except:
                pass

    threading.Thread(target=pipe, args=(conn, target), daemon=True).start()
    threading.Thread(target=pipe, args=(target, conn), daemon=True).start()


def handle_http(conn: socket.socket, target: socket.socket, first_chunk: bytes):
    """Handle plain HTTP — rewrite Host, strip Origin, then bidir bridge."""
    rewritten = _rewrite_http(first_chunk)
    target.sendall(rewritten)

    def bridge(src, dst, src_to_dst):
        try:
            if src_to_dst:
                while True:
                    buf = src.recv(65536)
                    if not buf:
                        break
                    dst.sendall(buf)
            else:
                while True:
                    buf = src.recv(65536)
                    if not buf:
                        break
                    dst.sendall(buf)
        except:
            pass
        finally:
            try:
                src.close()
            except:
                pass
            try:
                dst.close()
            except:
                pass

    threading.Thread(target=bridge, args=(conn, target, True), daemon=True).start()
    threading.Thread(target=bridge, args=(target, conn, False), daemon=True).start()


def handle(conn, addr):
    target = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    target.connect((UPSTREAM_HOST, UPSTREAM_PORT))

    first_chunk = conn.recv(65536)
    if not first_chunk:
        conn.close()
        target.close()
        return

    if _is_connect(first_chunk):
        handle_connect(conn, target, first_chunk)
    else:
        handle_http(conn, target, first_chunk)


srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bind_host = '127.0.0.1' if '--listen-only' in sys.argv else '0.0.0.0'
srv.bind((bind_host, 9872))
srv.listen(50)
print(f'Proxy on {bind_host}:9872 -> {UPSTREAM_HOST}:{UPSTREAM_PORT} (Host rewritten, Origin stripped, HTTPS CONNECT passthrough)', flush=True)
while True:
    try:
        conn, addr = srv.accept()
        threading.Thread(target=handle, args=(conn, addr), daemon=True).start()
    except:
        pass
