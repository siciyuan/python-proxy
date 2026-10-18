import socket
import select
import threading
import urllib.parse
import base64
import hmac
import os
import sys
import time
import random

# ================= 配置区 =================
PROXY_USER = os.environ.get("PROXY_USER", "")
PROXY_PASS = os.environ.get("PROXY_PASS", "")
LISTEN_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "3000"))

VERBOSE = os.environ.get("PROXY_VERBOSE", "false").lower() == "true"

BUFFER_SIZE = 8192
IDLE_TIMEOUT = 120
CONNECT_TIMEOUT = 10
MAX_CONCURRENT = 400
MAX_BUFFER = 2 * 1024 * 1024
# ==========================================

semaphore = threading.Semaphore(MAX_CONCURRENT)
_alive_threads = 0
_alive_lock = threading.Lock()

# ================= 伪装站点 =================
_FAKE_TITLES = [
    "Docs · Engineering Notes",
    "Release Notes",
    "Runtime Handbook",
    "Edge Infrastructure Docs",
    "Build Log Mirror",
    "Internal Documentation",
]

_FAKE_PAGE_TPL = b"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>__TITLE__</title>
<style>
:root{--bg:#ffffff;--fg:#1f2328;--muted:#57606a;--line:#d0d7de}
*{box-sizing:border-box}
body{margin:0;font:15px/1.65 -apple-system,BlinkMacSystemFont,"Segoe UI",system-ui,sans-serif;color:var(--fg);background:var(--bg)}
header{border-bottom:1px solid var(--line);padding:18px 32px;font-weight:600;letter-spacing:.2px}
main{max-width:780px;margin:48px auto;padding:0 24px}
h1{font-size:22px;margin:0 0 12px}
h2{font-size:17px;margin:32px 0 8px}
p{color:var(--muted);margin:10px 0}
code{background:#f6f8fa;padding:2px 6px;border-radius:4px;font-size:13px}
ul{padding-left:20px;color:var(--muted)}
li{margin:6px 0}
footer{margin-top:64px;border-top:1px solid var(--line);padding:18px 32px;font-size:13px;color:var(--muted)}
</style>
</head>
<body>
<header>engineering / notes</header>
<main>
<h1>Internal documentation mirror</h1>
<p>This is a read-only mirror of internal engineering notes, synced from upstream weekly.</p>
<p>Most pages are available under <code>/docs/</code> and <code>/changelog/</code>; some sections require signed access.</p>
<h2>Available sections</h2>
<ul>
<li><code>/docs/getting-started</code> &mdash; onboarding and setup</li>
<li><code>/docs/deployment</code> &mdash; rollout procedures</li>
<li><code>/changelog/</code> &mdash; recent changes</li>
</ul>
<p>Last sync: <code>2026-09-22 03:14 UTC</code></p>
</main>
<footer>&copy; 2026 infra team &middot; edge node 04</footer>
</body>
</html>
"""

_FAKE_PAGE = _FAKE_PAGE_TPL.replace(b"__TITLE__", random.choice(_FAKE_TITLES).encode("utf-8"))
_ROBOTS_TXT = b"User-agent: *\nAllow: /\n"
# ==========================================


def log(msg):
    if VERBOSE:
        print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


def log_error(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", file=sys.stderr, flush=True)


def check_proxy_auth(request_data: bytes) -> bool:
    try:
        text = request_data.decode("iso-8859-1")
        headers = text.split("\r\n")
        auth_value = None
        for line in headers[1:]:
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                if key.strip().lower() == "proxy-authorization":
                    auth_value = value.strip()
                    break
        if not auth_value:
            return False
        parts = auth_value.split(None, 1)
        if len(parts) != 2 or parts[0].lower() != "basic":
            return False
        decoded = base64.b64decode(parts[1]).decode("utf-8")
        username, password = decoded.split(":", 1)
        return (hmac.compare_digest(username, PROXY_USER)
                and hmac.compare_digest(password, PROXY_PASS))
    except Exception:
        return False


def remove_proxy_auth_header(request_data: bytes) -> bytes:
    text = request_data.decode("iso-8859-1")
    lines = text.split("\r\n")
    new_lines = []
    for line in lines:
        if ":" in line:
            key = line.split(":", 1)[0].strip().lower()
            if key == "proxy-authorization":
                continue
        new_lines.append(line)
    return "\r\n".join(new_lines).encode("iso-8859-1")


def parse_direct_request(request_data: bytes):
    """判断是否为直连浏览器请求（非代理协议），返回 (method, path) 或 None"""
    try:
        text = request_data.decode("iso-8859-1", errors="replace")
        first = text.split("\r\n", 1)[0].strip()
        parts = first.split()
        if len(parts) < 2:
            return None
        method, target = parts[0], parts[1]
        if method.upper() == "CONNECT":
            return None
        if target.lower().startswith(("http://", "https://")):
            return None
        return method.upper(), target
    except Exception:
        return None


def serve_fake_site(sock, target_path: str):
    """所有直连请求统一返回伪装页"""
    try:
        if target_path == "/robots.txt":
            body = _ROBOTS_TXT
            hdr = (f"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
                   f"Content-Type: text/plain\r\nContent-Length: {len(body)}\r\n"
                   f"Connection: close\r\n\r\n").encode("latin-1")
            sock.sendall(hdr + body)
            return
        if target_path == "/favicon.ico":
            sock.sendall(b"HTTP/1.1 204 No Content\r\nServer: nginx/1.24.0\r\nConnection: close\r\n\r\n")
            return
        # 其余全部返回伪装页
        body = _FAKE_PAGE
        hdr = (f"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
               f"Content-Type: text/html; charset=utf-8\r\n"
               f"Content-Length: {len(body)}\r\n"
               f"Cache-Control: public, max-age=3600\r\n"
               f"Connection: close\r\n\r\n").encode("latin-1")
        sock.sendall(hdr + body)
    except Exception:
        pass


def send_407(client_socket):
    try:
        client_socket.sendall(
            b"HTTP/1.1 407 Proxy Authentication Required\r\n"
            b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
            b"Content-Length: 0\r\nConnection: close\r\n\r\n"
        )
    except Exception:
        pass


def close_socket(sock):
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass
    try:
        sock.close()
    except Exception:
        pass


def make_tcp_socket():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return s


def tunnel(client_socket, server_socket):
    client_socket.setblocking(False)
    server_socket.setblocking(False)

    peer = {client_socket: server_socket, server_socket: client_socket}
    pending = {client_socket: bytearray(), server_socket: bytearray()}

    while True:
        write_list = [s for s in (client_socket, server_socket) if pending[s]]
        try:
            rlist, wlist, xlist = select.select(
                [client_socket, server_socket],
                write_list,
                [client_socket, server_socket],
                IDLE_TIMEOUT,
            )
        except (OSError, ValueError):
            return

        if xlist or (not rlist and not wlist):
            return

        # ---- 读 ----
        for s in rlist:
            if len(pending[peer[s]]) > MAX_BUFFER:
                continue
            try:
                data = s.recv(BUFFER_SIZE)
            except (BlockingIOError, InterruptedError):
                continue
            except Exception:
                return
            if not data:
                return
            pending[peer[s]] += data

        # ---- 写 ----
        for s in wlist:
            buf = pending[s]
            if not buf:
                continue
            try:
                n = s.send(buf)
            except (BlockingIOError, InterruptedError):
                continue
            except Exception:
                return
            if n <= 0:
                return
            del buf[:n]


def handle_connect(client_socket, hostname, port):
    server_socket = None
    try:
        server_socket = make_tcp_socket()
        server_socket.settimeout(CONNECT_TIMEOUT)
        server_socket.connect((hostname, port))
    except Exception as e:
        log_error(f"[CONNECT ERROR] {hostname}:{port} {e}")
        try:
            client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
        if server_socket:
            close_socket(server_socket)
        return

    try:
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except Exception:
        close_socket(server_socket)
        return

    try:
        tunnel(client_socket, server_socket)
    finally:
        close_socket(client_socket)
        close_socket(server_socket)


def handle_http(client_socket, request_data, url):
    url_parts = urllib.parse.urlparse(url)
    hostname = url_parts.hostname
    port = url_parts.port or 80
    if not hostname:
        return

    server_socket = None
    try:
        server_socket = make_tcp_socket()
        server_socket.settimeout(CONNECT_TIMEOUT)
        server_socket.connect((hostname, port))
    except Exception as e:
        log_error(f"[HTTP ERROR] {hostname}:{port} {e}")
        try:
            client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
        if server_socket:
            close_socket(server_socket)
        return

    try:
        server_socket.sendall(remove_proxy_auth_header(request_data))
    except Exception:
        close_socket(server_socket)
        return

    try:
        tunnel(client_socket, server_socket)
    finally:
        close_socket(server_socket)


def handle_client(client_socket, client_address):
    global _alive_threads
    try:
        client_socket.settimeout(CONNECT_TIMEOUT)
        request_data = client_socket.recv(BUFFER_SIZE)
        if not request_data:
            return

        # ===== 伪装站点兜底 =====
        direct = parse_direct_request(request_data)
        if direct is not None:
            _method, _path = direct
            serve_fake_site(client_socket, _path)
            return
        # ========================

        if not check_proxy_auth(request_data):
            log_error(f"[AUTH FAILED] {client_address}")
            send_407(client_socket)
            return

        request_lines = request_data.decode("iso-8859-1").split("\r\n")
        first = request_lines[0].split()
        method, url = first[0], first[1]

        if method.upper() == "CONNECT":
            if ":" in url:
                hostname, port = url.rsplit(":", 1)
                port = int(port)
            else:
                hostname, port = url, 443
            log(f"[CONNECT] {client_address} -> {hostname}:{port}")
            handle_connect(client_socket, hostname, port)
            return

        log(f"[{method}] {client_address} -> {url}")
        handle_http(client_socket, request_data, url)

    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    except Exception as e:
        log_error(f"[ERROR] {client_address}: {e}")
    finally:
        close_socket(client_socket)
        with _alive_lock:
            _alive_threads -= 1
            n = _alive_threads
        semaphore.release()
        if VERBOSE and n % 50 == 0:
            log(f"[STATUS] 当前活跃连接：{n}")


def main():
    server_socket = make_tcp_socket()
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    server_socket.listen(200)

    print(f"代理服务器已启动：{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"用户：{PROXY_USER}   VERBOSE：{VERBOSE}")
    print(f"空闲超时：{IDLE_TIMEOUT}s   最大并发：{MAX_CONCURRENT}")
    print("-" * 50, flush=True)

    while True:
        try:
            client_socket, client_address = server_socket.accept()
        except KeyboardInterrupt:
            print("\n服务器关闭中...")
            break
        except Exception as e:
            log_error(f"[ACCEPT ERROR] {e}")
            time.sleep(0.1)
            continue

        if not semaphore.acquire(blocking=False):
            log_error(f"[REJECT] 并发超限，拒绝 {client_address}")
            close_socket(client_socket)
            continue

        with _alive_lock:
            _alive_threads += 1

        try:
            t = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True,
            )
            t.start()
        except RuntimeError as e:
            log_error(f"[THREAD ERROR] {e}")
            with _alive_lock:
                _alive_threads -= 1
            semaphore.release()
            close_socket(client_socket)
            time.sleep(0.5)


if __name__ == "__main__":
    main()
