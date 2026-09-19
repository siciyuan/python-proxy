import socket
import select
import threading
import urllib.parse
import base64
import hmac
import os
import sys

# ================= 配置区 =================
PROXY_USER = os.environ.get("PROXY_USER", "scroam")
PROXY_PASS = os.environ.get("PROXY_PASS", "czh20110127")
LISTEN_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "20364"))

VERBOSE = os.environ.get("PROXY_VERBOSE", "false").lower() == "true"

BUFFER_SIZE = 8192
IDLE_TIMEOUT = 300          # ★ 空闲超时改为 5 分钟
CONNECT_TIMEOUT = 10
MAX_CONCURRENT = 500
MAX_BUFFER = 4 * 1024 * 1024   # ★ 单方向缓冲上限 4MB
# ==========================================

semaphore = threading.Semaphore(MAX_CONCURRENT)


def log(msg):
    if VERBOSE:
        print(msg, flush=True)


def log_error(msg):
    print(msg, file=sys.stderr, flush=True)


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


def send_407(client_socket):
    resp = (
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
        "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    try:
        client_socket.sendall(resp.encode("utf-8"))
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


def tunnel(client_socket, server_socket):
    """
    完全非阻塞双向转发：
      - select 监听可读 + 可写
      - 数据积压在 pending 缓冲里，等对端可写时慢慢发
      - 双向都空闲超过 IDLE_TIMEOUT 才回收
      - 慢连接不会因为 sendall 超时被强断
    """
    client_socket.setblocking(False)
    server_socket.setblocking(False)

    peer = {client_socket: server_socket, server_socket: client_socket}
    pending = {client_socket: b"", server_socket: b""}

    while True:
        # 只在有数据积压时才关心可写事件
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

        if xlist:
            return
        if not rlist and not wlist:
            # 双向都空闲，超时回收
            return

        # ---- 读方向 ----
        for s in rlist:
            # 缓冲已经积压太多就先不读，等对端消费
            if len(pending[peer[s]]) > MAX_BUFFER:
                continue
            try:
                data = s.recv(BUFFER_SIZE)
            except (BlockingIOError, InterruptedError):
                continue
            except Exception:
                return
            if not data:
                # 一方关闭读端，整条隧道结束
                return
            pending[peer[s]] += data

        # ---- 写方向 ----
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
            pending[s] = buf[n:]


def handle_connect(client_socket, hostname, port):
    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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

    # ★ 普通 HTTP 也改成双向隧道，不再手工 recv/sendall
    #   先握手：把去掉认证头的请求原样发给服务器
    try:
        forward_data = remove_proxy_auth_header(request_data)
        server_socket.sendall(forward_data)
    except Exception:
        close_socket(server_socket)
        return

    try:
        tunnel(client_socket, server_socket)
    finally:
        close_socket(server_socket)


def handle_client(client_socket, client_address):
    try:
        client_socket.settimeout(CONNECT_TIMEOUT)
        request_data = client_socket.recv(BUFFER_SIZE)
        if not request_data:
            return

        if not check_proxy_auth(request_data):
            log_error(f"[AUTH FAILED] {client_address}")
            send_407(client_socket)
            return

        request_lines = request_data.decode("iso-8859-1").split("\r\n")
        method, url, protocol = request_lines[0].split()

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
        semaphore.release()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((LISTEN_HOST, LISTEN_PORT))
    server_socket.listen(200)

    print(f"代理服务器已启动：{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"用户：{PROXY_USER}  VERBOSE：{VERBOSE}")
    print(f"空闲超时：{IDLE_TIMEOUT}s  最大并发：{MAX_CONCURRENT}  单方向缓冲上限：{MAX_BUFFER}")
    print("-" * 50, flush=True)

    while True:
        try:
            client_socket, client_address = server_socket.accept()
        except KeyboardInterrupt:
            print("\n服务器关闭中...")
            break
        except Exception as e:
            log_error(f"[ACCEPT ERROR] {e}")
            continue

        if not semaphore.acquire(blocking=False):
            log_error(f"[REJECT] 并发超限，拒绝 {client_address}")
            close_socket(client_socket)
            continue

        try:
            t = threading.Thread(
                target=handle_client,
                args=(client_socket, client_address),
                daemon=True
            )
            t.start()
        except RuntimeError as e:
            log_error(f"[THREAD ERROR] {e}")
            semaphore.release()
            close_socket(client_socket)


if __name__ == "__main__":
    main()
