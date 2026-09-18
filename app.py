import socket
import threading
import urllib.parse
import base64
import hmac
import os
import sys

# ================= 配置区 =================
PROXY_USER = os.environ.get("PROXY_USER", "admin")
PROXY_PASS = os.environ.get("PROXY_PASS", "ComplexPass123!") # 建议改强密码
LISTEN_HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("PROXY_PORT", "20364"))

# 是否打印正常请求日志（默认关闭，防刷屏）
VERBOSE = os.environ.get("PROXY_VERBOSE", "false").lower() == "true"

BUFFER_SIZE = 8192
SOCKET_TIMEOUT = 60          # 连接超时时间（秒）
MAX_CONCURRENT = 500         # 最大并发连接数

# 全局信号量，限制并发线程数
semaphore = threading.Semaphore(MAX_CONCURRENT)
# ==========================================


def log(msg):
    """打印普通日志"""
    if VERBOSE:
        print(msg, flush=True)


def log_error(msg):
    """打印错误日志（始终打印）"""
    print(msg, file=sys.stderr, flush=True)


def check_proxy_auth(request_data: bytes) -> bool:
    """检查 Proxy-Authorization: Basic xxx"""
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

        return (
            hmac.compare_digest(username, PROXY_USER)
            and hmac.compare_digest(password, PROXY_PASS)
        )
    except Exception:
        return False


def remove_proxy_auth_header(request_data: bytes) -> bytes:
    """删除发给目标服务器的 Proxy-Authorization 头"""
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
    """认证失败"""
    resp = (
        "HTTP/1.1 407 Proxy Authentication Required\r\n"
        "Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
        "Content-Length: 0\r\n"
        "Connection: close\r\n"
        "\r\n"
    )
    client_socket.sendall(resp.encode("utf-8"))


def relay(a, b):
    """单向转发：从 a 读，写入 b"""
    try:
        while True:
            data = a.recv(BUFFER_SIZE)
            if not data:
                break
            b.sendall(data)
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        try:
            a.shutdown(socket.SHUT_RD)
        except Exception:
            pass
        try:
            b.shutdown(socket.SHUT_WR)
        except Exception:
            pass


def handle_connect(client_socket, hostname, port):
    """处理 HTTPS 的 CONNECT 隧道"""
    server_socket = None
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.settimeout(SOCKET_TIMEOUT)
        server_socket.connect((hostname, port))
    except Exception as e:
        log_error(f"[CONNECT ERROR] 连接 {hostname}:{port} 失败：{e}")
        try:
            client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
        if server_socket:
            server_socket.close()
        return

    try:
        client_socket.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except Exception:
        server_socket.close()
        return

    t1 = threading.Thread(target=relay, args=(client_socket, server_socket))
    t2 = threading.Thread(target=relay, args=(server_socket, client_socket))
    t1.daemon = True
    t2.daemon = True
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    try:
        client_socket.close()
    except Exception:
        pass
    try:
        server_socket.close()
    except Exception:
        pass


def handle_http(client_socket, request_data, url):
    """处理普通 HTTP 请求"""
    url_parts = urllib.parse.urlparse(url)
    hostname = url_parts.hostname
    port = url_parts.port or 80

    if not hostname:
        return

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        server_socket.settimeout(SOCKET_TIMEOUT)
        server_socket.connect((hostname, port))
    except Exception as e:
        log_error(f"[HTTP ERROR] 连接 {hostname}:{port} 失败：{e}")
        try:
            client_socket.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
        except Exception:
            pass
        server_socket.close()
        return

    forward_data = remove_proxy_auth_header(request_data)
    try:
        server_socket.sendall(forward_data)
    except Exception:
        server_socket.close()
        return

    while True:
        try:
            response_data = server_socket.recv(BUFFER_SIZE)
            if not response_data:
                break
            client_socket.sendall(response_data)
        except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError):
            break

    server_socket.close()


def handle_client(client_socket, client_address):
    # 获取信号量，限制并发
    semaphore.acquire()
    try:
        client_socket.settimeout(SOCKET_TIMEOUT)
        request_data = client_socket.recv(BUFFER_SIZE)
        if not request_data:
            return

        if not check_proxy_auth(request_data):
            log_error(f"[AUTH FAILED] {client_address} 认证失败")
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
        pass  # 客户端异常断开，忽略
    except Exception as e:
        log_error(f"[ERROR] 处理 {client_address} 出错：{e}")
    finally:
        try:
            client_socket.close()
        except Exception:
            pass
        # 释放信号量
        semaphore.release()


def main():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    server_address = (LISTEN_HOST, LISTEN_PORT)
    server_socket.bind(server_address)
    server_socket.listen(100)

    print(f"代理服务器已启动，监听地址：{LISTEN_HOST}:{LISTEN_PORT}")
    print(f"认证用户名：{PROXY_USER}，密码：{PROXY_PASS}")
    print(f"详细日志(VERBOSE)：{VERBOSE}")
    print(f"最大并发数：{MAX_CONCURRENT}")
    print(f"客户端示例：curl -x http://{PROXY_USER}:{PROXY_PASS}@{LISTEN_HOST}:{LISTEN_PORT} https://example.com")
    print("-" * 50)

    while True:
        try:
            client_socket, client_address = server_socket.accept()
            client_thread = threading.Thread(
                target=handle_client, args=(client_socket, client_address)
            )
            client_thread.daemon = True
            client_thread.start()
        except KeyboardInterrupt:
            print("\n正在关闭服务器...")
            break
        except Exception as e:
            log_error(f"[ACCEPT ERROR] {e}")


if __name__ == "__main__":
    main()
