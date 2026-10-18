import socket, threading, base64, os, struct

LISTEN_HOST, LISTEN_PORT = "0.0.0.0", 20095
AUTH_USER, AUTH_PASS = "scroam", "czh20110127"  # 改掉！
FORCE_IPV4 = True
FAKE_WEB = """<html><body style="font-family:sans-serif;color:#06c"><h2>iP查询</h2><p>正常访问</p></body></html>"""

def set_keepalive(sock, aggressive=False):
    # 仅对长连接(WebSocket)使用激进心跳；普通连接不开启，回归第一版短连接
    if not aggressive: return
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)  # 30s空闲发探测
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10) # 每10s
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)    # 3次失败断

def graceful_close(sock):
    # 避免 SO_LINGER=0 的硬RST，采用半关闭（FIN），减少被对端Reset概率
    try: sock.shutdown(socket.SHUT_RDWR)
    except: pass
    sock.close()

def handle_client(local_sock):
    try:
        local_sock.settimeout(10)
        data = local_sock.recv(65535)
        if not data: return

        # 网页伪装
        if not data.startswith(b'CONNECT') and b'Host:' in data:
            host = data.split(b'Host:')[1].split(b'\r\n')[0].strip().decode()
            if host.split(':')[0] == LISTEN_HOST or host.startswith('127.'):
                local_sock.send(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + FAKE_WEB.encode())
                return

        # 认证
        auth_ok = b'Proxy-Authorization' in data
        if auth_ok:
            try:
                cred = base64.b64decode(data.split(b'Proxy-Authorization: Basic ')[1].split(b'\r\n')[0]).decode()
                auth_ok = (cred == f"{AUTH_USER}:{AUTH_PASS}")
            except: auth_ok = False
        if not auth_ok:
            local_sock.send(b'HTTP/1.1 407 Proxy Auth\r\nProxy-Authenticate: Basic realm="iP138"\r\n\r\n')
            return

        # 解析目标
        is_connect = data.startswith(b'CONNECT')
        if is_connect:
            host, port = data.split(b' ')[1].decode().split(':')
            port = int(port)
        else:
            host_line = [l for l in data.split(b'\r\n') if l.lower().startswith(b'host')]
            host = host_line[0].split(b':')[1].strip().decode().split(':')[0]
            port = 443 if b'https' in data[:10] else 80

        # 强制 IPv4
        addr = socket.getaddrinfo(host, port, socket.AF_INET if FORCE_IPV4 else 0, socket.SOCK_STREAM, 0)
        if not addr: return
        af, _, _, _, sa = addr[0]
        remote_sock = socket.socket(af, socket.SOCK_STREAM)
        remote_sock.settimeout(10)
        remote_sock.connect(sa)

        # ===== 关键：判断是否是 WebSocket（长连接）=====
        is_ws = b'Upgrade: websocket' in data.lower() or (is_connect and port == 443)
        set_keepalive(local_sock, aggressive=is_ws)
        set_keepalive(remote_sock, aggressive=is_ws)

        # CONNECT 响应
        if is_connect:
            local_sock.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            header_end = data.find(b'\r\n\r\n') + 4
            if len(data) > header_end: remote_sock.send(data[header_end:])
        else:
            remote_sock.send(data)

        # ===== 转发逻辑：长连接用 select（带心跳），短连接直接转发完就关 =====
        if is_ws:
            # 长连接：维持，但 30s 无数据就主动断（不卡死），让客户端重连
            while True:
                r, _, x = select.select([local_sock, remote_sock], [], [], 30)
                if x or not r: break  # 异常或30s空闲 -> 断（避免NAT老化后假死）
                if local_sock in r:
                    d = local_sock.recv(65535)
                    if not d: break
                    remote_sock.sendall(d)
                if remote_sock in r:
                    d = remote_sock.recv(65535)
                    if not d: break
                    local_sock.sendall(d)
        else:
            # 短连接（第一版逻辑）：双向转发，直到一端关闭，立刻释放
            while True:
                # 简单轮询，不长期阻塞
                local_sock.settimeout(5)
                remote_sock.settimeout(5)
                try:
                    d = local_sock.recv(65535)
                    if d: remote_sock.sendall(d)
                    else: break
                except: pass
                try:
                    d = remote_sock.recv(65535)
                    if d: local_sock.sendall(d)
                    else: break
                except: pass
    except Exception:
        pass
    finally:
        graceful_close(local_sock)
        try: graceful_close(remote_sock)
        except: pass

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(100)
    print(f"[*] Stable Proxy (Short+WS) on :{LISTEN_PORT} | Auth+Web | ForceIPv4")
    while True:
        cli, _ = s.accept()
        threading.Thread(target=handle_client, args=(cli,), daemon=True).start()

if __name__ == '__main__':
    import select
    main()
