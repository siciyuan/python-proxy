import socket, threading, select, base64, os

LISTEN_HOST, LISTEN_PORT = "0.0.0.0", 20095
FORCE_IPV4 = True
AUTH_USER, AUTH_PASS = "user", "pass123"  # 改密
FAKE_WEB = """<html><body style="font-family:sans-serif;color:#0055aa"><h2>iP查询</h2><p>您的IP地址信息</p></body></html>"""

def set_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
    except: pass

def handle_client(local_sock):
    remote_sock = None
    try:
        local_sock.settimeout(10)
        data = local_sock.recv(65535)
        if not data: return

        # 网页伪装
        if not data.startswith(b'CONNECT') and b'Host:' in data:
            host = [l for l in data.split(b'\r\n') if l.lower().startswith(b'host')][0].split(b':')[1].strip()
            if host == b'51.75.118.75' or host.startswith(b'192.168'):  # 直访IP或内网
                local_sock.send(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n' + FAKE_WEB.encode())
                return

        # 认证
        auth_ok = False
        if b'Proxy-Authorization' in data:
            try:
                cred = base64.b64decode(data.split(b'Proxy-Authorization: Basic ')[1].split(b'\r\n')[0]).decode()
                if cred == f"{AUTH_USER}:{AUTH_PASS}": auth_ok = True
            except: pass
        if not auth_ok:
            local_sock.send(b'HTTP/1.1 407 Proxy Auth\r\nProxy-Authenticate: Basic realm="iP138"\r\n\r\n')
            return

        # 解析目标
        is_connect = data.startswith(b'CONNECT')
        if is_connect:
            host, port = data.split(b' ')[1].decode().split(':')
            port = int(port)
        else:
            host = [l for l in data.split(b'\r\n') if l.lower().startswith(b'host')][0].split(b':')[1].strip().decode()
            port = 443 if b'https' in data[:10] else 80

        # 强制 IPv4
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET if FORCE_IPV4 else 0, socket.SOCK_STREAM, 0)
        if not addr_info: return
        af, _, _, _, sa = addr_info[0]
        remote_sock = socket.socket(af, socket.SOCK_STREAM)
        remote_sock.settimeout(10)
        remote_sock.connect(sa)
        remote_sock.settimeout(None)
        set_keepalive(remote_sock)
        set_keepalive(local_sock)

        # 响应
        if is_connect:
            local_sock.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            header_end = data.find(b'\r\n\r\n') + 4
            if len(data) > header_end: remote_sock.send(data[header_end:])
        else:
            remote_sock.send(data)

        # 双向转发（防 Reset 优化）
        while True:
            r, _, x = select.select([local_sock, remote_sock], [], [], 30)
            if x: break  # 异常才断
            if not r: continue  # 30秒无数据，继续（Keep-Alive 维持）
            try:
                if local_sock in r:
                    d = local_sock.recv(65535)
                    if not d: break
                    remote_sock.sendall(d)
                if remote_sock in r:
                    d = remote_sock.recv(65535)
                    if not d: break
                    local_sock.sendall(d)
            except (ConnectionResetError, BrokenPipeError):
                break
    except Exception:
        pass
    finally:
        try:
            # 优雅关闭，减少 RST
            if remote_sock: remote_sock.shutdown(socket.SHUT_RDWR)
        except: pass
        try: local_sock.close()
        except: pass
        try: remote_sock.close()
        except: pass

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(50)
    print(f"[*] Proxy on :{LISTEN_PORT} | Auth+Web | ForceIPv4: {FORCE_IPV4}")
    while True:
        cli, _ = s.accept()
        threading.Thread(target=handle_client, args=(cli,), daemon=True).start()

if __name__ == '__main__':
    main()
