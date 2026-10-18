import socket
import threading
import select
import base64
import os

LISTEN_HOST = '0.0.0.0'
LISTEN_PORT = 20095
FORCE_IPV4 = True

# 1. 认证配置 (修改为你自己的账号密码)
AUTH_USER = "user"
AUTH_PASS = "pass123"
AUTH_STRING = f"{AUTH_USER}:{AUTH_PASS}".encode('utf-8')
EXPECTED_AUTH = base64.b64encode(AUTH_STRING).decode('utf-8')

def set_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    try:
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 20)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)
    except (AttributeError, OSError):
        pass

def fake_web_response():
    # 2. 网页伪装：访问 IP:端口 时返回的假页面 (类似 ip138 查询网风格)
    html = """
    <!DOCTYPE html><html><head><meta charset="utf-8">
    <title>查询网 iP138.com</title>
    <style>body{font-family:sans-serif;text-align:center;margin-top:50px;}
    h1{color:#2b85e4;} .box{background:#f5f5f5;padding:20px;border-radius:8px;display:inline-block;}</style>
    </head><body>
    <h1>iP查询</h1><div class="box">
    <h2>iP地址归属地查询</h2>
    <p>您的访问已记录。</p>
    <p><small>OVH Hosting / France</small></p>
    </div></body></html>
    """
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n"
        b"Server: nginx/1.18.0\r\n"
        b"Connection: close\r\n\r\n" + html.encode('utf-8')
    )

def handle_client(local_sock):
    remote_sock = None
    try:
        local_sock.settimeout(10)
        data = b''
        while b'\r\n\r\n' not in data:
            chunk = local_sock.recv(4096)
            if not chunk: break
            data += chunk
        
        if not data: return
        
        # --- 网页伪装逻辑 ---
        # 如果直接访问 IP:端口 (GET /)，返回假网页，不要求认证
        if data.startswith(b'GET /') and b'Proxy-Connection' not in data:
            local_sock.send(fake_web_response())
            return

        # --- 认证逻辑 (仅针对代理请求) ---
        auth_ok = False
        if FORCE_IPV4: # 简单校验基础代理头
            if data.startswith(b'CONNECT') or data.startswith(b'GET') or data.startswith(b'POST'):
                # 提取 Proxy-Authorization
                auth_line = [l for l in data.split(b'\r\n') if l.lower().startswith(b'proxy-authorization')]
                if auth_line:
                    try:
                        # 格式: Basic base64(user:pass)
                        token = auth_line[0].split(b' ')[-1].decode('utf-8').strip()
                        if token == EXPECTED_AUTH:
                            auth_ok = True
                    except: pass
                
                if not auth_ok:
                    # 返回 407 要求认证
                    local_sock.send(b'HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm="iP138"\r\n\r\n')
                    return
            else:
                # 非标准请求直接断开
                return
        
        # --- 解析目标 ---
        is_connect = data.startswith(b'CONNECT')
        if is_connect:
            host_port = data.split(b' ')[1].decode('utf-8')
            host, port = host_port.split(':')
            port = int(port)
        else:
            # 简单解析 HTTP 目标
            host_line = [l for l in data.split(b'\r\n') if l.lower().startswith(b'host')]
            if not host_line: return
            host = host_line[0].split(b':')[1].strip().decode('utf-8')
            port = 80

        # --- 强制 IPv4 连接 ---
        addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM, 0)
        if not addr_info: return
        af, socktype, proto, canonname, sa = addr_info[0]
        
        remote_sock = socket.socket(af, socktype, proto)
        remote_sock.settimeout(10)
        remote_sock.connect(sa)
        remote_sock.settimeout(None)
        set_keepalive(remote_sock)
        set_keepalive(local_sock)

        # --- 响应与转发 ---
        if is_connect:
            local_sock.send(b'HTTP/1.1 200 Connection Established\r\n\r\n')
            # 剥离头，发送剩余数据
            header_end = data.find(b'\r\n\r\n') + 4
            if len(data) > header_end:
                remote_sock.send(data[header_end:])
        else:
            # 转发原始 HTTP (含 Host)，远端会自动处理
            remote_sock.send(data)

        # 双向透明转发 (WebSocket 兼容)
        while True:
            r, _, x = select.select([local_sock, remote_sock], [], [local_sock, remote_sock], 60)
            if x: break
            if not r: continue
            
            if local_sock in r:
                d = local_sock.recv(65535)
                if not d: break
                remote_sock.sendall(d)
            if remote_sock in r:
                d = remote_sock.recv(65535)
                if not d: break
                local_sock.sendall(d)

    except Exception:
        pass
    finally:
        try: local_sock.close()
        except: pass
        try: remote_sock.close()
        except: pass

def main():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((LISTEN_HOST, LISTEN_PORT))
    s.listen(50)
    print(f"[*] Proxy on {LISTEN_HOST}:{LISTEN_PORT} | Auth: ON | ForceIPv4: {FORCE_IPV4} | FakeWeb: ON")

    while True:
        cli, addr = s.accept()
        t = threading.Thread(target=handle_client, args=(cli,), daemon=True)
        t.start()

if __name__ == '__main__':
    main()
