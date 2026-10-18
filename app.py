import socket, select, threading, urllib.parse, base64, hmac, os, sys, time, random

# ================= 配置 =================
PROXY_USER   = os.environ.get("PROXY_USER", "")
PROXY_PASS   = os.environ.get("PROXY_PASS", "")
LISTEN_HOST  = os.environ.get("PROXY_HOST", "0.0.0.0")
LISTEN_PORT  = int(os.environ.get("PROXY_PORT", "3000"))
VERBOSE      = os.environ.get("PROXY_VERBOSE", "false").lower() == "true"

BUFFER_SIZE   = 8192
IDLE_TIMEOUT  = 120
CONNECT_TIMEOUT = 10
MAX_CONCURRENT = 400
MAX_BUFFER     = 2 * 1024 * 1024
# =======================================

sem = threading.Semaphore(MAX_CONCURRENT)
alive = 0
alive_lock = threading.Lock()

# ---------------- 伪装页（轻量） ----------------
_TITLE = random.choice([
    "Docs · Engineering Notes","Release Notes","Runtime Handbook",
    "Edge Infra Docs","Build Log Mirror"
]).encode()
_FAKE = (b"""<!doctype html><html lang=zh-CN><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1">
<title>""" + _TITLE + b"""</title>
<style>body{margin:0;font:15px/1.65 system-ui,sans-serif;color:#1f2328;background:#fff}
header{border-bottom:1px solid #d0d7de;padding:14px 28px;font-weight:600}
main{max-width:760px;margin:40px auto;padding:0 22px}code{background:#f6f8fa;padding:1px 5px;border-radius:3px}
footer{margin-top:56px;border-top:1px solid #d0d7de;padding:14px 28px;font-size:13px;color:#57606a}
</style></head><body><header>engineering / notes</header><main>
<h1>Internal documentation mirror</h1>
<p>This is a read-only mirror of internal engineering notes, synced weekly.</p>
<p>Sections under <code>/docs/</code> and <code>/changelog/</code>; signed access required for some.</p>
</main><footer>&copy; 2026 infra team</footer></body></html>""")

def _hdr(code="200 OK", ctype="text/html; charset=utf-8", body=b""):
    return (f"HTTP/1.1 {code}\r\nServer: nginx/1.24.0\r\n"
            f"Content-Type: {ctype}\r\nContent-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n").encode("latin-1")

# ---------------- 日志 ----------------
def log(m):   print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True) if VERBOSE else None
def err(m):   print(f"[{time.strftime('%H:%M:%S')}] {m}", file=sys.stderr, flush=True)

# ---------------- 工具 ----------------
def closes(s):
    try: s.close()
    except Exception: pass

def newsock():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    return s

# ---------------- 鉴权 ----------------
def auth_ok(data: bytes):
    try:
        txt = data.decode("iso-8859-1"); hdr = txt.split("\r\n")
        tok = None
        for ln in hdr[1:]:
            if not ln: break
            k,v = ln.split(":",1) if ":" in ln else ("","")
            if k.strip().lower()=="proxy-authorization": tok=v.strip(); break
        if not tok or tok.split(None,1)[0].lower()!="basic": return False
        u,p = base64.b64decode(tok.split(None,1)[1]).decode().split(":",1)
        return hmac.compare_digest(u,PROXY_USER) and hmac.compare_digest(p,PROXY_PASS)
    except Exception: return False

def strip_auth(data: bytes):
    out=[]; txt=data.decode("iso-8859-1")
    for ln in txt.split("\r\n"):
        if ":" in ln and ln.split(":",1)[0].strip().lower()=="proxy-authorization": continue
        out.append(ln)
    return "\r\n".join(out).encode("iso-8859-1")

# ---------------- 直连伪装 ----------------
def direct(data: bytes):
    """返回 path 或 None"""
    try:
        first = data.decode("iso-8859-1",errors="replace").split("\r\n",1)[0]
        p = first.split()
        if len(p)<2 or p[0].upper()=="CONNECT": return None
        if p[1].lower().startswith(("http://","https://")): return None
        return p[1]
    except Exception: return None

def serve_fake(sock, path):
    try:
        if path=="/robots.txt":
            b=b"User-agent: *\nAllow: /\n"
            sock.sendall(_hdr("200 OK","text/plain",b)+b); return
        if path=="/favicon.ico":
            sock.sendall(b"HTTP/1.1 204 No Content\r\nServer: nginx/1.24.0\r\nConnection: close\r\n\r\n"); return
        sock.sendall(_hdr("200 OK","text/html; charset=utf-8",_FAKE)+_FAKE)
    except Exception: pass

# ---------------- tunnel（修复核心） ----------------
def tunnel(a, b):
    a.setblocking(False); b.setblocking(False)
    fwd = {a:b, b:a}; buf = {a:bytearray(), b:bytearray()}
    while True:
        wl = [s for s in (a,b) if buf[s]]
        try: r,w,x = select.select([a,b], wl, [a,b], IDLE_TIMEOUT)
        except (OSError, ValueError): return          # fd 复用直接退出，不炸
        if x or (not r and not w): return
        for s in r:
            dst = fwd[s]
            if len(buf[dst]) > MAX_BUFFER: continue
            try: chunk = s.recv(BUFFER_SIZE)
            except (BlockingIOError, InterruptedError): continue
            except OSError: return
            if not chunk: return
            buf[dst] += chunk
        for s in w:
            b2 = buf[s]; 
            if not b2: continue
            try: n = s.send(bytes(b2))
            except (BlockingIOError, InterruptedError): continue
            except OSError: return
            if n<=0: return
            del b2[:n]

# ---------------- 协议处理 ----------------
def do_connect(cs, host, port):
    ss = None
    try: ss = newsock(); ss.settimeout(CONNECT_TIMEOUT); ss.connect((host,int(port)))
    except Exception as e: err(f"[C ERR] {host}:{port} {e}"); closes(cs); closes(ss); return
    try: cs.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
    except Exception: closes(ss); return
    tunnel(cs, ss); closes(cs); closes(ss)

def do_http(cs, data, url):
    u = urllib.parse.urlparse(url); h=u.hostname; p=u.port or 80
    if not h: return
    ss=None
    try: ss=newsock(); ss.settimeout(CONNECT_TIMEOUT); ss.connect((h,p))
    except Exception: closes(cs); closes(ss); return
    try: ss.sendall(strip_auth(data))
    except Exception: closes(ss); return
    tunnel(cs,ss); closes(cs); closes(ss)

# ---------------- 每连接入口 ----------------
def handle(cs, addr):
    global alive
    try:
        cs.settimeout(CONNECT_TIMEOUT)
        try: data = cs.recv(BUFFER_SIZE)
        except Exception: return
        if not data: return

        p = direct(data)
        if p is not None:              # 直连 → 伪装页，绝不进代理分支
            serve_fake(cs, p); return

        if not auth_ok(data):
            try: cs.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                            b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                            b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            except: pass; return

        first = data.decode("iso-8859-1").split("\r\n",1)[0].split()
        meth, target = first[0], first[1]
        if meth.upper()=="CONNECT":
            hp = target.rsplit(":",1); h=hp[0]; port=int(hp[1]) if len(hp)>1 else 443
            log(f"[CONNECT] {addr}->{h}:{port}"); do_connect(cs,h,port); return
        do_http(cs, data, target)
    except (socket.timeout, ConnectionResetError, BrokenPipeError, OSError): pass
    except Exception as e: err(f"[BUG] {addr} {type(e).__name__}:{e}")
    finally:
        closes(cs)
        with alive_lock:
            global alive; alive -= 1; n = alive
        sem.release()
        if VERBOSE and n%50==0: log(f"[alive]{n}")

# ---------------- main（监听 socket 永不传给线程） ----------------
def main():
    ls = newsock(); ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,1)
    ls.bind((LISTEN_HOST, LISTEN_PORT)); ls.listen(256)
    print(f"listen {LISTEN_HOST}:{LISTEN_PORT}  max={MAX_CONCURRENT}", flush=True)
    while True:
        try: cs, addr = ls.accept()
        except KeyboardInterrupt:
            print("\nshutdown"); closes(ls); break
        except Exception as e:
            err(f"[accept] {e}"); time.sleep(.05); continue

        if not sem.acquire(blocking=False):
            err(f"[full] {addr}"); closes(cs); continue
        with alive_lock: alive += 1
        try: threading.Thread(target=handle, args=(cs,addr), daemon=True).start()
        except RuntimeError as e:
            err(f"[thread] {e}"); closes(cs)
            with alive_lock: alive -= 1; sem.release()

if __name__ == "__main__": main()
