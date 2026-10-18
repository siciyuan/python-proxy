import socket, threading, urllib.parse, base64, hmac, os, sys, time

PROXY_USER  = os.environ.get("PROXY_USER", "")
PROXY_PASS  = os.environ.get("PROXY_PASS", "")
HOST = os.environ.get("PROXY_HOST", "0.0.0.0")
PORT = int(os.environ.get("PROXY_PORT", "3000"))
VERBOSE = os.environ.get("PROXY_VERBOSE","false").lower()=="true"

def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}",flush=True) if VERBOSE else None
def err(m): print(f"[{time.strftime('%H:%M:%S')}] {m}",file=sys.stderr,flush=True)
def close(s):
    try: s.close()
    except: pass

FAKE = b"""<!doctype html><html><head><meta charset=utf-8><title>Engineering Notes</title>
<style>body{margin:0;font:15px/1.65 system-ui,sans-serif;color:#1f2328;background:#fff}
main{max-width:720px;margin:48px auto;padding:0 24px}code{background:#f6f8fa;padding:2px 5px}</style>
</head><body><main><h1>Internal documentation mirror</h1>
<p>Read-only mirror synced weekly. Sections under <code>/docs/</code>.</p></main></body></html>"""

def page(sock):
    try:
        sock.sendall((f"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\n"
            f"Content-Type: text/html; charset=utf-8\r\nContent-Length: {len(FAKE)}\r\n"
            f"Connection: close\r\n\r\n").encode()+FAKE)
    except: pass

def auth(data):
    try:
        for ln in data.decode("iso-8859-1").split("\r\n")[1:]:
            if not ln: break
            if ":" in ln and ln.split(":",1)[0].strip().lower()=="proxy-authorization":
                tok=ln.split(":",1)[1].strip().split(None,1)[1]
                u,p=base64.b64decode(tok).decode().split(":",1)
                return hmac.compare_digest(u,PROXY_USER) and hmac.compare_digest(p,PROXY_PASS)
    except: pass
    return False

def strip_auth(data):
    out=[]; txt=data.decode("iso-8859-1")
    for ln in txt.split("\r\n"):
        if ":" in ln and ln.split(":",1)[0].strip().lower()=="proxy-authorization": continue
        out.append(ln)
    return "\r\n".join(out).encode("iso-8859-1")

# ===== 最土的单向拷贝：阻塞，一个方向一个线程 =====
def pipe(src, dst):
    try:
        while True:
            d = src.recv(8192)
            if not d: break
            dst.sendall(d)
    except: pass

def relay(a, b):
    """两个方向并发拷贝，谁先断就全关"""
    t1 = threading.Thread(target=pipe, args=(a,b), daemon=True)
    t2 = threading.Thread(target=pipe, args=(b,a), daemon=True)
    t1.start(); t2.start()
    t1.join(); t2.join()

# ===== 处理 =====
def handle(cs, addr):
    try:
        cs.settimeout(15)
        head = cs.recv(8192)
        if not head: return

        # --- 伪装页前置判断 ---
        try:
            first = head.decode("iso-8859-1",errors="replace").split("\r\n",1)[0].split()
            meth,target = first[0],first[1]
        except: return
        if meth.upper()!="CONNECT" and not target.lower().startswith(("http://","https://")):
            page(cs); return

        if not auth(head):
            try: cs.sendall(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n"
                b"Content-Length: 0\r\nConnection: close\r\n\r\n")
            except: pass; return

        if meth.upper()=="CONNECT":
            hp = target.rsplit(":",1)
            h=hp[0]; p=int(hp[1]) if len(hp)>1 else 443
            ss=socket.socket(); ss.settimeout(10)
            try: ss.connect((h,p))
            except: close(cs); close(ss); return
            cs.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            relay(cs, ss)
            close(cs); close(ss); return

        # plain http proxy
        up=urllib.parse.urlparse(target); h=up.hostname; p=up.port or 80
        if not h: return
        ss=socket.socket(); ss.settimeout(10)
        try: ss.connect((h,p))
        except: close(cs); close(ss); return
        ss.sendall(strip_auth(head))
        relay(cs, ss)
        close(cs); close(ss)
    except: pass
    finally: close(cs)

# ===== main，极简 =====
def main():
    ls=socket.socket(); ls.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    ls.bind((HOST,PORT)); ls.listen(128)
    print(f"proxy on {HOST}:{PORT}",flush=True)
    while True:
        try: cs,_ = ls.accept()
        except KeyboardInterrupt: close(ls); break
        except: continue
        threading.Thread(target=handle,args=(cs,None),daemon=True).start()

if __name__=="__main__": main()
