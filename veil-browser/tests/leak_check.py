"""End-to-end leak check (needs a display or runs offscreen; no Tor network needed).

Runs Veil against a fake SOCKS5 "Tor" that logs every connection and serves a local
test page, then asserts: nothing connects before Tor is ready, every request goes through
SOCKS with the *hostname* (remote DNS, no local resolution), HTTPS-only upgrades first,
trackers never reach the network, and fingerprinting values are the uniform ones.

    python3 tests/leak_check.py
"""
import os, sys, socket, socketserver, struct, threading, http.server, json, time
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
OUT = os.environ.get("VEIL_SCREENSHOTS", "")
SOCKS_LOG = []

PAGE = b"""<!doctype html><title>fp</title><body>hello<script>
const c=document.createElement('canvas');c.width=50;c.height=20;const x=c.getContext('2d');
x.fillStyle='#f00';x.fillText('hi',2,10);
let pc; try { pc = typeof RTCPeerConnection } catch(e) { pc='err' }
window.fp = {ua:navigator.userAgent, hc:navigator.hardwareConcurrency, plat:navigator.platform,
 langs:navigator.languages, tz:Intl.DateTimeFormat().resolvedOptions().timeZone, off:new Date().getTimezoneOffset(),
 sw:screen.width, sh:screen.height, iw:innerWidth, ih:innerHeight, dpr:devicePixelRatio,
 canvasBlank: c.toDataURL()=== (()=>{const b=document.createElement('canvas');b.width=50;b.height=20;const y=b.getContext('2d');y.fillStyle='#fff';y.fillRect(0,0,50,20);return b.toDataURL()})(),
 px: Array.from(x.getImageData(0,0,1,1).data), perf: performance.now()%100, rtc: pc,
 tostr: HTMLCanvasElement.prototype.toDataURL.toString(), battery: 'getBattery' in navigator,
 uad: 'userAgentData' in navigator, wasm: typeof WebAssembly, tracker: null};
fetch('https://www.google-analytics.com/collect').then(()=>fp.tracker='LOADED').catch(()=>fp.tracker='blocked');
document.cookie='a=1';
</script><iframe src="http://third.test/frame"></iframe>"""

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type","text/html")
        if 'frame' in self.path: self.send_header("Set-Cookie","tp=1")
        self.end_headers(); self.wfile.write(PAGE if 'frame' not in self.path else b"frame")
    def log_message(self,*a): pass
web = http.server.ThreadingHTTPServer(("127.0.0.1",0),H); threading.Thread(target=web.serve_forever,daemon=True).start()
WEB_PORT = web.server_address[1]

class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        s=self.request; s.recv(262); s.sendall(b"\x05\x00")
        ver,cmd,_,atyp=s.recv(4)
        if atyp==3: host=s.recv(s.recv(1)[0]).decode()
        elif atyp==1: host="IP:"+socket.inet_ntoa(s.recv(4))
        else: host="IPv6"; s.recv(16)
        port=struct.unpack(">H",s.recv(2))[0]
        SOCKS_LOG.append(f"{host}:{port}")
        if port==80:
            up=socket.create_connection(("127.0.0.1",WEB_PORT))
            s.sendall(b"\x05\x00\x00\x01"+b"\0"*6)
            def pipe(a,b):
                try:
                    while (d:=a.recv(65536)): b.sendall(d)
                except OSError: pass
                finally:
                    try: b.shutdown(socket.SHUT_WR)
                    except OSError: pass
            threading.Thread(target=pipe,args=(up,s),daemon=True).start(); pipe(s,up)
        else:
            s.sendall(b"\x05\x05\x00\x01"+b"\0"*6)  # connection refused (no TLS here)
class TS(socketserver.ThreadingTCPServer): allow_reuse_address=True; daemon_threads=True
socks=TS(("127.0.0.1",0),Socks); threading.Thread(target=socks.serve_forever,daemon=True).start()
SOCKS_PORT=socks.server_address[1]

class StubTor:
    managed=True; socks_port=SOCKS_PORT; log_lines=["stub"]; ready=False
    def is_alive(self): return True
    def connect_control(self): return True
    def bootstrap_progress(self): return (100,"Done") if self.ready else (45,"Loading relay descriptors")
    def version(self): return "stub"
    def stop(self): pass
    def circuit_for_host(self,h): return None
    def new_identity(self): pass

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
from veil.app import prepare_engine, lock_proxy
from veil.privacy import RequestPolicy, SecurityLevel
prepare_engine(SOCKS_PORT)
from PyQt6.QtWidgets import QApplication
from veil.ui import BrowserWindow
from PyQt6.QtCore import QTimer, QUrl
app=QApplication([sys.argv[0]]); lock_proxy(SOCKS_PORT)

tor=StubTor(); pol=RequestPolicy()
w=BrowserWindow(tor,pol,SecurityLevel.STANDARD); w.show()
results={}
def at(ms,f): QTimer.singleShot(ms,f)
def shot(name):
    if OUT: w.grab().save(f"{OUT}/{name}.png")
def step1():
    shot("home"); results["ready_before"]=pol.tor_ready
    w.navigate("example.com")   # Tor not ready -> blocked page
def step2():
    results["blocked_url"]=w.view().url().toString(); shot("blocked"); results["socks_before_ready"]=list(SOCKS_LOG)
    tor.ready=True
def step3():
    results["ready"]=pol.tor_ready
    w.navigate("http://fp.test/")   # https-only upgrade -> fails -> https-failed page
def step4():
    results["after_upgrade_url"]=w.view().url().toString(); shot("https_failed")
    w.view().setUrl(QUrl("veil://allow-http?url=http%3A%2F%2Ffp.test%2F"))
def step5():
    results["fp_url"]=w.view().url().toString()
    w.view().page().runJavaScript("JSON.stringify(window.fp)", lambda r: results.__setitem__("fp", json.loads(r) if r else None))
    w.engine.profile.cookieStore().loadAllCookies()
def step6():
    shot("page")
    results["socks_log"]=sorted(set(SOCKS_LOG)); results["trackers"]=w.blocked_count
    print(json.dumps(results,indent=1)); app.quit()
    fp = results["fp"] or {}
    checks = {
        "no traffic before Tor ready": results["socks_before_ready"] == [],
        "kill-switch page shown": results["blocked_url"].startswith("veil://blocked"),
        "https tried first": "fp.test:443" in results["socks_log"],
        "https-failed page shown": results["after_upgrade_url"].startswith("veil://https-failed"),
        "remote DNS only (no IPs sent)": all(not h.startswith("IP") for h in results["socks_log"]),
        "tracker never hit network": not any("google-analytics" in h for h in results["socks_log"]),
        "tracker blocked": fp.get("tracker") == "blocked" and results["trackers"] >= 1,
        "UTC": fp.get("tz") == "UTC" and fp.get("off") == 0,
        "uniform navigator": fp.get("hc") == 4 and fp.get("plat") == "Win32" and not fp.get("battery"),
        "screen == letterboxed viewport": fp.get("sw") == fp.get("iw") and fp.get("iw", 1) % 200 == 0,
        "canvas readout blank": fp.get("canvasBlank") is True and fp.get("px") == [255, 255, 255, 255],
        "patched fn looks native": "[native code]" in fp.get("tostr", ""),
    }
    for name, ok in checks.items():
        print(("PASS " if ok else "FAIL ") + name)
    global EXIT
    EXIT = 0 if all(checks.values()) else 1
for i,f in enumerate([step1,step2,step3,step4,step5,step6]): at(2500*(i+1),f)
EXIT = 1
app.exec()
sys.exit(EXIT)
