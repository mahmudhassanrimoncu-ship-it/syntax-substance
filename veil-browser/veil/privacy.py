"""Privacy policy: security levels, request filtering and fingerprint resistance."""

from __future__ import annotations

import enum
import json
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlsplit

ONION_SEARCH = "https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/"

# Small built-in list of well-known tracking/ads hosts. Matching is by domain
# suffix, so "google-analytics.com" also blocks "www.google-analytics.com".
TRACKER_DOMAINS = frozenset("""
google-analytics.com googletagmanager.com googletagservices.com doubleclick.net
googlesyndication.com googleadservices.com adservice.google.com app-measurement.com
connect.facebook.net facebook.net pixel.facebook.com analytics.twitter.com ads-twitter.com
static.ads-twitter.com analytics.tiktok.com bat.bing.com clarity.ms scorecardresearch.com
quantserve.com hotjar.com hotjar.io mixpanel.com segment.io segment.com cdn.segment.com
amplitude.com fullstory.com mouseflow.com crazyegg.com newrelic.com nr-data.net
criteo.com criteo.net taboola.com outbrain.com adnxs.com rubiconproject.com pubmatic.com
openx.net casalemedia.com moatads.com adsrvr.org demdex.net omtrdc.net everesttech.net
krxd.net bluekai.com rlcdn.com mathtag.com yieldmo.com sharethrough.com amazon-adsystem.com
chartbeat.com chartbeat.net parsely.com branch.io adjust.com appsflyer.com
""".split())

ALLOWED_SCHEMES = frozenset({"http", "https", "ws", "wss", "data", "blob", "veil", "about", "qrc"})
NETWORK_SCHEMES = frozenset({"http", "https", "ws", "wss"})


class SecurityLevel(enum.Enum):
    STANDARD = "standard"
    SAFER = "safer"
    SAFEST = "safest"

    @property
    def label(self) -> str:
        return {"standard": "Standard", "safer": "Safer", "safest": "Safest"}[self.value]

    @property
    def description(self) -> str:
        return {
            "standard": "All site features enabled. Fingerprinting surfaces are spoofed or blanked.",
            "safer": "JavaScript only on HTTPS and .onion sites. WebGL, WebRTC, WebAssembly and "
                     "audio fingerprinting APIs are removed. Media needs a click to play.",
            "safest": "JavaScript is disabled everywhere. Static content only.",
        }[self.value]

    def allows_js(self, url: str) -> bool:
        if self is SecurityLevel.STANDARD:
            return True
        if self is SecurityLevel.SAFEST:
            return False
        parts = urlsplit(url)
        return parts.scheme in ("https", "veil") or is_onion(parts.hostname or "")

    @property
    def webgl(self) -> bool:
        return self is SecurityLevel.STANDARD


def is_onion(host: str) -> bool:
    return host.lower().rstrip(".").endswith(".onion")


def is_tracker(host: str, extra: frozenset[str] = frozenset()) -> bool:
    host = host.lower().rstrip(".")
    labels = host.split(".")
    for i in range(len(labels) - 1):
        suffix = ".".join(labels[i:])
        if suffix in TRACKER_DOMAINS or suffix in extra:
            return True
    return False


def normalize_input(text: str) -> str:
    """Turn what the user typed into a URL (or an onion search)."""
    text = text.strip()
    if not text:
        return "veil://home"
    if " " not in text:
        parts = urlsplit(text)
        if parts.scheme in ALLOWED_SCHEMES and (parts.netloc or parts.scheme in ("veil", "about", "data")):
            return text
        host = text.split("/", 1)[0].split(":", 1)[0]
        if "." in host or host == "localhost":
            scheme = "http" if is_onion(host) else "https"
            return f"{scheme}://{text}"
    from urllib.parse import quote_plus
    return f"{ONION_SEARCH}?q={quote_plus(text)}"


@dataclass
class Decision:
    action: str              # "allow", "block", "redirect"
    url: Optional[str] = None
    reason: str = ""


@dataclass
class RequestPolicy:
    """Pure decision logic for every network request the engine makes."""

    tor_ready: bool = False
    https_only: bool = True
    block_trackers: bool = True
    http_exceptions: set[str] = field(default_factory=set)
    extra_trackers: frozenset[str] = frozenset()

    def decide(self, url: str) -> Decision:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = (parts.hostname or "").lower()

        if scheme not in ALLOWED_SCHEMES:
            return Decision("block", reason=f"scheme {scheme}: not allowed")
        if scheme not in NETWORK_SCHEMES:
            return Decision("allow")
        if not self.tor_ready:
            # Kill switch: nothing leaves the machine unless Tor is up.
            return Decision("block", reason="Tor is not connected")
        if self.block_trackers and is_tracker(host, self.extra_trackers):
            return Decision("block", reason="tracker")
        if self.https_only and scheme in ("http", "ws") and not is_onion(host) \
                and host not in self.http_exceptions:
            secure = "https" if scheme == "http" else "wss"
            new = parts._replace(scheme=secure)
            if parts.port == 80:
                new = new._replace(netloc=new.netloc.rsplit(":", 1)[0])
            return Decision("redirect", url=new.geturl(), reason="https-only upgrade")
        return Decision("allow")


# ---------------------------------------------------------------------------
# Fingerprint resistance (injected into every frame before page scripts run)
# ---------------------------------------------------------------------------

def user_agent(chromium_version: str) -> str:
    major = chromium_version.split(".")[0]
    # The most common desktop configuration, with the engine's real major version so
    # the claimed version matches the features the page can detect.
    return (f"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            f"(KHTML, like Gecko) Chrome/{major}.0.0.0 Safari/537.36")


FINGERPRINT_JS = r"""
(() => {
  'use strict';
  const CFG = __CONFIG__;
  if (window.__veil) return;
  Object.defineProperty(window, '__veil', {value: true});

  // Make our replacements look like native functions to toString() probes.
  const natives = new WeakMap();
  const origToString = Function.prototype.toString;
  const toStr = function toString() {
    if (natives.has(this)) return `function ${natives.get(this)}() { [native code] }`;
    return origToString.call(this);
  };
  natives.set(toStr, 'toString');
  Function.prototype.toString = toStr;

  const getter = (proto, prop, fn) => {
    if (!proto) return;
    try {
      const g = function () { return fn.call(this); };
      natives.set(g, 'get ' + prop);
      Object.defineProperty(proto, prop, {get: g, configurable: true, enumerable: true});
    } catch (e) {}
  };
  const method = (proto, prop, fn) => {
    if (!proto || !(prop in proto)) return;
    natives.set(fn, prop);
    try { Object.defineProperty(proto, prop, {value: fn, configurable: true, writable: true}); } catch (e) {}
  };
  const remove = (obj, prop) => { try { delete obj[prop]; } catch (e) {} };

  // --- Navigator: uniform hardware / locale ---------------------------------
  const N = Navigator.prototype;
  getter(N, 'hardwareConcurrency', () => 4);
  getter(N, 'deviceMemory', () => 8);
  getter(N, 'platform', () => 'Win32');
  getter(N, 'language', () => 'en-US');
  getter(N, 'languages', () => Object.freeze(['en-US', 'en']));
  getter(N, 'maxTouchPoints', () => 0);
  getter(N, 'webdriver', () => false);
  getter(N, 'doNotTrack', () => null);
  remove(N, 'getBattery');
  remove(N, 'connection');
  remove(N, 'userAgentData');
  remove(N, 'keyboard');
  method(N, 'getGamepads', function getGamepads() { return []; });
  if (window.MediaDevices) {
    method(MediaDevices.prototype, 'enumerateDevices',
           function enumerateDevices() { return Promise.resolve([]); });
  }

  // --- Screen: report the (letterboxed) viewport, never the real monitor ------
  const S = Screen.prototype;
  getter(S, 'width', () => window.innerWidth);
  getter(S, 'height', () => window.innerHeight);
  getter(S, 'availWidth', () => window.innerWidth);
  getter(S, 'availHeight', () => window.innerHeight);
  getter(S, 'availLeft', () => 0);
  getter(S, 'availTop', () => 0);
  getter(S, 'colorDepth', () => 24);
  getter(S, 'pixelDepth', () => 24);
  for (const [p, f] of [['outerWidth', () => window.innerWidth], ['outerHeight', () => window.innerHeight],
                        ['screenX', () => 0], ['screenY', () => 0], ['screenLeft', () => 0],
                        ['screenTop', () => 0], ['devicePixelRatio', () => 1]]) {
    try { Object.defineProperty(window, p, {get: f, configurable: true}); } catch (e) {}
  }

  // --- Timers: reduce precision to 100 ms (timing side channels) ------------
  const perfNow = Performance.prototype.now;
  method(Performance.prototype, 'now', function now() {
    return Math.floor(perfNow.call(this) / 100) * 100;
  });
  const tsDesc = Object.getOwnPropertyDescriptor(Event.prototype, 'timeStamp');
  if (tsDesc && tsDesc.get) {
    getter(Event.prototype, 'timeStamp', function () { return Math.floor(tsDesc.get.call(this) / 100) * 100; });
  }

  // --- Canvas: extraction returns a blank white image ------------------------
  const blank = (w, h) => {
    const c = document.createElement('canvas');
    c.width = w; c.height = h;
    const ctx = origGetContext.call(c, '2d');
    ctx.fillStyle = '#fff';
    origFillRect.call(ctx, 0, 0, w, h);
    return c;
  };
  const C = HTMLCanvasElement.prototype;
  const origGetContext = C.getContext;
  const origFillRect = CanvasRenderingContext2D.prototype.fillRect;
  const origToDataURL = C.toDataURL;
  const origToBlob = C.toBlob;
  method(C, 'toDataURL', function toDataURL(...a) {
    return origToDataURL.apply(blank(this.width || 1, this.height || 1), a);
  });
  method(C, 'toBlob', function toBlob(...a) {
    return origToBlob.apply(blank(this.width || 1, this.height || 1), a);
  });
  const whiteData = (sw, sh) => {
    const d = new ImageData(Math.max(1, Math.abs(sw | 0)), Math.max(1, Math.abs(sh | 0)));
    d.data.fill(255);
    return d;
  };
  method(CanvasRenderingContext2D.prototype, 'getImageData',
         function getImageData(sx, sy, sw, sh) { return whiteData(sw, sh); });
  if (window.OffscreenCanvasRenderingContext2D) {
    method(OffscreenCanvasRenderingContext2D.prototype, 'getImageData',
           function getImageData(sx, sy, sw, sh) { return whiteData(sw, sh); });
  }
  method(CanvasRenderingContext2D.prototype, 'measureText', (() => {
    const orig = CanvasRenderingContext2D.prototype.measureText;
    // Round metrics so sub-pixel font rendering differences don't leak.
    return function measureText(t) {
      const m = orig.call(this, t);
      const r = {};
      for (const k in m) r[k] = typeof m[k] === 'number' ? Math.round(m[k]) : m[k];
      return Object.setPrototypeOf(r, TextMetrics.prototype);
    };
  })());

  // --- WebGL -----------------------------------------------------------------
  for (const name of ['WebGLRenderingContext', 'WebGL2RenderingContext']) {
    const G = window[name] && window[name].prototype;
    if (!G) continue;
    const getParameter = G.getParameter;
    method(G, 'getParameter', function getParameter_(p) {
      if (p === 0x9245) return 'Google Inc.';          // UNMASKED_VENDOR_WEBGL
      if (p === 0x9246) return 'ANGLE (Generic GPU)';  // UNMASKED_RENDERER_WEBGL
      if (p === 0x1F00) return 'WebKit';               // VENDOR
      if (p === 0x1F01) return 'WebKit WebGL';         // RENDERER
      return getParameter.call(this, p);
    });
    method(G, 'readPixels', function readPixels(x, y, w, h, f, t, px) {
      if (px && px.fill) px.fill(0);
    });
  }

  if (CFG.strict) {
    for (const k of ['RTCPeerConnection', 'webkitRTCPeerConnection', 'RTCDataChannel',
                     'RTCSessionDescription', 'RTCIceCandidate', 'OfflineAudioContext',
                     'webkitOfflineAudioContext', 'WebAssembly', 'WebGLRenderingContext',
                     'WebGL2RenderingContext', 'SharedArrayBuffer']) {
      remove(window, k);
    }
  }
})();
"""


def fingerprint_script(level: SecurityLevel) -> str:
    cfg = {"strict": level is not SecurityLevel.STANDARD}
    return FINGERPRINT_JS.replace("__CONFIG__", json.dumps(cfg))


# Chromium switches. These are the network-level guarantees; the JS above is
# only best-effort.
def chromium_flags(socks_port: int) -> list[str]:
    return [
        f"--proxy-server=socks5://127.0.0.1:{socks_port}",
        # Never resolve hostnames locally: everything is resolved by Tor at the exit.
        "--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
        "--proxy-bypass-list=<-loopback>",
        # WebRTC may only use the proxy, and the SOCKS proxy has no UDP: no IP leak.
        "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--webrtc-ip-handling-policy=disable_non_proxied_udp",
        "--no-pings",
        "--dns-prefetch-disable",
        "--disable-background-networking",
        "--disable-component-update",
        "--disable-domain-reliability",
        "--disable-breakpad",
        "--disable-features=NetworkPrediction,InterestFeedContentSuggestions,"
        "AutofillServerCommunication,MediaRouter,OptimizationHints,PrivacySandboxSettings4",
        "--enable-features=ReducedSystemInfo,ReduceUserAgentMinorVersion",
        "--lang=en-US",
    ]
