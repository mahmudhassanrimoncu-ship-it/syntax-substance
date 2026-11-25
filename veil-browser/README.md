# Veil — a privacy browser with Tor-like protections

Veil is a small desktop browser (Python + Qt WebEngine/Chromium) that sends **all** traffic
through the Tor network and adds many of Tor Browser's protections.

> **Use Tor Browser for real anonymity.** Veil is a learning project and a lightweight
> alternative. Tor Browser makes every user look the same, so its users blend in. Veil's
> users don't share that crowd: there are few of them and it runs on a different engine.
> See [Limitations](#limitations).

## Features

| Area | What Veil does |
| --- | --- |
| **Tor routing** | Starts its own `tor` daemon (or attaches to one) and forces Chromium through its SOCKS5 port. Tor exits if Veil dies. |
| **No DNS leaks** | Hostnames are resolved by Tor at the exit. All local DNS is disabled (`--host-resolver-rules=MAP * ~NOTFOUND`). |
| **Kill switch** | Until Tor has fully connected, or if it stops, every network request is blocked. |
| **Circuit isolation** | Each site gets its own circuit (`IsolateDestAddr`), so unrelated sites don't share an exit. |
| **New Identity** (Ctrl+Shift+U) | Closes all tabs, deletes the in-memory profile (cookies, cache, storage, HTTP exceptions), sends `NEWNYM` and closes open streams. |
| **New circuit for this site** (Ctrl+Shift+L) | Tears down only the current site's circuit and reloads. |
| **Circuit view** (🧅) | Shows the guard, middle and exit relays (with countries) the current site uses. |
| **Amnesia** | Off-the-record profile: nothing is written to disk. Tor state is a temp dir deleted on exit. |
| **Security levels** | *Standard*; *Safer*: JS only on HTTPS/.onion, no WebGL/WebRTC/WebAssembly/OfflineAudio, click-to-play media; *Safest*: no JS. |
| **HTTPS-only** | Upgrades `http://` and `ws://` (not .onion). If that fails, a warning page offers a per-site HTTP exception. |
| **Fingerprinting resistance** | UTC time zone, `en-US`, a common Windows user agent and matching client hints, fixed `hardwareConcurrency` and `deviceMemory`. Screen size reports the viewport, `devicePixelRatio` is 1, timers are rounded to 100 ms, canvas readout is blank, WebGL vendor/renderer are generic, and battery, gamepads, media devices and `userAgentData` are hidden. |
| **Letterboxing** | The page area is rounded down to 200×100 px steps, so sites see a few common window sizes. |
| **WebRTC** | Restricted to proxied connections. SOCKS has no UDP, so it can't leak your IP. Removed entirely at Safer and above. |
| **Tracker blocking** | A built-in list of ~60 ad/analytics domains, plus `--blocklist FILE`. |
| **Cookies & permissions** | Third-party cookies blocked. Geolocation, camera, mic, notifications and fullscreen are always denied. |
| **Onion services** | `.onion` addresses work directly. The home page searches DuckDuckGo's onion service. |

## Install & run

Requires Python 3.10+ and Tor.

```bash
# Debian/Ubuntu: sudo apt install tor      macOS: brew install tor
# Windows: install the Tor Expert Bundle and pass --tor-path C:\path\to\tor.exe
pip install -r requirements.txt
python -m veil                    # opens the home page once Tor connects
python -m veil https://check.torproject.org
```

Options:

```
--security {standard,safer,safest}   initial security level
--external-tor 9050:9051             use a running Tor (system tor 9050:9051, Tor Browser 9150:9151)
--control-password PW               control-port password for --external-tor (or VEIL_TOR_PASSWORD)
--torrc-extra FILE                   extra torrc lines, e.g. bridges for censored networks
--tor-data-dir DIR                   keep Tor state (stable entry guards) instead of a temp dir
--tor-path PATH                      tor binary
--blocklist FILE                     extra tracker domains, one per line
--no-https-only / --no-tracker-blocking
```

Bridges example (`bridges.txt`):

```
UseBridges 1
ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy
Bridge obfs4 192.0.2.1:443 FINGERPRINT cert=... iat-mode=0
```

## Tests

```bash
python -m unittest discover -s tests       # policy, parsers, control-port auth (fake Tor)
python tests/leak_check.py                 # end-to-end leak test, offscreen, no Tor network needed
```

`leak_check.py` runs the real browser against a fake SOCKS5 "Tor" that logs every
connection. It asserts that nothing connects before Tor is ready, that only hostnames
(never resolved IPs) are sent, that HTTPS is tried first, that trackers never reach the
network, and that the fingerprinting values are the uniform ones.

## How it's built

```
veil/app.py      CLI; Chromium switches + Qt proxy lock, set before the engine starts
veil/tor.py      launches tor, control-port client (SAFECOOKIE/COOKIE/password auth), circuits
veil/privacy.py  request policy (kill switch, HTTPS-only, trackers), security levels, anti-fingerprinting JS
veil/ui.py       window, tabs, letterboxing, veil:// pages, New Identity / circuit actions
veil/pages.py    HTML for veil://home, veil://status and warning pages
```

A gotcha we hit: Qt WebEngine **ignores** Chromium switches given as application
arguments. If you pass `--proxy-server` that way, the browser silently connects directly.
Veil sets them through `QTWEBENGINE_CHROMIUM_FLAGS` and *also* sets Qt's application proxy to
Tor. It removes `http_proxy`/`https_proxy` from the environment so a system proxy can never be
used instead of Tor.

## Limitations

Be honest with yourself about these before relying on Veil:

- **Small crowd.** Tor Browser's protection comes from millions of identical browsers. Veil
  claims to be a common Chrome, but sites can still tell it apart: Qt WebEngine features,
  installed system fonts and audio processing differ.
- **The anti-fingerprinting JavaScript is best-effort.** It runs before page scripts in every
  frame, but Web Workers and some `about:blank` iframe tricks can reach the original APIs.
  The network-level protections (proxy, DNS, kill switch, WebRTC policy) don't depend on it.
- **No first-party isolation** of cookies and storage beyond blocking third-party cookies.
  Use New Identity between unrelated activities.
- **Tor state is thrown away by default**, so you get new entry guards each launch. Use
  `--tor-data-dir` for stable guards.
- Running as root disables Chromium's sandbox. Run as a normal user.
- Downloads are handed to other apps, which may connect to the internet directly.
