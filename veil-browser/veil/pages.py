"""HTML for the browser's internal veil:// pages."""

from html import escape

from .privacy import ONION_SEARCH

_STYLE = """
:root { color-scheme: light dark; --bg:#f6f4fb; --fg:#1d1830; --muted:#6b6584; --card:#fff;
        --accent:#7d4698; --line:#e3deef; }
@media (prefers-color-scheme: dark) {
  :root { --bg:#16131f; --fg:#ece8f6; --muted:#a29cb8; --card:#211c2e; --accent:#c08be0; --line:#332c44; }
}
* { box-sizing: border-box; }
body { margin:0; font: 15px/1.5 system-ui, sans-serif; background:var(--bg); color:var(--fg); }
main { max-width: 720px; margin: 0 auto; padding: 56px 20px; }
h1 { font-size: 28px; margin: 0 0 6px; }
p.lead { color: var(--muted); margin: 0 0 28px; }
.card { background:var(--card); border:1px solid var(--line); border-radius:12px; padding:18px 20px; margin:14px 0; }
form { display:flex; gap:8px; }
input[type=search] { flex:1; font:inherit; padding:12px 14px; border-radius:10px; border:1px solid var(--line);
                     background:var(--card); color:var(--fg); }
button, a.btn { font:inherit; padding:11px 18px; border-radius:10px; border:0; background:var(--accent);
                color:#fff; text-decoration:none; cursor:pointer; display:inline-block; }
a.btn.secondary { background:transparent; color:var(--accent); border:1px solid var(--line); }
table { width:100%; border-collapse: collapse; }
td { padding: 6px 0; border-bottom: 1px solid var(--line); vertical-align: top; }
td:first-child { color: var(--muted); width: 40%; }
code { font-size: 13px; word-break: break-all; }
ul { padding-left: 20px; } li { margin: 4px 0; }
.logo { font-size: 44px; }
"""


def _page(title: str, body: str) -> str:
    return (f"<!doctype html><html lang=en><head><meta charset=utf-8>"
            f"<meta name=viewport content='width=device-width'><title>{escape(title)}</title>"
            f"<style>{_STYLE}</style></head><body><main>{body}</main></body></html>")


def home() -> str:
    return _page("Veil", f"""
<div class=logo>🧅</div>
<h1>Veil</h1>
<p class=lead>Every connection from this window goes through the Tor network.
Nothing is written to disk, and everything is forgotten when you close the browser.</p>
<form action="{ONION_SEARCH}" method=get>
  <input type=search name=q placeholder="Search privately with DuckDuckGo (.onion)" autofocus>
  <button>Search</button>
</form>
<div class=card>
  <b>Check your connection</b><br>
  <a href="https://check.torproject.org/">check.torproject.org</a> confirms that you are using Tor.
</div>
<div class=card>
  <b>Good habits</b>
  <ul>
    <li>Use <b>New Identity</b> (🧹) before switching to unrelated activity.</li>
    <li>Don't log in to accounts that identify you in the same session as anonymous browsing.</li>
    <li>Files you download may contact the internet when opened outside Veil. Open them offline.</li>
    <li>Leave the window at its default size: the page is letterboxed so sites see a common size.</li>
  </ul>
</div>
<p><a href="veil://status">Privacy status &amp; settings in effect →</a></p>
""")


def status(rows: list[tuple[str, str]]) -> str:
    table = "".join(f"<tr><td>{escape(k)}</td><td><code>{escape(v)}</code></td></tr>" for k, v in rows)
    return _page("Veil status", f"<h1>Privacy status</h1><p class=lead>What is active right now.</p>"
                                f"<div class=card><table>{table}</table></div>")


def https_failed(url: str, allow_url: str) -> str:
    return _page("Secure connection unavailable", f"""
<h1>⚠️ Secure connection unavailable</h1>
<p class=lead>HTTPS-only mode tried to load <code>{escape(url)}</code> securely and failed.</p>
<div class=card>The site may not support HTTPS. If you continue over plain HTTP, the Tor
<b>exit relay can read and modify</b> everything you send and receive on this site.</div>
<p><a class=btn href="veil://home">Go home</a>
<a class="btn secondary" href="{escape(allow_url)}">Continue over HTTP</a></p>
""")


def blocked(reason: str) -> str:
    return _page("Not connected", f"""
<h1>🛑 Request blocked</h1>
<p class=lead>{escape(reason)}</p>
<div class=card>Veil never connects directly. Pages load only once Tor has finished connecting.
Watch the progress in the status bar, or open <b>Tor log</b> from the menu if it is stuck.</div>
""")
