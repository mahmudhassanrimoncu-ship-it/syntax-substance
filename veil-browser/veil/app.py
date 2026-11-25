"""Command-line entry point."""

from __future__ import annotations

import argparse
import atexit
import os
import signal
import sys
import time

from .privacy import RequestPolicy, SecurityLevel, chromium_flags
from .tor import TorError, TorService


def parse_args(argv=None) -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="veil", description="A privacy browser that routes everything through Tor.")
    p.add_argument("url", nargs="?", help="page to open once Tor is connected")
    p.add_argument("--security", choices=[l.value for l in SecurityLevel], default="standard",
                   help="initial security level (default: standard)")
    p.add_argument("--no-https-only", action="store_true", help="allow plain HTTP without asking")
    p.add_argument("--no-tracker-blocking", action="store_true")
    p.add_argument("--blocklist", metavar="FILE", help="extra tracker domains, one per line")
    tor = p.add_argument_group("Tor")
    tor.add_argument("--tor-path", help="path to the tor executable (default: found on PATH)")
    tor.add_argument("--torrc-extra", metavar="FILE",
                     help="extra torrc lines, e.g. bridges: 'UseBridges 1', 'Bridge obfs4 …', "
                          "'ClientTransportPlugin obfs4 exec /usr/bin/obfs4proxy'")
    tor.add_argument("--tor-data-dir", metavar="DIR",
                     help="keep Tor state (entry guards) in DIR instead of a throwaway temp dir")
    tor.add_argument("--external-tor", metavar="SOCKS:CONTROL",
                     help="use an already-running Tor, e.g. 9050:9051 (system tor) or 9150:9151 (Tor Browser)")
    tor.add_argument("--control-password", help="control-port password for --external-tor "
                                                "(or set VEIL_TOR_PASSWORD)")
    return p.parse_args(argv)


PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "ftp_proxy", "no_proxy")


def prepare_engine(socks_port: int) -> None:
    """Configure Chromium before the Qt application (and engine) is created."""
    # Report UTC to every site, like Tor Browser.
    os.environ["TZ"] = "UTC"
    if hasattr(time, "tzset"):
        time.tzset()
    # Qt WebEngine ignores Chromium switches given as application arguments; it only
    # reads this variable (quoted values may contain spaces). It replaces anything
    # inherited, so nothing from the environment can override the proxy.
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(
        f'"{f}"' if " " in f else f for f in chromium_flags(socks_port))
    # A system proxy must never be used instead of (or in front of) Tor.
    for var in PROXY_ENV_VARS:
        os.environ.pop(var, None)
        os.environ.pop(var.upper(), None)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        print("veil: running as root, so the Chromium sandbox has to be disabled. "
              "Run as a normal user for better protection.", file=sys.stderr)
        os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"

    from PyQt6.QtWebEngineCore import QWebEngineUrlScheme
    scheme = QWebEngineUrlScheme(b"veil")
    scheme.setSyntax(QWebEngineUrlScheme.Syntax.Host)
    scheme.setFlags(QWebEngineUrlScheme.Flag.SecureScheme | QWebEngineUrlScheme.Flag.LocalScheme
                    | QWebEngineUrlScheme.Flag.LocalAccessAllowed)
    QWebEngineUrlScheme.registerScheme(scheme)


def lock_proxy(socks_port: int) -> None:
    """Second layer: Qt's application proxy is Tor too, so a dropped switch can't mean DIRECT."""
    from PyQt6.QtNetwork import QNetworkProxy, QNetworkProxyFactory
    QNetworkProxyFactory.setUseSystemConfiguration(False)
    QNetworkProxy.setApplicationProxy(
        QNetworkProxy(QNetworkProxy.ProxyType.Socks5Proxy, "127.0.0.1", socks_port))


def main(argv=None) -> int:
    args = parse_args(argv)

    external = None
    if args.external_tor:
        try:
            s, c = args.external_tor.split(":")
            external = (int(s), int(c))
        except ValueError:
            print("--external-tor expects SOCKS:CONTROL, e.g. 9050:9051", file=sys.stderr)
            return 2

    torrc_extra = None
    if args.torrc_extra:
        with open(args.torrc_extra) as f:
            torrc_extra = f.read()

    try:
        tor = TorService(tor_path=args.tor_path, external=external,
                         control_password=args.control_password or os.environ.get("VEIL_TOR_PASSWORD"),
                         torrc_extra=torrc_extra, data_dir=args.tor_data_dir)
        tor.start()
    except (TorError, OSError) as e:
        print(f"veil: {e}", file=sys.stderr)
        return 1
    atexit.register(tor.stop)

    prepare_engine(tor.socks_port)
    from PyQt6.QtWidgets import QApplication
    from .ui import BrowserWindow

    app = QApplication([sys.argv[0]])
    lock_proxy(tor.socks_port)
    app.setApplicationName("Veil")
    app.aboutToQuit.connect(tor.stop)
    signal.signal(signal.SIGINT, lambda *_: app.quit())

    extra = frozenset()
    if args.blocklist:
        with open(args.blocklist) as f:
            extra = frozenset(l.strip().lower() for l in f if l.strip() and not l.startswith("#"))
    policy = RequestPolicy(https_only=not args.no_https_only, block_trackers=not args.no_tracker_blocking,
                           extra_trackers=extra)
    win = BrowserWindow(tor, policy, SecurityLevel(args.security), start_url=args.url)
    win.show()
    return app.exec()
