import hashlib
import hmac
import os
import socket
import tempfile
import threading
import unittest

from veil.privacy import (
    ONION_SEARCH, RequestPolicy, SecurityLevel, chromium_flags, fingerprint_script, is_tracker,
    normalize_input,
)
from veil.tor import (
    ControlConnection, TorService, _SAFECOOKIE_CLIENT_KEY, _SAFECOOKIE_SERVER_KEY, parse_circuit_status,
    parse_kv, parse_stream_event,
)

ONION = "duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion"


class PolicyTests(unittest.TestCase):
    def test_kill_switch_blocks_network_until_tor_ready(self):
        p = RequestPolicy(tor_ready=False)
        for url in ("https://example.com/", "http://x.org", "wss://a.b/c"):
            self.assertEqual(p.decide(url).action, "block")
        self.assertEqual(p.decide("veil://home").action, "allow")
        self.assertEqual(p.decide("data:text/plain,hi").action, "allow")
        p.tor_ready = True
        self.assertEqual(p.decide("https://example.com/").action, "allow")

    def test_disallowed_schemes(self):
        p = RequestPolicy(tor_ready=True)
        for url in ("file:///etc/passwd", "ftp://example.com/", "chrome://gpu", "smb://host/share"):
            self.assertEqual(p.decide(url).action, "block", url)

    def test_https_upgrade(self):
        p = RequestPolicy(tor_ready=True)
        d = p.decide("http://example.com:80/a?b=1")
        self.assertEqual((d.action, d.url), ("redirect", "https://example.com/a?b=1"))
        self.assertEqual(p.decide("ws://example.com/s").url, "wss://example.com/s")
        self.assertEqual(p.decide("http://example.com:8080/").url, "https://example.com:8080/")

    def test_onion_and_exceptions_stay_http(self):
        p = RequestPolicy(tor_ready=True)
        self.assertEqual(p.decide(f"http://{ONION}/").action, "allow")
        p.http_exceptions.add("legacy.example")
        self.assertEqual(p.decide("http://legacy.example/").action, "allow")
        p.https_only = False
        self.assertEqual(p.decide("http://other.example/").action, "allow")

    def test_trackers(self):
        self.assertTrue(is_tracker("www.google-analytics.com"))
        self.assertTrue(is_tracker("connect.facebook.net"))
        self.assertFalse(is_tracker("example.com"))
        self.assertFalse(is_tracker("notdoubleclick.net"))
        self.assertTrue(is_tracker("x.custom.io", frozenset({"custom.io"})))
        p = RequestPolicy(tor_ready=True)
        self.assertEqual(p.decide("https://stats.g.doubleclick.net/x").action, "block")
        p.block_trackers = False
        self.assertEqual(p.decide("https://stats.g.doubleclick.net/x").action, "allow")


class InputTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(normalize_input("example.com"), "https://example.com")
        self.assertEqual(normalize_input("example.com/path"), "https://example.com/path")
        self.assertEqual(normalize_input(ONION), f"http://{ONION}")
        self.assertEqual(normalize_input("https://a.b/c"), "https://a.b/c")
        self.assertEqual(normalize_input("veil://status"), "veil://status")
        self.assertEqual(normalize_input(""), "veil://home")
        self.assertEqual(normalize_input("how does tor work"), ONION_SEARCH + "?q=how+does+tor+work")
        self.assertTrue(normalize_input("privacy").startswith(ONION_SEARCH))


class LevelTests(unittest.TestCase):
    def test_js_rules(self):
        self.assertTrue(SecurityLevel.STANDARD.allows_js("http://a.com"))
        self.assertTrue(SecurityLevel.SAFER.allows_js("https://a.com"))
        self.assertTrue(SecurityLevel.SAFER.allows_js(f"http://{ONION}/"))
        self.assertFalse(SecurityLevel.SAFER.allows_js("http://a.com"))
        self.assertFalse(SecurityLevel.SAFEST.allows_js("https://a.com"))

    def test_script_config(self):
        self.assertIn('{"strict": false}', fingerprint_script(SecurityLevel.STANDARD))
        self.assertIn('{"strict": true}', fingerprint_script(SecurityLevel.SAFER))
        self.assertNotIn("__CONFIG__", fingerprint_script(SecurityLevel.SAFEST))

    def test_flags_force_proxy_and_remote_dns(self):
        flags = chromium_flags(9999)
        self.assertIn("--proxy-server=socks5://127.0.0.1:9999", flags)
        self.assertTrue(any(f.startswith("--host-resolver-rules=MAP * ~NOTFOUND") for f in flags))
        self.assertTrue(any("disable_non_proxied_udp" in f for f in flags))


class ParserTests(unittest.TestCase):
    def test_parse_kv(self):
        kv = parse_kv('BOOTSTRAP PROGRESS=85 TAG=ap_conn SUMMARY="Connecting to a relay"')
        self.assertEqual(kv["PROGRESS"], "85")
        self.assertEqual(kv["SUMMARY"], "Connecting to a relay")

    def test_circuit_status(self):
        text = ("12 BUILT $AAAA~guard1,$BBBB~mid2,$CCCC~exit3 BUILD_FLAGS=NEED_CAPACITY PURPOSE=GENERAL\n"
                "13 LAUNCHED PURPOSE=GENERAL")
        circs = parse_circuit_status(text)
        self.assertEqual(len(circs), 2)
        self.assertEqual([r.nickname for r in circs[0].relays], ["guard1", "mid2", "exit3"])
        self.assertEqual(circs[0].relays[0].fingerprint, "AAAA")
        self.assertEqual(circs[0].purpose, "GENERAL")
        self.assertEqual(circs[1].relays, [])

    def test_stream_event(self):
        self.assertEqual(parse_stream_event("STREAM 54 SUCCEEDED 12 example.com:443"),
                         ("54", "SUCCEEDED", "12", "example.com"))
        self.assertEqual(parse_stream_event(f"STREAM 1 SENTCONNECT 3 {'A' * 0}Example.COM.$"
                                            f"{'F' * 40}.exit:443")[3], "example.com")
        self.assertIsNone(parse_stream_event("CIRC 1 BUILT"))

    def test_torrc_isolation(self):
        with tempfile.TemporaryDirectory() as d:
            t = TorService(tor_path="/bin/true", data_dir=d, torrc_extra="UseBridges 1")
            rc = t.torrc()
            self.assertIn(f"SocksPort 127.0.0.1:{t.socks_port} IsolateDestAddr IsolateDestPort", rc)
            self.assertIn("UseBridges 1", rc)
            self.assertIn("CookieAuthentication 1", rc)


class FakeTor(threading.Thread):
    """Minimal control-port server speaking enough of the protocol for the client."""

    def __init__(self, cookie_path, cookie):
        super().__init__(daemon=True)
        self.srv = socket.socket()
        self.srv.bind(("127.0.0.1", 0))
        self.srv.listen(1)
        self.port = self.srv.getsockname()[1]
        self.cookie_path, self.cookie = cookie_path, cookie
        self.commands = []

    def run(self):
        conn, _ = self.srv.accept()
        f = conn.makefile("rb")
        server_nonce = os.urandom(32)
        client_nonce = b""
        for raw in f:
            line = raw.decode().strip()
            self.commands.append(line)
            send = lambda s: conn.sendall(s.encode())
            if line.startswith("PROTOCOLINFO"):
                send('250-PROTOCOLINFO 1\r\n250-AUTH METHODS=COOKIE,SAFECOOKIE '
                     f'COOKIEFILE="{self.cookie_path}"\r\n250-VERSION Tor="0.4.8.0"\r\n250 OK\r\n')
            elif line.startswith("AUTHCHALLENGE"):
                client_nonce = bytes.fromhex(line.split()[2])
                sh = hmac.new(_SAFECOOKIE_SERVER_KEY, self.cookie + client_nonce + server_nonce,
                              hashlib.sha256).hexdigest()
                send(f"250 AUTHCHALLENGE SERVERHASH={sh} SERVERNONCE={server_nonce.hex()}\r\n")
            elif line.startswith("AUTHENTICATE"):
                expected = hmac.new(_SAFECOOKIE_CLIENT_KEY, self.cookie + client_nonce + server_nonce,
                                    hashlib.sha256).hexdigest()
                send("250 OK\r\n" if line.split()[1] == expected else "515 Bad authentication\r\n")
            elif line == "GETINFO circuit-status":
                send("250+circuit-status=\r\n7 BUILT $AA~a,$BB~b,$CC~c PURPOSE=GENERAL\r\n.\r\n250 OK\r\n")
            elif line == "GETINFO status/bootstrap-phase":
                send('250-status/bootstrap-phase=NOTICE BOOTSTRAP PROGRESS=100 TAG=done SUMMARY="Done"\r\n'
                     "250 OK\r\n")
            else:
                send("510 Unrecognized command\r\n")


class ControlTests(unittest.TestCase):
    def test_safecookie_auth_and_getinfo(self):
        with tempfile.TemporaryDirectory() as d:
            cookie = os.urandom(32)
            path = os.path.join(d, "cookie")
            with open(path, "wb") as f:
                f.write(cookie)
            fake = FakeTor(path, cookie)
            fake.start()
            c = ControlConnection("127.0.0.1", fake.port)
            self.assertIn("AUTHENTICATE", fake.commands[-1])
            self.assertEqual(parse_kv(c.getinfo("status/bootstrap-phase"))["PROGRESS"], "100")
            circs = parse_circuit_status(c.getinfo("circuit-status"))
            self.assertEqual([r.nickname for r in circs[0].relays], ["a", "b", "c"])
            with self.assertRaises(Exception):
                c.command("BOGUS")
            c.close()


if __name__ == "__main__":
    unittest.main()
