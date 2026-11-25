"""Tor process management and a small, dependency-free control-port client.

Veil either launches its own ``tor`` daemon (the default) or attaches to one
that is already running. All browser traffic goes through Tor's SOCKS port;
the control port is used for bootstrap status, "New Identity", per-site
circuit renewal and showing the circuit a site is using.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from typing import Callable, Optional


class TorError(RuntimeError):
    pass


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# ---------------------------------------------------------------------------
# Control protocol
# ---------------------------------------------------------------------------

_SAFECOOKIE_SERVER_KEY = b"Tor safe cookie authentication server-to-controller hash"
_SAFECOOKIE_CLIENT_KEY = b"Tor safe cookie authentication controller-to-server hash"


def parse_kv(text: str) -> dict[str, str]:
    """Parse ``KEY=VALUE KEY2="quoted value"`` pairs from a reply line."""
    out: dict[str, str] = {}
    for m in re.finditer(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)', text):
        v = m.group(2)
        if v.startswith('"'):
            v = bytes(v[1:-1], "utf-8").decode("unicode_escape")
        out[m.group(1)] = v
    return out


class ControlConnection:
    """One authenticated connection to Tor's control port.

    Replies are returned as a list of ``(status_code, text)`` tuples; multi-line
    data blocks (``250+key=`` ... ``.``) are joined with newlines.
    """

    def __init__(self, host: str, port: int, password: Optional[str] = None,
                 cookie_path: Optional[str] = None, timeout: float = 5.0):
        self._sock = socket.create_connection((host, port), timeout=timeout)
        self._file = self._sock.makefile("rb")
        self._lock = threading.Lock()
        self._authenticate(password, cookie_path)

    # -- low level -------------------------------------------------------
    def _readline(self) -> str:
        line = self._file.readline()
        if not line:
            raise TorError("control connection closed")
        return line.decode("utf-8", "replace").rstrip("\r\n")

    def read_reply(self) -> list[tuple[str, str]]:
        lines: list[tuple[str, str]] = []
        while True:
            line = self._readline()
            if len(line) < 4:
                raise TorError(f"malformed control reply: {line!r}")
            code, sep, rest = line[:3], line[3], line[4:]
            if sep == "+":
                data = [rest]
                while True:
                    dl = self._readline()
                    if dl == ".":
                        break
                    data.append(dl[1:] if dl.startswith("..") else dl)
                lines.append((code, "\n".join(data)))
            else:
                lines.append((code, rest))
            if sep == " ":
                return lines

    def command(self, cmd: str, check: bool = True) -> list[tuple[str, str]]:
        with self._lock:
            self._sock.sendall(cmd.encode() + b"\r\n")
            reply = self.read_reply()
        if check and not reply[-1][0].startswith("2"):
            raise TorError(f"{cmd.split()[0]} failed: {reply[-1][0]} {reply[-1][1]}")
        return reply

    def close(self) -> None:
        try:
            self._sock.close()
        except OSError:
            pass

    # -- auth ------------------------------------------------------------
    def _authenticate(self, password: Optional[str], cookie_path: Optional[str]) -> None:
        info = " ".join(t for _, t in self.command("PROTOCOLINFO 1"))
        methods = set(re.search(r"METHODS=(\S+)", info).group(1).split(",")) \
            if "METHODS=" in info else set()
        m = re.search(r'COOKIEFILE="((?:[^"\\]|\\.)*)"', info)
        cookie_file = cookie_path or (bytes(m.group(1), "utf-8").decode("unicode_escape") if m else None)

        if "NULL" in methods:
            self.command("AUTHENTICATE")
        elif password is not None and "HASHEDPASSWORD" in methods:
            escaped = password.replace("\\", "\\\\").replace('"', '\\"')
            self.command(f'AUTHENTICATE "{escaped}"')
        elif cookie_file and methods & {"SAFECOOKIE", "COOKIE"}:
            with open(cookie_file, "rb") as f:
                cookie = f.read()
            if "SAFECOOKIE" in methods:
                client_nonce = secrets.token_bytes(32)
                reply = self.command(f"AUTHCHALLENGE SAFECOOKIE {client_nonce.hex()}")
                kv = parse_kv(reply[0][1])
                server_nonce = bytes.fromhex(kv["SERVERNONCE"])
                msg = cookie + client_nonce + server_nonce
                expected = hmac.new(_SAFECOOKIE_SERVER_KEY, msg, hashlib.sha256).digest()
                if not hmac.compare_digest(expected, bytes.fromhex(kv["SERVERHASH"])):
                    raise TorError("Tor failed SAFECOOKIE server authentication")
                client_hash = hmac.new(_SAFECOOKIE_CLIENT_KEY, msg, hashlib.sha256).hexdigest()
                self.command(f"AUTHENTICATE {client_hash}")
            else:
                self.command(f"AUTHENTICATE {cookie.hex()}")
        else:
            raise TorError(f"no usable control-port auth method (offered: {sorted(methods)})")

    # -- helpers ---------------------------------------------------------
    def getinfo(self, key: str) -> str:
        for code, text in self.command(f"GETINFO {key}"):
            if text.startswith(key + "="):
                return text[len(key) + 1:].lstrip("\n")
        return ""


# ---------------------------------------------------------------------------
# Circuit model
# ---------------------------------------------------------------------------

@dataclass
class Relay:
    fingerprint: str
    nickname: str
    ip: str = ""
    country: str = ""


@dataclass
class Circuit:
    id: str
    status: str
    relays: list[Relay] = field(default_factory=list)
    purpose: str = ""


def parse_circuit_status(text: str) -> list[Circuit]:
    circuits = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        circ = Circuit(id=parts[0], status=parts[1])
        if len(parts) > 2 and "=" not in parts[2]:
            for hop in parts[2].split(","):
                fp, _, nick = hop.partition("~")
                circ.relays.append(Relay(fingerprint=fp.lstrip("$"), nickname=nick or fp[:9]))
            circ.purpose = parse_kv(" ".join(parts[3:])).get("PURPOSE", "")
        else:
            circ.purpose = parse_kv(" ".join(parts[2:])).get("PURPOSE", "")
        circuits.append(circ)
    return circuits


def parse_stream_event(line: str) -> Optional[tuple[str, str, str, str]]:
    """``STREAM <id> <status> <circ> <host:port> ...`` -> (id, status, circ, host)."""
    parts = line.split()
    if len(parts) < 5 or parts[0] != "STREAM":
        return None
    target = parts[4]
    host = target.rsplit(":", 1)[0] if ":" in target else target
    host = host.strip("[]").lower()
    # Tor appends ".$fingerprint.exit" when it knows the exit; strip that.
    host = re.sub(r"\.\$[0-9A-Fa-f]{40}\.exit$", "", host)
    return parts[1], parts[2], parts[3], host


# ---------------------------------------------------------------------------
# Tor service
# ---------------------------------------------------------------------------

class TorService:
    """Owns (or attaches to) a tor daemon and exposes high-level operations."""

    def __init__(self, tor_path: Optional[str] = None, external: Optional[tuple[int, int]] = None,
                 control_password: Optional[str] = None, torrc_extra: Optional[str] = None,
                 data_dir: Optional[str] = None,
                 on_log: Optional[Callable[[str], None]] = None):
        self.on_log = on_log or (lambda line: None)
        self.log_lines: list[str] = []
        self._password = control_password
        self._proc: Optional[subprocess.Popen] = None
        self._ctl: Optional[ControlConnection] = None
        self._events: Optional[ControlConnection] = None
        self._host_circuits: dict[str, str] = {}
        self._circ_lock = threading.Lock()
        self._owns_data_dir = False
        self.cookie_path: Optional[str] = None

        if external:
            self.socks_port, self.control_port = external
            self.managed = False
            return

        self.managed = True
        self.tor_path = tor_path or shutil.which("tor")
        if not self.tor_path:
            raise TorError("Could not find the 'tor' executable. Install Tor "
                           "(e.g. `apt install tor`, `brew install tor`) or pass --tor-path.")
        if data_dir:
            os.makedirs(data_dir, mode=0o700, exist_ok=True)
            self.data_dir = data_dir
        else:
            self.data_dir = tempfile.mkdtemp(prefix="veil-tor-")
            self._owns_data_dir = True
        self.socks_port = free_port()
        self.control_port = free_port()
        self.cookie_path = os.path.join(self.data_dir, "control_auth_cookie")
        self._torrc_extra = torrc_extra

    # -- lifecycle -------------------------------------------------------
    def _log(self, line: str) -> None:
        self.log_lines.append(line)
        del self.log_lines[:-2000]
        self.on_log(line)

    def torrc(self) -> str:
        lines = [
            f"DataDirectory {self.data_dir}",
            # Every distinct destination host:port gets its own circuit, so
            # unrelated sites can't be correlated by sharing an exit.
            f"SocksPort 127.0.0.1:{self.socks_port} IsolateDestAddr IsolateDestPort",
            f"ControlPort 127.0.0.1:{self.control_port}",
            "CookieAuthentication 1",
            f"CookieAuthFile {self.cookie_path}",
            "AvoidDiskWrites 1",
            "ClientOnly 1",
            "SafeSocks 1",
            "Log notice stdout",
        ]
        if self._torrc_extra:
            lines.append(self._torrc_extra)
        return "\n".join(lines) + "\n"

    def start(self) -> None:
        if not self.managed:
            return
        torrc_path = os.path.join(self.data_dir, "torrc")
        with open(torrc_path, "w") as f:
            f.write(self.torrc())
        self._proc = subprocess.Popen(
            [self.tor_path, "-f", torrc_path, "--ignore-missing-torrc"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
        )
        threading.Thread(target=self._pump_stdout, daemon=True).start()

    def _pump_stdout(self) -> None:
        assert self._proc and self._proc.stdout
        for raw in self._proc.stdout:
            self._log(raw.decode("utf-8", "replace").rstrip())
        self._log("[veil] tor process exited")

    def is_alive(self) -> bool:
        if self.managed:
            return self._proc is not None and self._proc.poll() is None
        return True

    def connect_control(self) -> bool:
        """Try to open the control connections. Returns False if not up yet."""
        if self._ctl:
            return True
        if self.managed and not os.path.exists(self.cookie_path or ""):
            return False
        try:
            self._ctl = ControlConnection("127.0.0.1", self.control_port, self._password, self.cookie_path)
            self._events = ControlConnection("127.0.0.1", self.control_port, self._password, self.cookie_path,
                                             timeout=None)
            if self.managed:
                # Tor exits when this connection closes, so it can't outlive us.
                self._ctl.command("TAKEOWNERSHIP")
            self._events.command("SETEVENTS STREAM")
            threading.Thread(target=self._pump_events, daemon=True).start()
            return True
        except (OSError, TorError) as e:
            self._ctl = self._events = None
            if not self.managed:
                raise TorError(f"Cannot use Tor control port {self.control_port}: {e}") from e
            return False

    def _pump_events(self) -> None:
        conn = self._events
        try:
            while conn is self._events:
                for code, text in conn.read_reply():
                    if code != "650":
                        continue
                    ev = parse_stream_event(text)
                    if ev and ev[1] in ("SENTCONNECT", "SUCCEEDED") and ev[2] != "0":
                        with self._circ_lock:
                            self._host_circuits[ev[3]] = ev[2]
        except (OSError, TorError):
            pass

    def bootstrap_progress(self) -> tuple[int, str]:
        if not self._ctl:
            return 0, "Starting Tor…"
        kv = parse_kv(self._ctl.getinfo("status/bootstrap-phase"))
        return int(kv.get("PROGRESS", 0)), kv.get("SUMMARY", "")

    def stop(self) -> None:
        for c in (self._events, self._ctl):
            if c:
                c.close()
        self._ctl = self._events = None
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(5)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._owns_data_dir:
            shutil.rmtree(self.data_dir, ignore_errors=True)

    # -- features --------------------------------------------------------
    def version(self) -> str:
        return self._ctl.getinfo("version") if self._ctl else "?"

    def new_identity(self) -> None:
        """Mark every circuit dirty and close all open streams."""
        if not self._ctl:
            return
        self._ctl.command("SIGNAL NEWNYM")
        for line in self._ctl.getinfo("stream-status").splitlines():
            sid = line.split()[0] if line.strip() else None
            if sid:
                self._ctl.command(f"CLOSESTREAM {sid} 1", check=False)
        with self._circ_lock:
            self._host_circuits.clear()

    def circuit_for_host(self, host: str) -> Optional[Circuit]:
        if not self._ctl:
            return None
        with self._circ_lock:
            cid = self._host_circuits.get(host.lower())
        if not cid:
            return None
        for circ in parse_circuit_status(self._ctl.getinfo("circuit-status")):
            if circ.id == cid:
                for relay in circ.relays:
                    self._fill_relay(relay)
                return circ
        return None

    def new_circuit_for_host(self, host: str) -> bool:
        """Tear down the circuit serving ``host``; the next request builds a new one."""
        if not self._ctl:
            return False
        with self._circ_lock:
            cid = self._host_circuits.pop(host.lower(), None)
        if not cid:
            return False
        self._ctl.command(f"CLOSECIRCUIT {cid}", check=False)
        return True

    def _fill_relay(self, relay: Relay) -> None:
        try:
            ns = self._ctl.getinfo(f"ns/id/{relay.fingerprint}")
        except TorError:
            return  # bridges / unknown relays have no consensus entry
        for line in ns.splitlines():
            if line.startswith("r "):
                parts = line.split()
                if len(parts) >= 7:
                    relay.nickname, relay.ip = parts[1], parts[6]
        if relay.ip:
            try:
                relay.country = self._ctl.getinfo(f"ip-to-country/{relay.ip}").upper()
            except TorError:
                pass
