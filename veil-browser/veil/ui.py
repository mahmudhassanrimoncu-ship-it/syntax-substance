"""Browser window, tabs and the Qt WebEngine glue for the privacy policy."""

from __future__ import annotations

import os
from typing import Optional
from urllib.parse import parse_qs, quote, urlsplit

from PyQt6.QtCore import QBuffer, QByteArray, QIODevice, QObject, QSize, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import QAction, QKeySequence
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QMainWindow, QMenu, QMessageBox, QPlainTextEdit, QProgressBar, QTabWidget, QToolBar, QToolButton,
    QVBoxLayout, QWidget,
)
from PyQt6.QtWebEngineCore import (
    QWebEngineLoadingInfo, QWebEnginePage, QWebEngineProfile, QWebEngineScript, QWebEngineSettings,
    QWebEngineUrlRequestInfo, QWebEngineUrlRequestInterceptor, QWebEngineUrlRequestJob,
    QWebEngineUrlSchemeHandler, qWebEngineChromiumVersion,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView

from . import pages
from .privacy import RequestPolicy, SecurityLevel, fingerprint_script, is_onion, normalize_input, user_agent
from .tor import Circuit, TorError, TorService

A = QWebEngineSettings.WebAttribute
ERR_ABORTED = -3
ERR_BLOCKED_BY_CLIENT = -20


# ---------------------------------------------------------------------------
# Engine glue
# ---------------------------------------------------------------------------

class Interceptor(QWebEngineUrlRequestInterceptor):
    def __init__(self, policy: RequestPolicy, engine: "PrivacyEngine"):
        super().__init__(engine)
        self.policy = policy
        self.engine = engine
        self.upgraded_hosts: set[str] = set()

    def interceptRequest(self, info: QWebEngineUrlRequestInfo) -> None:
        url = info.requestUrl().toString()
        decision = self.policy.decide(url)
        if decision.action == "block":
            info.block(True)
            if decision.reason == "tracker":
                self.engine.tracker_blocked.emit(info.firstPartyUrl().host())
        elif decision.action == "redirect":
            self.upgraded_hosts.add(info.requestUrl().host().lower())
            info.redirect(QUrl(decision.url))


class SchemeHandler(QWebEngineUrlSchemeHandler):
    """Serves veil://home, veil://status, ... from memory."""

    def __init__(self, window: "BrowserWindow"):
        super().__init__(window)
        self.window = window

    def requestStarted(self, job: QWebEngineUrlRequestJob) -> None:
        url = job.requestUrl()
        query = parse_qs(url.query())
        name = url.host()
        if name == "home":
            html = pages.home()
        elif name == "status":
            html = pages.status(self.window.status_rows())
        elif name == "https-failed":
            target = query.get("url", [""])[0]
            html = pages.https_failed(target, "veil://allow-http?url=" + quote(target, safe=""))
        elif name == "blocked":
            html = pages.blocked(query.get("reason", ["Blocked"])[0])
        else:
            job.fail(QWebEngineUrlRequestJob.Error.UrlNotFound)
            return
        buf = QBuffer(job)
        buf.setData(QByteArray(html.encode()))
        buf.open(QIODevice.OpenModeFlag.ReadOnly)
        job.reply(b"text/html", buf)


class PrivacyEngine(QObject):
    """Builds amnesic, hardened WebEngine profiles."""

    tracker_blocked = pyqtSignal(str)

    def __init__(self, window: "BrowserWindow", policy: RequestPolicy, level: SecurityLevel):
        super().__init__(window)
        self.window = window
        self.policy = policy
        self.level = level
        self.chromium = qWebEngineChromiumVersion()
        self.interceptor = Interceptor(policy, self)
        self.scheme_handler = SchemeHandler(window)
        self.profile: Optional[QWebEngineProfile] = None

    def new_profile(self) -> QWebEngineProfile:
        old = self.profile
        # No storage name => off-the-record: cookies, cache, storage live in RAM only.
        p = QWebEngineProfile(self)
        p.setHttpUserAgent(user_agent(self.chromium))
        p.setHttpAcceptLanguage("en-US,en;q=0.9")
        p.setHttpCacheType(QWebEngineProfile.HttpCacheType.MemoryHttpCache)
        p.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.NoPersistentCookies)
        p.setPersistentPermissionsPolicy(QWebEngineProfile.PersistentPermissionsPolicy.AskEveryTime)
        p.setSpellCheckEnabled(False)
        major = self.chromium.split(".")[0]
        ch = p.clientHints()  # keep client hints consistent with the user agent
        ch.setPlatform("Windows"); ch.setPlatformVersion("10.0.0"); ch.setArch("x86")
        ch.setBitness("64"); ch.setModel(""); ch.setIsMobile(False); ch.setIsWow64(False)
        ch.setFullVersion(f"{major}.0.0.0")
        p.setUrlRequestInterceptor(self.interceptor)
        p.installUrlSchemeHandler(b"veil", self.scheme_handler)
        p.cookieStore().setCookieFilter(lambda req: not req.thirdParty)
        p.downloadRequested.connect(self.window.on_download)
        self.profile = p
        self.apply_level(self.level)
        if old is not None:
            old.deleteLater()
        return p

    def apply_level(self, level: SecurityLevel) -> None:
        self.level = level
        p = self.profile
        s = p.settings()
        for attr, value in [
            (A.JavascriptEnabled, level is not SecurityLevel.SAFEST),
            (A.JavascriptCanOpenWindows, False),
            (A.JavascriptCanAccessClipboard, False),
            (A.JavascriptCanPaste, False),
            (A.AllowWindowActivationFromJavaScript, False),
            (A.WebGLEnabled, level.webgl),
            (A.ReadingFromCanvasEnabled, level is not SecurityLevel.SAFEST),
            (A.PlaybackRequiresUserGesture, level is not SecurityLevel.STANDARD),
            (A.LocalContentCanAccessRemoteUrls, False),
            (A.LocalContentCanAccessFileUrls, False),
            (A.AllowRunningInsecureContent, False),
            (A.AllowGeolocationOnInsecureOrigins, False),
            (A.HyperlinkAuditingEnabled, False),
            (A.DnsPrefetchEnabled, False),
            (A.ScreenCaptureEnabled, False),
            (A.FullScreenSupportEnabled, False),
            (A.WebRTCPublicInterfacesOnly, True),
            (A.PluginsEnabled, False),
            (A.PdfViewerEnabled, True),   # real Chrome has it; removing it is itself a fingerprint
            (A.TouchIconsEnabled, False),
            (A.LocalStorageEnabled, True),  # in memory only (off-the-record)
            (A.NavigateOnDropEnabled, False),
            (A.XSSAuditingEnabled, True),
        ]:
            s.setAttribute(attr, value)
        scripts = p.scripts()
        scripts.clear()
        script = QWebEngineScript()
        script.setName("veil-fingerprint")
        script.setSourceCode(fingerprint_script(level))
        script.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        script.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
        script.setRunsOnSubFrames(True)
        scripts.insert(script)


class VeilPage(QWebEnginePage):
    def __init__(self, profile: QWebEngineProfile, window: "BrowserWindow", parent: QObject):
        super().__init__(profile, parent)
        self.window = window
        self.permissionRequested.connect(lambda perm: perm.deny())
        self.fullScreenRequested.connect(lambda req: req.reject())
        self.loadingChanged.connect(self._on_loading)

    def acceptNavigationRequest(self, url: QUrl, nav_type, is_main_frame: bool) -> bool:
        if url.scheme() == "veil" and url.host() == "allow-http":
            target = parse_qs(url.query()).get("url", [""])[0]
            host = (urlsplit(target).hostname or "").lower()
            if host:
                self.window.policy.http_exceptions.add(host)
                QTimer.singleShot(0, lambda: self.setUrl(QUrl(target)))
            return False
        if is_main_frame:
            level = self.window.engine.level
            self.settings().setAttribute(A.JavascriptEnabled, level.allows_js(url.toString()))
        return super().acceptNavigationRequest(url, nav_type, is_main_frame)

    def _on_loading(self, info: QWebEngineLoadingInfo) -> None:
        if info.status() != QWebEngineLoadingInfo.LoadStatus.LoadFailedStatus:
            return
        url = info.url()
        if info.errorCode() == ERR_BLOCKED_BY_CLIENT and not self.window.policy.tor_ready:
            self.setUrl(QUrl("veil://blocked?reason=" + quote("Tor is not connected yet.")))
        elif (info.errorCode() != ERR_ABORTED and url.scheme() == "https"
              and url.host().lower() in self.window.engine.interceptor.upgraded_hosts
              and self.window.policy.https_only):
            http = QUrl(url)
            http.setScheme("http")
            self.setUrl(QUrl("veil://https-failed?url=" + quote(http.toString(), safe="")))

    def createWindow(self, _type):
        return self.window.add_tab().page()


class Letterbox(QWidget):
    """Centers the web view at a size rounded down to 200x100 steps (like Tor Browser),
    so the viewport size reported to sites falls into a few common buckets."""

    def __init__(self, view: QWebEngineView):
        super().__init__()
        self.view = view
        view.setParent(self)
        self.setAutoFillBackground(True)
        self.setStyleSheet("background:#3b3549;")

    def resizeEvent(self, ev):
        w, h = self.width(), self.height()
        vw = max(min(w, 200), (w // 200) * 200)
        vh = max(min(h, 100), (h // 100) * 100)
        self.view.setGeometry((w - vw) // 2, (h - vh) // 2, vw, vh)
        super().resizeEvent(ev)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class BrowserWindow(QMainWindow):
    def __init__(self, tor: TorService, policy: RequestPolicy, level: SecurityLevel,
                 start_url: Optional[str] = None):
        super().__init__()
        self.tor = tor
        self.policy = policy
        self.engine = PrivacyEngine(self, policy, level)
        self.engine.tracker_blocked.connect(self._on_tracker)
        self.blocked_count = 0
        self._download_warned = False
        self._start_url = start_url
        self._was_ready = False

        self.setWindowTitle("Veil")
        self.tabs = QTabWidget(documentMode=True, tabsClosable=True, movable=True)
        self.tabs.tabCloseRequested.connect(self.close_tab)
        self.tabs.currentChanged.connect(self._sync_url_bar)
        plus = QToolButton(text="+", autoRaise=True)
        plus.clicked.connect(lambda: self.add_tab("veil://home"))
        self.tabs.setCornerWidget(plus, Qt.Corner.TopRightCorner)
        self.setCentralWidget(self.tabs)

        self._build_toolbar()
        self._build_statusbar()
        self.engine.new_profile()
        self.add_tab("veil://home")

        self.resize(1016, 930)
        self.timer = QTimer(self, interval=500, timeout=self._poll_tor)
        self.timer.start()

    # -- chrome ----------------------------------------------------------
    def _act(self, text, slot, shortcut=None, tip=None) -> QAction:
        a = QAction(text, self)
        a.triggered.connect(slot)
        if shortcut:
            a.setShortcuts([QKeySequence(s) for s in ([shortcut] if isinstance(shortcut, str) else shortcut)])
        if tip:
            a.setToolTip(tip)
        self.addAction(a)
        return a

    def _build_toolbar(self) -> None:
        tb = QToolBar(movable=False)
        tb.setIconSize(QSize(18, 18))
        self.addToolBar(tb)
        tb.addAction(self._act("←", lambda: self.view() and self.view().back(), "Alt+Left", "Back"))
        tb.addAction(self._act("→", lambda: self.view() and self.view().forward(), "Alt+Right", "Forward"))
        tb.addAction(self._act("⟳", lambda: self.view() and self.view().reload(), ["Ctrl+R", "F5"], "Reload"))

        self.lock = QLabel(" ")
        self.lock.setMinimumWidth(26)
        self.lock.setAlignment(Qt.AlignmentFlag.AlignCenter)
        tb.addWidget(self.lock)
        self.url_bar = QLineEdit(placeholderText="Search or enter address")
        self.url_bar.returnPressed.connect(lambda: self.navigate(self.url_bar.text()))
        tb.addWidget(self.url_bar)
        self._act("Focus address bar", lambda: (self.url_bar.setFocus(), self.url_bar.selectAll()), "Ctrl+L")

        tb.addAction(self._act("🧅", self.show_circuit, None, "Show the Tor circuit for this site"))
        tb.addAction(self._act("🧹", self.new_identity, "Ctrl+Shift+U",
                               "New Identity: close all tabs, forget everything, use new circuits"))

        self.level_box = QComboBox()
        for lvl in SecurityLevel:
            self.level_box.addItem("🛡 " + lvl.label, lvl)
            self.level_box.setItemData(self.level_box.count() - 1, lvl.description, Qt.ItemDataRole.ToolTipRole)
        self.level_box.setCurrentIndex(list(SecurityLevel).index(self.engine.level))
        self.level_box.currentIndexChanged.connect(self._on_level)
        tb.addWidget(self.level_box)

        menu = QMenu(self)
        menu.addAction(self._act("New tab", lambda: self.add_tab("veil://home"), "Ctrl+T"))
        menu.addAction(self._act("Close tab", lambda: self.close_tab(self.tabs.currentIndex()), "Ctrl+W"))
        menu.addSeparator()
        menu.addAction(self._act("New Identity", self.new_identity))
        menu.addAction(self._act("New Tor circuit for this site", self.new_circuit, "Ctrl+Shift+L"))
        menu.addSeparator()
        self.https_action = self._act("HTTPS-only mode", self._toggle_https)
        self.https_action.setCheckable(True)
        self.https_action.setChecked(self.policy.https_only)
        menu.addAction(self.https_action)
        self.tracker_action = self._act("Block trackers", self._toggle_trackers)
        self.tracker_action.setCheckable(True)
        self.tracker_action.setChecked(self.policy.block_trackers)
        menu.addAction(self.tracker_action)
        menu.addSeparator()
        menu.addAction(self._act("Privacy status", lambda: self.add_tab("veil://status")))
        menu.addAction(self._act("Tor log", self.show_tor_log))
        menu.addSeparator()
        menu.addAction(self._act("Quit", self.close, "Ctrl+Q"))
        btn = QToolButton(text="☰", popupMode=QToolButton.ToolButtonPopupMode.InstantPopup)
        btn.setMenu(menu)
        tb.addWidget(btn)

    def _build_statusbar(self) -> None:
        sb = self.statusBar()
        self.tor_label = QLabel("Starting Tor…")
        self.tor_progress = QProgressBar(maximum=100, textVisible=False, maximumWidth=160, maximumHeight=10)
        self.tracker_label = QLabel("")
        sb.addWidget(self.tor_label)
        sb.addWidget(self.tor_progress)
        sb.addPermanentWidget(self.tracker_label)

    # -- tabs ------------------------------------------------------------
    def view(self) -> Optional[QWebEngineView]:
        w = self.tabs.currentWidget()
        return w.view if w else None

    def add_tab(self, url: Optional[str] = None) -> QWebEngineView:
        view = QWebEngineView()
        page = VeilPage(self.engine.profile, self, view)
        view.setPage(page)
        box = Letterbox(view)
        idx = self.tabs.addTab(box, "New tab")
        self.tabs.setCurrentIndex(idx)
        page.titleChanged.connect(lambda t, b=box: self._set_title(b, t))
        page.urlChanged.connect(lambda _u, b=box: b is self.tabs.currentWidget() and self._sync_url_bar())
        if url:
            view.setUrl(QUrl(url))
        if url == "veil://home":
            self.url_bar.setFocus()
        return view

    def _set_title(self, box, title):
        i = self.tabs.indexOf(box)
        if i >= 0:
            self.tabs.setTabText(i, (title or "New tab")[:28])
            self.tabs.setTabToolTip(i, title)

    def close_tab(self, index: int) -> None:
        if index < 0:
            return
        box = self.tabs.widget(index)
        self.tabs.removeTab(index)
        box.view.page().deleteLater()
        box.deleteLater()
        if self.tabs.count() == 0:
            self.add_tab("veil://home")

    def navigate(self, text: str) -> None:
        url = normalize_input(text)
        if not self.policy.tor_ready and urlsplit(url).scheme in ("http", "https"):
            url = "veil://blocked?reason=" + quote("Tor is still connecting. Try again in a moment.")
        self.view().setUrl(QUrl(url))
        self.view().setFocus()

    def _sync_url_bar(self, *_):
        v = self.view()
        if not v:
            return
        url = v.url()
        if url.scheme() == "veil" and url.host() == "home":
            self.url_bar.clear()
        else:
            self.url_bar.setText(url.toString())
            self.url_bar.setCursorPosition(0)
        if is_onion(url.host()):
            self.lock.setText("🧅"); self.lock.setToolTip("Onion service: end-to-end encrypted inside Tor")
        elif url.scheme() == "https":
            self.lock.setText("🔒"); self.lock.setToolTip("HTTPS: encrypted to the site")
        elif url.scheme() == "http":
            self.lock.setText("⚠️"); self.lock.setToolTip("Not encrypted: the Tor exit relay can see this traffic")
        else:
            self.lock.setText("◆"); self.lock.setToolTip("Veil internal page")

    # -- Tor status ------------------------------------------------------
    def _poll_tor(self) -> None:
        try:
            if not self.tor.is_alive():
                raise TorError("Tor process stopped")
            if not self.tor.connect_control():
                self.tor_label.setText("Starting Tor…")
                return
            progress, summary = self.tor.bootstrap_progress()
        except (TorError, OSError) as e:
            self._set_ready(False)
            self.tor_label.setText(f"⛔ Tor unavailable: {e}. All traffic is blocked.")
            self.tor_progress.hide()
            return
        self.tor_progress.setValue(progress)
        if progress >= 100:
            self._set_ready(True)
        else:
            self._set_ready(False)
            self.tor_label.setText(f"Connecting to Tor… {progress}% {summary}")

    def _set_ready(self, ready: bool) -> None:
        self.policy.tor_ready = ready
        if ready and not self._was_ready:
            self.tor_label.setText("🧅 Connected to the Tor network")
            self.tor_progress.hide()
            self.timer.setInterval(3000)
            if self._start_url:
                self.navigate(self._start_url)
                self._start_url = None
        elif not ready and self._was_ready:
            self.tor_progress.show()
            self.timer.setInterval(500)
        self._was_ready = ready

    def status_rows(self) -> list[tuple[str, str]]:
        try:
            version = self.tor.version()
        except TorError:
            version = "?"
        return [
            ("Tor", ("connected" if self.policy.tor_ready else "NOT connected — traffic blocked")),
            ("Tor version", version),
            ("Tor daemon", "managed by Veil" if self.tor.managed else "external"),
            ("SOCKS proxy", f"127.0.0.1:{self.tor.socks_port} (remote DNS, per-site circuits)"),
            ("Security level", f"{self.engine.level.label} — {self.engine.level.description}"),
            ("HTTPS-only", "on" if self.policy.https_only else "off"),
            ("Tracker blocking", "on" if self.policy.block_trackers else "off"),
            ("HTTP exceptions", ", ".join(sorted(self.policy.http_exceptions)) or "none"),
            ("Storage", "memory only (off-the-record); wiped on New Identity and exit"),
            ("Third-party cookies", "blocked"),
            ("User agent", self.engine.profile.httpUserAgent()),
            ("Time zone", os.environ.get("TZ", "?")),
            ("WebRTC", "proxied only (no UDP → no IP leak)"),
            ("Engine", f"Chromium {self.engine.chromium}"),
        ]

    # -- privacy actions -------------------------------------------------
    def current_host(self) -> str:
        v = self.view()
        return v.url().host().lower() if v else ""

    def new_identity(self) -> None:
        if QMessageBox.question(
                self, "New Identity",
                "Close all tabs, erase cookies, cache, history and site data, and use new Tor circuits?"
        ) != QMessageBox.StandardButton.Yes:
            return
        while self.tabs.count():
            box = self.tabs.widget(0)
            self.tabs.removeTab(0)
            box.view.page().deleteLater()
            box.deleteLater()
        self.policy.http_exceptions.clear()
        self.engine.interceptor.upgraded_hosts.clear()
        self.blocked_count = 0
        self.tracker_label.clear()
        try:
            self.tor.new_identity()
        except TorError as e:
            self.statusBar().showMessage(f"Tor NEWNYM failed: {e}", 5000)
        self.engine.new_profile()
        self.add_tab("veil://home")
        self.statusBar().showMessage("New identity: everything was cleared", 4000)

    def new_circuit(self) -> None:
        host = self.current_host()
        if not host or self.view().url().scheme() == "veil":
            return
        try:
            done = self.tor.new_circuit_for_host(host)
        except TorError:
            done = False
        self.statusBar().showMessage(f"New circuit for {host}" if done else
                                     "No active circuit for this site yet", 4000)
        self.view().reload()

    def show_circuit(self) -> None:
        host = self.current_host()
        circ: Optional[Circuit] = None
        if host and self.view().url().scheme() != "veil":
            try:
                circ = self.tor.circuit_for_host(host)
            except TorError:
                pass
        if not circ:
            text = "No Tor circuit is in use for this page yet." if host else "Internal page: no network."
        else:
            hops = ["This browser"]
            names = ["Guard", "Middle", "Middle", "Middle"]
            for i, r in enumerate(circ.relays):
                role = "Exit" if i == len(circ.relays) - 1 and not is_onion(host) else \
                       ("Rendezvous" if i == len(circ.relays) - 1 else names[min(i, 3)])
                where = f" ({r.country})" if r.country else ""
                ip = f" {r.ip}" if r.ip else ""
                hops.append(f"{role}: {r.nickname}{where}{ip}")
            if is_onion(host):
                hops += ["  ⋯ 3 relays chosen by the onion service ⋯", f"Onion service: {host}"]
            else:
                hops.append(host)
            text = "\n   ↓\n".join(hops)
        QMessageBox.information(self, f"Tor circuit — {host or 'Veil'}",
                                text + "\n\nUse “New Tor circuit for this site” (Ctrl+Shift+L) to change it.")

    def _on_level(self, _i) -> None:
        level = self.level_box.currentData()
        self.engine.apply_level(level)
        for i in range(self.tabs.count()):
            self.tabs.widget(i).view.reload()
        self.statusBar().showMessage(f"Security level: {level.label}. {level.description}", 6000)

    def _toggle_https(self, on: bool) -> None:
        self.policy.https_only = on

    def _toggle_trackers(self, on: bool) -> None:
        self.policy.block_trackers = on

    def _on_tracker(self, _host: str) -> None:
        self.blocked_count += 1
        self.tracker_label.setText(f"🛡 {self.blocked_count} trackers blocked")

    def show_tor_log(self) -> None:
        dlg = QDialog(self)
        dlg.setWindowTitle("Tor log")
        lay = QVBoxLayout(dlg)
        log = QPlainTextEdit(readOnly=True)
        log.setPlainText("\n".join(self.tor.log_lines) or "(no log output — external Tor)")
        log.moveCursor(log.textCursor().MoveOperation.End)
        lay.addWidget(log)
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        bb.rejected.connect(dlg.reject)
        lay.addWidget(bb)
        dlg.resize(760, 460)
        dlg.exec()

    def on_download(self, req) -> None:
        if not self._download_warned:
            self._download_warned = True
            QMessageBox.warning(
                self, "Downloads",
                "Some files (documents, media, PDFs) can connect to the internet when opened in other "
                "apps, revealing your real IP address. Open downloaded files while offline, or inside Tails/Whonix.")
        path, _ = QFileDialog.getSaveFileName(self, "Save file",
                                              os.path.join(req.downloadDirectory(), req.downloadFileName()))
        if not path:
            req.cancel()
            return
        req.setDownloadDirectory(os.path.dirname(path))
        req.setDownloadFileName(os.path.basename(path))
        req.isFinishedChanged.connect(
            lambda: self.statusBar().showMessage(f"Downloaded {os.path.basename(path)}", 5000))
        req.accept()

    def closeEvent(self, ev) -> None:
        self.timer.stop()
        while self.tabs.count():
            box = self.tabs.widget(0)
            self.tabs.removeTab(0)
            box.view.page().deleteLater()
            box.deleteLater()
        super().closeEvent(ev)
