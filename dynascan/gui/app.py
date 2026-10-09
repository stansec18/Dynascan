"""Dynascan desktop application (PySide6)."""
from __future__ import annotations

import sys
import webbrowser
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QFileDialog, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
    QLineEdit, QMainWindow, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QSpinBox,
    QSplitter, QTableWidget, QTableWidgetItem, QTabWidget, QTextBrowser, QVBoxLayout, QWidget,
    QStackedWidget, QAbstractItemView, QScrollArea, QFrame,
)

from .. import __version__
from ..config import ScanConfig
from ..models import ScanResult
from ..owasp import API_TOP10, WEB_TOP10, coverage
from ..report import write_reports
from .worker import ScanWorker

SEV_COLOR = {"critical": "#7f1d1d", "high": "#dc2626", "medium": "#d97706", "low": "#2563eb", "info": "#6b7280"}


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"Dynascan {__version__}")
        self.resize(1100, 720)
        self.setMinimumSize(720, 480)
        self.worker: ScanWorker | None = None
        self.result: ScanResult | None = None
        self.cfg_used: ScanConfig | None = None

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.tabs.addTab(self._build_setup(), "1. Scan setup")
        self.tabs.addTab(self._build_progress(), "2. Progress")
        self.tabs.addTab(self._build_results(), "3. Results")
        self.tabs.addTab(self._build_threats(), "4. Threat model")
        self.statusBar().showMessage("Ready. Only scan systems you are authorised to test.")

    # ------------------------------------------------------------------ setup tab
    def _build_setup(self) -> QWidget:
        # Outer page = scrollable form + a footer (authorisation + Start) that is always visible,
        # so the Start button can never be pushed off-screen on small displays.
        page = QWidget()
        page_lay = QVBoxLayout(page)
        page_lay.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        page_lay.addWidget(scroll, 1)

        w = QWidget()
        scroll.setWidget(w)
        lay = QVBoxLayout(w)

        tgt = QGroupBox("Target")
        f = QFormLayout(tgt)
        self.target = QLineEdit()
        self.target.setPlaceholderText("https://app.example.com")
        self.openapi = QLineEdit()
        self.openapi.setPlaceholderText("Optional: OpenAPI/Swagger file path or URL for API scanning")
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._pick_openapi)
        row = QHBoxLayout()
        row.addWidget(self.openapi)
        row.addWidget(browse)
        f.addRow("Base URL", self.target)
        f.addRow("OpenAPI spec", row)
        self.hosts = QLineEdit()
        self.hosts.setPlaceholderText("Optional extra in-scope hosts, comma separated (wildcards allowed: *.example.com)")
        f.addRow("Extra hosts", self.hosts)
        self.exclude = QLineEdit()
        self.exclude.setPlaceholderText("Optional regexes for paths to never request, comma separated (e.g. /logout,/delete)")
        f.addRow("Exclude paths", self.exclude)
        lay.addWidget(tgt)

        mode = QGroupBox("Scan mode")
        mf = QFormLayout(mode)
        self.mode = QComboBox()
        self.mode.addItems(["Unauthenticated", "Authenticated"])
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self.passive = QCheckBox("Passive only (send no attack payloads)")
        mf.addRow("Mode", self.mode)
        mf.addRow("", self.passive)
        lay.addWidget(mode)

        self.auth_box = QGroupBox("Credentials")
        af = QFormLayout(self.auth_box)
        self.auth_type = QComboBox()
        self.auth_type.addItems(["Form login", "Token login (JSON)", "Bearer token / JWT", "API key header", "Custom headers / cookies"])
        self.auth_type.currentIndexChanged.connect(self._auth_changed)
        af.addRow("Method", self.auth_type)
        self.stack = QStackedWidget()
        af.addRow(self.stack)
        # 0 form, 1 token login (share username/password page)
        self.login_url = QLineEdit()
        self.login_url.setPlaceholderText("/login")
        self.username = QLineEdit()
        self.password = QLineEdit()
        self.password.setEchoMode(QLineEdit.Password)
        self.user_field = QLineEdit("username")
        self.pass_field = QLineEdit("password")
        self.success = QLineEdit()
        self.success.setPlaceholderText("Text shown only when logged in (recommended)")
        self.token_path = QLineEdit("token")
        p0 = QWidget()
        f0 = QFormLayout(p0)
        for label, wdg in [("Login URL", self.login_url), ("Username", self.username), ("Password", self.password),
                           ("Username field", self.user_field), ("Password field", self.pass_field),
                           ("Success indicator", self.success), ("Token JSON path", self.token_path)]:
            f0.addRow(label, wdg)
        self.stack.addWidget(p0)
        self.token = QLineEdit()
        self.token.setEchoMode(QLineEdit.Password)
        self.api_header = QLineEdit("X-API-Key")
        p1 = QWidget()
        f1 = QFormLayout(p1)
        f1.addRow("Token / key", self.token)
        f1.addRow("Header name (API key)", self.api_header)
        self.stack.addWidget(p1)
        self.custom = QPlainTextEdit()
        self.custom.setPlaceholderText("One per line:\nHeader-Name: value\ncookie:session=abc123")
        self.custom.setFixedHeight(90)
        self.stack.addWidget(self.custom)
        lay.addWidget(self.auth_box)
        self.auth_box.setEnabled(False)

        tune = QGroupBox("Tuning")
        tf = QFormLayout(tune)
        self.rate = QSpinBox()
        self.rate.setRange(1, 200)
        self.rate.setValue(15)
        self.pages = QSpinBox()
        self.pages.setRange(1, 2000)
        self.pages.setValue(150)
        self.insecure = QCheckBox("Ignore TLS certificate errors")
        self.proxy = QLineEdit()
        self.proxy.setPlaceholderText("Optional proxy, e.g. http://127.0.0.1:8080")
        tf.addRow("Requests / second", self.rate)
        tf.addRow("Max pages to crawl", self.pages)
        tf.addRow("", self.insecure)
        tf.addRow("Proxy", self.proxy)
        lay.addWidget(tune)

        lay.addStretch(1)

        # ---- pinned footer
        footer = QWidget()
        fl = QVBoxLayout(footer)
        fl.setContentsMargins(12, 6, 12, 10)
        self.authorized = QCheckBox("I confirm I am authorised to security-test this target")
        self.start_btn = QPushButton("Start scan")
        self.start_btn.setStyleSheet("padding:10px;font-weight:600;")
        self.start_btn.clicked.connect(self._start)
        fl.addWidget(self.authorized)
        fl.addWidget(self.start_btn)
        page_lay.addWidget(footer)

        self._auth_changed(0)
        return page

    def _pick_openapi(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Choose OpenAPI/Swagger file", "", "API specs (*.json *.yaml *.yml)")
        if path:
            self.openapi.setText(path)

    def _mode_changed(self, idx: int) -> None:
        self.auth_box.setEnabled(idx == 1)

    def _auth_changed(self, idx: int) -> None:
        self.stack.setCurrentIndex({0: 0, 1: 0, 2: 1, 3: 1, 4: 2}[idx])

    # ------------------------------------------------------------------ progress tab
    def _build_progress(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.bar = QProgressBar()
        self.bar.setRange(0, 1000)
        self.stage = QLabel("Idle")
        self.log = QPlainTextEdit()
        self.log.setReadOnly(True)
        self.stop_btn = QPushButton("Stop scan")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._stop)
        lay.addWidget(self.stage)
        lay.addWidget(self.bar)
        lay.addWidget(self.log, 1)
        lay.addWidget(self.stop_btn)
        return w

    # ------------------------------------------------------------------ results tab
    def _build_results(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.summary = QLabel("No scan yet.")
        lay.addWidget(self.summary)
        split = QSplitter(Qt.Vertical)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["Severity", "Title", "URL", "OWASP Web", "OWASP API"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(1, 330)
        self.table.setColumnWidth(2, 330)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.itemSelectionChanged.connect(self._show_detail)
        self.detail = QTextBrowser()
        self.detail.setOpenExternalLinks(True)
        split.addWidget(self.table)
        split.addWidget(self.detail)
        split.setSizes([360, 260])
        lay.addWidget(split, 1)
        row = QHBoxLayout()
        self.export_btn = QPushButton("Export reports…")
        self.export_btn.clicked.connect(self._export)
        self.export_btn.setEnabled(False)
        self.open_btn = QPushButton("Open HTML report")
        self.open_btn.clicked.connect(self._open_html)
        self.open_btn.setEnabled(False)
        row.addStretch(1)
        row.addWidget(self.export_btn)
        row.addWidget(self.open_btn)
        lay.addLayout(row)
        return w

    def _build_threats(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        self.owasp_view = QTextBrowser()
        lay.addWidget(self.owasp_view)
        return w

    # ------------------------------------------------------------------ actions
    def _auth_config(self) -> dict | None:
        if self.mode.currentIndex() == 0:
            return None
        idx = self.auth_type.currentIndex()
        if idx in (0, 1):
            cfg = {"type": "form" if idx == 0 else "token_login", "login_url": self.login_url.text().strip(),
                   "username": self.username.text(), "password": self.password.text(),
                   "username_field": self.user_field.text().strip() or "username",
                   "password_field": self.pass_field.text().strip() or "password"}
            if idx == 0:
                cfg["success_indicator"] = self.success.text()
            else:
                cfg["token_path"] = self.token_path.text().strip() or "token"
            return cfg
        if idx == 2:
            return {"type": "bearer", "token": self.token.text().strip()}
        if idx == 3:
            return {"type": "apikey", "key": self.token.text().strip(), "header": self.api_header.text().strip() or "X-API-Key"}
        headers, cookies = {}, {}
        for line in self.custom.toPlainText().splitlines():
            if line.lower().startswith("cookie:") and "=" in line:
                k, v = line.split(":", 1)[1].split("=", 1)
                cookies[k.strip()] = v.strip()
            elif ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip()] = v.strip()
        return {"type": "headers", "headers": headers, "cookies": cookies}

    def _start(self) -> None:
        target = self.target.text().strip()
        if not target.startswith(("http://", "https://")):
            QMessageBox.warning(self, "Target required", "Enter a full URL starting with http:// or https://")
            return
        if not self.authorized.isChecked():
            QMessageBox.warning(self, "Authorisation required",
                                "Confirm that you are authorised to test this target before scanning.")
            return
        cfg = ScanConfig(
            target=target, authorized=True, auth=self._auth_config(),
            openapi=self.openapi.text().strip() or None,
            allowed_hosts=[h.strip() for h in self.hosts.text().split(",") if h.strip()],
            exclude_paths=[p.strip() for p in self.exclude.text().split(",") if p.strip()],
            active=not self.passive.isChecked(), requests_per_second=float(self.rate.value()),
            max_pages=self.pages.value(), verify_tls=not self.insecure.isChecked(),
            proxy=self.proxy.text().strip() or None,
        )
        self.cfg_used = cfg
        self.log.clear()
        self.bar.setValue(0)
        self.table.setRowCount(0)
        self.detail.clear()
        self.result = None
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.export_btn.setEnabled(False)
        self.open_btn.setEnabled(False)
        self.tabs.setCurrentIndex(1)
        self.worker = ScanWorker(cfg)
        self.worker.progress.connect(self._on_progress)
        self.worker.finished_ok.connect(self._on_done)
        self.worker.failed.connect(self._on_failed)
        self.worker.start()

    def _stop(self) -> None:
        if self.worker:
            self.worker.stop()
            self.stage.setText("Stopping after the current request…")

    def _on_progress(self, msg: str, frac: float) -> None:
        self.stage.setText(msg)
        self.bar.setValue(int(frac * 1000))
        self.log.appendPlainText(f"[{int(frac * 100):3d}%] {msg}")

    def _on_failed(self, msg: str) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.stage.setText("Scan failed")
        self.log.appendPlainText(f"ERROR: {msg}")
        QMessageBox.critical(self, "Scan failed", msg)
        self.tabs.setCurrentIndex(0)

    def _on_done(self, result: ScanResult) -> None:
        self.result = result
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.export_btn.setEnabled(True)
        self.open_btn.setEnabled(True)
        c = result.counts()
        self.summary.setText(
            f"{result.mode.title()} scan of {result.target}: "
            f"{c['critical']} critical, {c['high']} high, {c['medium']} medium, {c['low']} low, {c['info']} info "
            f"({result.requests_made} requests, {len(result.endpoints)} endpoints)")
        self._fill_table(result)
        self._fill_owasp(result)
        self.tabs.setCurrentIndex(2)
        self.statusBar().showMessage("Scan complete.")

    def _fill_table(self, result: ScanResult) -> None:
        fs = result.sorted_findings()
        self.table.setRowCount(len(fs))
        for r, f in enumerate(fs):
            sev = QTableWidgetItem(f.severity.upper())
            sev.setForeground(QBrush(QColor("white")))
            sev.setBackground(QBrush(QColor(SEV_COLOR[f.severity])))
            sev.setData(Qt.UserRole, r)
            self.table.setItem(r, 0, sev)
            self.table.setItem(r, 1, QTableWidgetItem(f.title))
            self.table.setItem(r, 2, QTableWidgetItem(f"{f.method} {f.url}"))
            self.table.setItem(r, 3, QTableWidgetItem(", ".join(f.owasp_web)))
            self.table.setItem(r, 4, QTableWidgetItem(", ".join(f.owasp_api)))
        self._sorted = fs

    def _show_detail(self) -> None:
        rows = self.table.selectionModel().selectedRows()
        if not rows or not self.result:
            return
        f = self._sorted[rows[0].row()]
        import html
        e = html.escape
        self.detail.setHtml(
            f"<h3>{e(f.title)} <span style='color:{SEV_COLOR[f.severity]}'>[{f.severity.upper()}]</span></h3>"
            f"<p><b>{e(f.method)} {e(f.url)}</b>{(' - parameter <code>' + e(f.parameter) + '</code>') if f.parameter else ''}<br>"
            f"OWASP Web: {e(', '.join(f.owasp_web) or '-')} | OWASP API: {e(', '.join(f.owasp_api) or '-')} | "
            f"{e(', '.join(f.cwe) or '-')} | confidence: {e(f.confidence)}</p>"
            f"<p>{e(f.description)}</p>"
            f"{('<p><b>Evidence:</b> <code>' + e(f.evidence) + '</code></p>') if f.evidence else ''}"
            f"<p><b>Remediation:</b> {e(f.remediation)}</p>")

    def _fill_owasp(self, result: ScanResult) -> None:
        cov = coverage(result.findings)

        def section(title: str, catalog: dict, groups: dict) -> str:
            rows = "".join(
                f"<tr><td><b>{c}</b></td><td>{n}</td><td align=center>{len(groups.get(c, []))}</td></tr>"
                for c, (n, _) in catalog.items())
            return f"<h3>{title}</h3><table cellpadding=4 border=0 width=100%>{rows}</table>"

        tm = result.threat_model or {}
        threats = "".join(
            f"<tr><td><b>{t['id']}</b></td><td>{t['stride']}</td><td>{t['component']}: {t['threat']}</td>"
            f"<td>{t['status']}</td><td><b>{t['risk']}</b></td></tr>" for t in tm.get("threats", []))
        self.owasp_view.setHtml(
            section("OWASP Top 10 - Web (2021): findings per category", WEB_TOP10, cov["web"]) +
            section("OWASP API Security Top 10 (2023): findings per category", API_TOP10, cov["api"]) +
            "<h3>STRIDE threats</h3><table cellpadding=4 border=1 width=100%>"
            "<tr><th>ID</th><th>STRIDE</th><th>Threat</th><th>Status</th><th>Risk</th></tr>" + threats + "</table>")

    def _export(self) -> None:
        if not self.result:
            return
        folder = QFileDialog.getExistingDirectory(self, "Choose output folder")
        if not folder:
            return
        written = write_reports(self.result, Path(folder), ["html", "json", "sarif", "md"],
                                self.cfg_used.redacted() if self.cfg_used else None)
        self._last_html = written["html"]
        QMessageBox.information(self, "Reports saved", "\n".join(str(p) for p in written.values()))

    def _open_html(self) -> None:
        if not self.result:
            return
        import tempfile
        out = Path(tempfile.mkdtemp(prefix="dynascan-"))
        written = write_reports(self.result, out, ["html"], self.cfg_used.redacted() if self.cfg_used else None)
        webbrowser.open(written["html"].as_uri())


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Dynascan")
    win = MainWindow()
    win.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
