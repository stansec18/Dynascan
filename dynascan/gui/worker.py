"""Runs a scan on a background thread so the UI stays responsive."""
from __future__ import annotations

import asyncio

from PySide6.QtCore import QThread, Signal

from ..auth import AuthError
from ..config import ScanConfig
from ..engine import ScanEngine
from ..scope import OutOfScopeError


class ScanWorker(QThread):
    progress = Signal(str, float)
    finished_ok = Signal(object)   # ScanResult
    failed = Signal(str)

    def __init__(self, cfg: ScanConfig, parent=None) -> None:
        super().__init__(parent)
        self.cfg = cfg
        self.engine = ScanEngine(cfg, lambda msg, frac: self.progress.emit(msg, frac))

    def stop(self) -> None:
        self.engine.stop()

    def run(self) -> None:
        try:
            result = asyncio.run(self.engine.run())
            self.finished_ok.emit(result)
        except OutOfScopeError as e:
            self.failed.emit(str(e))
        except AuthError as e:
            self.failed.emit(f"Authentication failed: {e}")
        except Exception as e:  # noqa: BLE001
            self.failed.emit(f"{type(e).__name__}: {e}")
