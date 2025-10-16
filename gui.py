from __future__ import annotations
import json
from typing import Dict, Any
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtGui import QValidator
from scanner import PortScanner
from common import parse_hosts, parse_ports, validate_host, SERVICE_MAP

STATE_COLOR = {
    "open": QtGui.QColor(0,170,0),
    "closed": QtGui.QColor(200,0,0),
    "filtered": QtGui.QColor(200,160,0),
    "error": QtGui.QColor(120,120,120),
}

# --------- Validators ----------
class PortsValidator(QValidator):
    def validate(self, input_text: str, pos: int):
        if not input_text:
            return (QValidator.Acceptable, input_text, pos)
        tokens = [t.strip() for t in input_text.split(",")]
        if input_text.endswith(",") or input_text.endswith("-"):
            return (QValidator.Intermediate, input_text, pos)
        for token in tokens:
            if not token: continue
            if "-" in token:
                try:
                    a,b = map(int, token.split("-",1))
                    if not (1<=a<=65535 and 1<=b<=65535 and a<=b):
                        return (QValidator.Invalid, input_text, pos)
                except ValueError:
                    return (QValidator.Invalid, input_text, pos)
            else:
                try:
                    p = int(token)
                    if not (1<=p<=65535):
                        return (QValidator.Invalid, input_text, pos)
                except ValueError:
                    return (QValidator.Invalid, input_text, pos)
        return (QValidator.Acceptable, input_text, pos)

# --------- Worker ----------
class ScanWorker(QtCore.QThread):
    result_signal = QtCore.pyqtSignal(str, int, dict)
    progress_signal = QtCore.pyqtSignal(int, int)
    finished_signal = QtCore.pyqtSignal(dict)

    def __init__(self, params: Dict[str, Any]):
        super().__init__()
        self.params = params
        self.scanner = PortScanner(timeout_ms=params["timeout_ms"],
                                   max_workers=params["threads"])

    def run(self):
        res = self.scanner.scan(
            targets=self.params["targets"],
            ports=self.params["ports"],
            do_tcp=True,
            do_udp=False,  # ready for future UDP; disabled now
            on_result=lambda h,p,d: self.result_signal.emit(h,p,d),
            on_progress=lambda d,t: self.progress_signal.emit(d,t)
        )
        self.finished_signal.emit(res)

    def stop(self): self.scanner.stop()

# --------- Main Window ----------
class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Port Scanner + Offline AI")
        self.resize(1100, 700)
        self._build_ui()
        self.worker: ScanWorker | None = None
        self.last_result: Dict[str, Any] | None = None
        from ai_engine import LocalAI
        self.ai = LocalAI()

    # UI
    def _build_ui(self):
        central = QtWidgets.QWidget(); self.setCentralWidget(central)
        layout = QtWidgets.QHBoxLayout(central)

        left = QtWidgets.QVBoxLayout(); layout.addLayout(left, 1)
        self.hosts_edit = QtWidgets.QLineEdit()
        self.hosts_edit.setPlaceholderText("Targets (comma-separated IP/hostnames)")
        left.addWidget(self._labeled("Targets", self.hosts_edit))

        # Modes
        mode_box = QtWidgets.QHBoxLayout()
        self.rb_quick = QtWidgets.QRadioButton("Quick"); self.rb_quick.setChecked(True)
        self.rb_full  = QtWidgets.QRadioButton("Full")
        self.rb_custom= QtWidgets.QRadioButton("Custom")
        for rb in (self.rb_quick, self.rb_full, self.rb_custom): mode_box.addWidget(rb)
        left.addWidget(self._labeled_layout("Mode", mode_box))

        self.custom_ports = QtWidgets.QLineEdit()
        self.custom_ports.setValidator(PortsValidator())
        self.custom_ports.setPlaceholderText("e.g. 80,443,1000-2000")
        left.addWidget(self._labeled("Custom Ports", self.custom_ports))

        # Timeout & Threads
        self.timeout_spin = QtWidgets.QSpinBox(); self.timeout_spin.setRange(100,10000); self.timeout_spin.setValue(800)
        left.addWidget(self._labeled("Timeout (ms)", self.timeout_spin))

        threads_box = QtWidgets.QHBoxLayout()
        self.threads_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal); self.threads_slider.setRange(5, 400); self.threads_slider.setValue(150)
        self.threads_label = QtWidgets.QLabel(str(self.threads_slider.value()))
        self.threads_slider.valueChanged.connect(lambda v: self.threads_label.setText(str(v)))
        threads_box.addWidget(self.threads_slider); threads_box.addWidget(self.threads_label)
        left.addWidget(self._labeled_layout("Threads", threads_box))

        # Buttons
        btn_box = QtWidgets.QHBoxLayout()
        self.btn_start = QtWidgets.QPushButton("Start")
        self.btn_stop  = QtWidgets.QPushButton("Stop")
        self.btn_export= QtWidgets.QPushButton("Export JSON")
        self.btn_ai    = QtWidgets.QPushButton("Analyze with AI")
        for b in (self.btn_start, self.btn_stop, self.btn_export, self.btn_ai): btn_box.addWidget(b)
        left.addLayout(btn_box)
        left.addStretch(1)

        # Right
        right = QtWidgets.QVBoxLayout(); layout.addLayout(right, 2)
        self.progress = QtWidgets.QProgressBar(); self.status_label = QtWidgets.QLabel("Idle.")
        right.addWidget(self.progress); right.addWidget(self.status_label)

        self.table = QtWidgets.QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Host","Port","TCP","Service","Banner","Notes"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        right.addWidget(self.table, 5)

        self.warn_label = QtWidgets.QLabel(""); self.warn_label.setStyleSheet("color:#C07800;")
        right.addWidget(self.warn_label)

        self.ai_output = QtWidgets.QTextEdit(); self.ai_output.setReadOnly(True)
        right.addWidget(self._labeled("AI Insights", self.ai_output), 2)

        # Hooks
        self.btn_start.clicked.connect(self.start_scan)
        self.btn_stop.clicked.connect(self.stop_scan)
        self.btn_export.clicked.connect(self.export_json)
        self.btn_ai.clicked.connect(self.run_ai)

        # Style + disclaimer
        self.setStyleSheet("QTableWidget::item{padding:4px;} QPushButton{padding:6px 10px;}")
        QtWidgets.QMessageBox.information(self,"Disclaimer",
            "Use only on systems you own or have permission to test.")

    # helpers
    def _labeled(self, title: str, widget: QtWidgets.QWidget) -> QtWidgets.QWidget:
        w = QtWidgets.QWidget(); v = QtWidgets.QVBoxLayout(w); v.setContentsMargins(0,0,0,0)
        v.addWidget(QtWidgets.QLabel(title)); v.addWidget(widget); return w

    def _labeled_layout(self, title: str, layout: QtWidgets.QLayout) -> QtWidgets.QWidget:
        w = QtWidgets.QWidget(); v = QtWidgets.QVBoxLayout(w); v.setContentsMargins(0,0,0,0)
        v.addWidget(QtWidgets.QLabel(title)); v.addLayout(layout); return w

    def _item_text(self, r: int, c: int) -> str:
        it = self.table.item(r, c); return it.text() if it else ""

    # actions
    def start_scan(self):
        if hasattr(self, "worker") and self.worker and self.worker.isRunning(): return
        hosts = parse_hosts(self.hosts_edit.text())
        bad = [h for h in hosts if not validate_host(h)]
        if bad:
            QtWidgets.QMessageBox.warning(self,"Invalid Hosts",f"Invalid: {', '.join(bad)}"); return
        if not hosts:
            QtWidgets.QMessageBox.warning(self,"Input","Enter at least one host."); return

        mode = "Quick" if self.rb_quick.isChecked() else ("Full" if self.rb_full.isChecked() else "Custom")
        ports = parse_ports(mode, self.custom_ports.text())
        if not ports:
            QtWidgets.QMessageBox.warning(self,"Ports","No ports resolved."); return

        params = {
            "targets": hosts,
            "ports": ports,
            "timeout_ms": int(self.timeout_spin.value()),
            "threads": int(self.threads_slider.value())
        }
        self.table.setRowCount(0); self.warn_label.setText(""); self.ai_output.clear()
        self.progress.setValue(0); self.status_label.setText("Scanning...")

        self.worker = ScanWorker(params)
        self.worker.result_signal.connect(self._on_result)
        self.worker.progress_signal.connect(self._on_progress)
        self.worker.finished_signal.connect(self._on_finished)
        self.worker.start()

    def stop_scan(self):
        if self.worker and self.worker.isRunning():
            self.worker.stop(); self.status_label.setText("Stopping...")

    def _on_progress(self, done: int, total: int):
        self.progress.setMaximum(max(1,total)); self.progress.setValue(done)

    def _find_row(self, host: str, port: int) -> int | None:
        for r in range(self.table.rowCount()):
            if self._item_text(r,0)==host and self._item_text(r,1)==str(port):
                return r
        return None

    def _set_state_cell(self, row: int, col: int, state: str):
        it = self.table.item(row,col)
        if it is None:
            it = QtWidgets.QTableWidgetItem(""); self.table.setItem(row,col,it)
        it.setText(state)
        color = STATE_COLOR.get(state, QtGui.QColor(90,90,90))
        it.setBackground(color); it.setForeground(QtGui.QColor(255,255,255))

    def _on_result(self, host: str, port: int, data: Dict[str, Any]):
        row = self._find_row(host, port)
        if row is None:
            row = self.table.rowCount(); self.table.insertRow(row)
            self.table.setItem(row,0,QtWidgets.QTableWidgetItem(host))
            self.table.setItem(row,1,QtWidgets.QTableWidgetItem(str(port)))
            for c in range(2,6): self.table.setItem(row,c,QtWidgets.QTableWidgetItem(""))

        info = data.get("tcp", {})
        self._set_state_cell(row, 2, info.get("state",""))

        # service guess
        svc = SERVICE_MAP.get(port, self._item_text(row,3) or "")
        self.table.item(row,3).setText(svc)

        # notes: error + latency (banner omitted in TCP-connect baseline)
        notes = []
        if info.get("error"): notes.append(str(info["error"]))
        if "latency_ms" in info and info["latency_ms"] is not None:
            notes.append(f"{info['latency_ms']}ms")
        self.table.item(row,5).setText("; ".join(notes))

    def _on_finished(self, result: Dict[str, Any]):
        self.last_result = result; self.status_label.setText("Done.")
        msgs = []
        for s in result.get("summaries", []):
            for w in s.get("warnings", []):
                msgs.append(f"{s['host']}: {w}")
        if msgs: self.warn_label.setText(" | ".join(msgs))

    def export_json(self):
        if not self.last_result:
            QtWidgets.QMessageBox.information(self,"Nothing to export","Run a scan first."); return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save JSON", "scan_results.json", "JSON (*.json)")
        if not path: return
        with open(path,"w",encoding="utf-8") as f:
            json.dump(self._materialize_results(self.last_result), f, indent=2)
        QtWidgets.QMessageBox.information(self,"Saved",f"Exported to {path}")

    def _materialize_results(self, raw: Dict[str, Any]) -> Dict[str, Any]:
        out = {"started_ms": raw.get("started_ms"), "ended_ms": raw.get("ended_ms"),
               "targets": raw.get("targets", []), "results": [], "params": {}}
        for host, ports in raw.get("results", {}).items():
            entries = []
            for port, detail in ports.items():
                t = detail.get("tcp")
                entries.append({
                    "port": port,
                    "tcp": t.get("state") if t else None,
                    "service_guess": SERVICE_MAP.get(port, ""),
                    "banner": "",
                    "tcp_latency_ms": t.get("latency_ms") if t else None,
                    "tcp_error": t.get("error") if t else None
                })
            out["results"].append({"host": host, "ports": sorted(entries, key=lambda e: e["port"])})
        out["summaries"] = raw.get("summaries", [])
        return out

    def run_ai(self):
        if not self.last_result:
            QtWidgets.QMessageBox.information(self,"No results","Run a scan first."); return
        doc = self._materialize_results(self.last_result)
        text = self.ai.analyze(doc, max_tokens=700)
        self.ai_output.setPlainText(text)
