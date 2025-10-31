# ui/main_window.py
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5.QtGui import *
from core.scanner import AdvancedScanner
from core.scan_logger import log_scan
import subprocess
import json
import os

class pentscanUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("pentscan")
        self.resize(1300, 750)
        self.scanner = AdvancedScanner()
        self.results = []
        
        # Widgets principales
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("192.168.1.0/24")
        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["stealth", "normal", "aggressive", "destructive"])
        self.profile_combo.setCurrentText("stealth")  # SAFE SCAN POR DEFECTO
        self.destructive_check = QCheckBox("Confirmo modo destructivo")
        self.destructive_check.setVisible(False)
        self.scan_btn = QPushButton("Escanear Red")
        self.export_pdf_btn = QPushButton("Exportar PDF")
        self.export_json_btn = QPushButton("Exportar JSON")
        
        # Tabla de resultados
        self.result_table = QTableWidget()
        self.result_table.setColumnCount(6)
        self.result_table.setHorizontalHeaderLabels(["IP", "SO", "Puertos", "AD", "Vulns", "Acciones"])
        self.result_table.horizontalHeader().setStretchLastSection(True)
        self.result_table.setSortingEnabled(True)
        
        # Terminal integrada
        self.shell_input = QLineEdit()
        self.shell_output = QTextEdit()
        self.shell_output.setFont(QFont("Monospace", 10))
        self.shell_output.setReadOnly(True)
        
        # Layout superior
        top_layout = QHBoxLayout()
        top_layout.addWidget(QLabel("Objetivo:"))
        top_layout.addWidget(self.target_input)
        top_layout.addWidget(QLabel("Modo:"))
        top_layout.addWidget(self.profile_combo)
        top_layout.addWidget(self.destructive_check)
        top_layout.addWidget(self.scan_btn)
        top_layout.addWidget(self.export_pdf_btn)
        top_layout.addWidget(self.export_json_btn)
        
        # Layout de terminal
        shell_layout = QVBoxLayout()
        shell_layout.addWidget(QLabel("Terminal Integrada:"))
        shell_layout.addWidget(self.shell_output)
        shell_layout.addWidget(self.shell_input)
        shell_widget = QWidget()
        shell_widget.setLayout(shell_layout)
        
        # Divisor principal
        main_splitter = QSplitter(Qt.Vertical)
        main_splitter.addWidget(self.result_table)
        main_splitter.addWidget(shell_widget)
        
        # Layout principal
        main_layout = QVBoxLayout()
        main_layout.addLayout(top_layout)
        main_layout.addWidget(main_splitter)
        
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)
        
        # Conexiones
        self.profile_combo.currentTextChanged.connect(self.toggle_destructive)
        self.scan_btn.clicked.connect(self.start_scan)
        self.export_pdf_btn.clicked.connect(self.export_pdf)
        self.export_json_btn.clicked.connect(self.export_json)
        self.shell_input.returnPressed.connect(self.run_shell)
    
    def toggle_destructive(self, text):
        self.destructive_check.setVisible(text == "destructive")
    
    def start_scan(self):
        target = self.target_input.text().strip()
        profile = self.profile_combo.currentText()
        if profile == "destructive" and not self.destructive_check.isChecked():
            QMessageBox.warning(self, "Advertencia", "Activa la confirmación para modo destructivo.")
            return
        if not target:
            QMessageBox.warning(self, "Error", "Ingresa un objetivo válido.")
            return
        
        # Registrar objetivo (solo hash)
        log_scan(target, profile)
        
        self.scan_btn.setEnabled(False)
        self.worker = ScanWorker(self.scanner, target, profile)
        self.worker.finished.connect(self.on_scan_finished)
        self.worker.start()
    
    def on_scan_finished(self, results):
        self.results = results
        self.result_table.setRowCount(len(results))
        for row, host in enumerate(results):
            self.result_table.setItem(row, 0, QTableWidgetItem(host['ip']))
            self.result_table.setItem(row, 1, QTableWidgetItem(host.get('os', 'N/A')))
            ports = ", ".join(str(p['port']) for p in host['ports'] if p['state'] == 'open')
            self.result_table.setItem(row, 2, QTableWidgetItem(ports))
            ad = "Sí" if 'ad_info' in host and host['ad_info'] else "No"
            self.result_table.setItem(row, 3, QTableWidgetItem(ad))
            vulns = len(host.get('vulns', []))
            self.result_table.setItem(row, 4, QTableWidgetItem(str(vulns)))
            btn = QPushButton("Comandos")
            btn.clicked.connect(lambda _, h=host: self.show_commands(h))
            self.result_table.setCellWidget(row, 5, btn)
        self.scan_btn.setEnabled(True)
    
    def show_commands(self, host):
        cmds = []
        if 'ad_info' in host:
            ad = host['ad_info']
            if 'as_rep_command' in ad:
                cmds.append(ad['as_rep_command'])
        if cmds:
            msg = "\n".join(cmds)
        else:
            msg = "No hay comandos sugeridos."
        QMessageBox.information(self, "Comandos Útiles", msg)
    
    def export_pdf(self):
        if not self.results:
            QMessageBox.information(self, "Info", "No hay resultados para exportar.")
            return
        from core.pdf_generator import generate_executive_report
        path, _ = QFileDialog.getSaveFileName(self, "Guardar PDF", "pentscan_report.pdf", "PDF (*.pdf)")
        if path:
            try:
                generate_executive_report(self.results, path)
                QMessageBox.information(self, "Éxito", f"Reporte PDF generado:\n{path}")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"No se pudo generar el PDF:\n{str(e)}")
    
    def export_json(self):
        if not self.results:
            QMessageBox.information(self, "Info", "No hay resultados.")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Guardar JSON", "pentscan_results.json", "JSON (*.json)")
        if path:
            with open(path, 'w') as f:
                json.dump(self.results, f, indent=4)
            QMessageBox.information(self, "Éxito", f"Guardado en {path}")
    
    def run_shell(self):
        cmd = self.shell_input.text().strip()
        if not cmd:
            return
        self.shell_output.append(f"\n$ {cmd}")
        try:
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr
            self.shell_output.append(output if output.strip() else "[Sin salida]")
        except subprocess.TimeoutExpired:
            self.shell_output.append("[!] Comando cancelado por timeout (30s)")
        except Exception as e:
            self.shell_output.append(f"[!] Error: {str(e)}")
        self.shell_input.clear()

class ScanWorker(QThread):
    finished = pyqtSignal(list)
    def __init__(self, scanner, target, profile):
        super().__init__()
        self.scanner = scanner
        self.target = target
        self.profile = profile
    def run(self):
        results = self.scanner.scan(self.target, self.profile)
        self.finished.emit(results)