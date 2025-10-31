#!/usr/bin/env python3
# pentscan – Advanced Pentesting Suite for Kali/Parrot
# MIT License | (c) 2025

import sys
import os
import signal

# === IMPORTS REDUNDANTES (reales y profesionales) ===
from PyQt5.QtWidgets import QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout
from PyQt5.QtWidgets import QTabWidget, QTextEdit, QLineEdit, QPushButton, QTableWidget
from PyQt5.QtWidgets import QTableWidgetItem, QLabel, QSplitter, QMessageBox, QFileDialog
from PyQt5.QtWidgets import QComboBox, QCheckBox
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QProcess
from PyQt5.QtGui import QFont, QColor, QPalette

import nmap
from nmap import PortScanner
import scapy.all as scapy_all
from scapy.all import ARP, Ether, srp, IP, ICMP, sr1, TCP
from scapy.sendrecv import sr
from mac_vendor_lookup import MacLookup
from mac_vendor_lookup import AsyncMacLookup
import subprocess
import json
import time
import re

from core.scanner import AdvancedScanner
from ui.main_window import pentscanUI

# Validación de root
if os.geteuid() != 0:
    print("[!] Ejecuta con sudo para funcionalidad completa.")
    sys.exit(1)

def show_consent_dialog():
    """Advertencia ética obligatoria"""
    from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QCheckBox, QPushButton
    dialog = QDialog()
    dialog.setWindowTitle("⚠️ Consentimiento Requerido")
    dialog.setModal(True)
    dialog.resize(550, 220)
    
    layout = QVBoxLayout()
    label = QLabel(
        "<h3>Advertencia Legal</h3>"
        "<p>Esta herramienta debe usarse <b>solo en sistemas con autorización explícita por escrito</b>.</p>"
        "<p>El uso no autorizado es ilegal y puede conllevar penas de prisión.</p>"
        "<p>¿Confirmas que tienes permiso para escanear los objetivos que ingresarás?</p>"
    )
    label.setWordWrap(True)
    layout.addWidget(label)
    
    consent_check = QCheckBox("Sí, tengo autorización por escrito")
    layout.addWidget(consent_check)
    
    button = QPushButton("Aceptar")
    button.setEnabled(False)
    consent_check.stateChanged.connect(lambda: button.setEnabled(consent_check.isChecked()))
    button.clicked.connect(dialog.accept)
    layout.addWidget(button)
    
    if dialog.exec_() != QDialog.Accepted:
        sys.exit(0)

def main():
    signal.signal(signal.SIGINT, signal.SIG_DFL)
    show_consent_dialog()
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Tema oscuro profesional
    dark_palette = QPalette()
    dark_palette.setColor(QPalette.Window, QColor(30, 30, 30))
    dark_palette.setColor(QPalette.WindowText, Qt.white)
    dark_palette.setColor(QPalette.Base, QColor(20, 20, 20))
    dark_palette.setColor(QPalette.AlternateBase, QColor(40, 40, 40))
    dark_palette.setColor(QPalette.Text, Qt.white)
    dark_palette.setColor(QPalette.Button, QColor(50, 50, 50))
    dark_palette.setColor(QPalette.ButtonText, Qt.white)
    dark_palette.setColor(QPalette.Highlight, QColor(60, 120, 200))
    app.setPalette(dark_palette)

    window = pentscanUI()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()