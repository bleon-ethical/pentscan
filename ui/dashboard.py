# ui/dashboard.py
from PyQt5.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame,
    QScrollArea, QSizePolicy, QGridLayout
)
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtGui import QFont, QColor, QPalette
import matplotlib
matplotlib.use('Qt5Agg')
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg
from matplotlib.figure import Figure
from matplotlib import rcParams
rcParams.update({'figure.autolayout': True})

class MetricCard(QFrame):
    """Tarjeta de métrica profesional con estilo moderno"""
    def __init__(self, title: str, value: str, color: str = "#3498db", parent=None):
        super().__init__(parent)
        self.setFrameShape(QFrame.StyledPanel)
        self.setStyleSheet(f"""
            QFrame {{
                background-color: #2d2d2d;
                border-radius: 12px;
                border: 1px solid #3a3a3a;
            }}
        """)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 16, 20, 16)
        
        title_label = QLabel(title)
        title_label.setFont(QFont("Segoe UI", 10))
        title_label.setStyleSheet("color: #aaa;")
        
        value_label = QLabel(value)
        value_label.setFont(QFont("Segoe UI", 18, QFont.Bold))
        value_label.setStyleSheet(f"color: {color};")
        value_label.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(title_label)
        layout.addWidget(value_label)
        self.setLayout(layout)

class VulnerabilityChart(FigureCanvasQTAgg):
    """Gráfico circular de vulnerabilidades por severidad"""
    def __init__(self, parent=None, width=5, height=4, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi, facecolor='#252526')
        self.axes = fig.add_subplot(111)
        self.axes.set_facecolor('#252526')
        super().__init__(fig)
        self.setParent(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def update_chart(self, data: dict):
        self.axes.clear()
        
        # Filtrar datos con valores > 0
        labels = []
        sizes = []
        colors = []
        color_map = {
            'CRITICAL': '#e74c3c',
            'HIGH': '#f39c12',
            'MEDIUM': '#3498db',
            'LOW': '#2ecc71',
            'INFO': '#95a5a6'
        }
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
            if data.get(severity, 0) > 0:
                labels.append(severity)
                sizes.append(data[severity])
                colors.append(color_map.get(severity, '#95a5a6'))
        
        if not sizes:
            self.axes.text(0.5, 0.5, 'Sin vulnerabilidades', 
                          horizontalalignment='center',
                          verticalalignment='center',
                          transform=self.axes.transAxes,
                          color='white', fontsize=14)
        else:
            wedges, texts, autotexts = self.axes.pie(
                sizes, 
                labels=labels, 
                colors=colors,
                autopct=lambda pct: f'{int(pct/100.*sum(sizes))}' if pct > 5 else '',
                startangle=90,
                textprops={'color': 'white', 'fontsize': 10}
            )
            for autotext in autotexts:
                autotext.set_color('white')
                autotext.set_fontweight('bold')
        
        self.axes.set_title('Distribución de Vulnerabilidades', 
                           color='white', fontsize=12, pad=20)
        self.draw()

class HostsChart(FigureCanvasQTAgg):
    """Gráfico de barras: hosts por sistema operativo"""
    def __init__(self, parent=None, width=5, height=3, dpi=100):
        fig = Figure(figsize=(width, height), dpi=dpi, facecolor='#252526')
        self.axes = fig.add_subplot(111)
        self.axes.set_facecolor('#252526')
        super().__init__(fig)
        self.setParent(parent)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)

    def update_chart(self, os_data: dict):
        self.axes.clear()
        
        if not os_data:
            self.axes.text(0.5, 0.5, 'Sin datos de SO', 
                          horizontalalignment='center',
                          verticalalignment='center',
                          transform=self.axes.transAxes,
                          color='white', fontsize=12)
            self.draw()
            return
        
        # Limitar a top 5 SOs
        sorted_os = sorted(os_data.items(), key=lambda x: x[1], reverse=True)[:5]
        labels = [item[0] if len(item[0]) < 20 else item[0][:17] + "..." for item in sorted_os]
        counts = [item[1] for item in sorted_os]
        
        bars = self.axes.bar(labels, counts, color='#3498db', edgecolor='#2980b9')
        self.axes.set_title('Hosts por Sistema Operativo', color='white', fontsize=12, pad=15)
        self.axes.tick_params(axis='x', colors='white', labelrotation=15)
        self.axes.tick_params(axis='y', colors='white')
        self.axes.spines['bottom'].set_color('#555')
        self.axes.spines['left'].set_color('#555')
        
        # Añadir valores encima de las barras
        for bar in bars:
            height = bar.get_height()
            self.axes.annotate(f'{int(height)}',
                              xy=(bar.get_x() + bar.get_width() / 2, height),
                              xytext=(0, 3),
                              textcoords="offset points",
                              ha='center', va='bottom',
                              color='white', fontsize=9)
        
        self.draw()

class DashboardWidget(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.results = []

    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)

        # Título
        title_label = QLabel("Panel de Análisis de Seguridad")
        title_label.setFont(QFont("Segoe UI", 18, QFont.Bold))
        title_label.setStyleSheet("color: white; margin-bottom: 10px;")
        title_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(title_label)

        # Métricas superiores
        self.metrics_layout = QHBoxLayout()
        self.metrics_layout.setSpacing(15)
        self.metric_cards = {}
        for name in ["Hosts", "Vulnerabilidades", "Críticas", "Servicios"]:
            card = MetricCard(name, "0")
            self.metric_cards[name] = card
            self.metrics_layout.addWidget(card)
        main_layout.addLayout(self.metrics_layout)

        # Gráficos
        charts_layout = QHBoxLayout()
        charts_layout.setSpacing(20)

        # Gráfico de vulnerabilidades
        self.vuln_chart = VulnerabilityChart(self, width=4, height=3)
        chart_container1 = QFrame()
        chart_container1.setStyleSheet("background-color: #252526; border-radius: 10px;")
        chart_layout1 = QVBoxLayout(chart_container1)
        chart_layout1.addWidget(self.vuln_chart)
        charts_layout.addWidget(chart_container1)

        # Gráfico de SO
        self.os_chart = HostsChart(self, width=4, height=3)
        chart_container2 = QFrame()
        chart_container2.setStyleSheet("background-color: #252526; border-radius: 10px;")
        chart_layout2 = QVBoxLayout(chart_container2)
        chart_layout2.addWidget(self.os_chart)
        charts_layout.addWidget(chart_container2)

        main_layout.addLayout(charts_layout)

        # Recomendaciones
        rec_label = QLabel("Recomendaciones Clave")
        rec_label.setFont(QFont("Segoe UI", 12, QFont.Bold))
        rec_label.setStyleSheet("color: #3498db; margin-top: 10px;")
        main_layout.addWidget(rec_label)

        self.recommendations = QLabel()
        self.recommendations.setFont(QFont("Segoe UI", 10))
        self.recommendations.setStyleSheet("""
            background-color: #2d2d2d;
            padding: 15px;
            border-radius: 10px;
            color: #ecf0f1;
            line-height: 1.4;
        """)
        self.recommendations.setWordWrap(True)
        self.recommendations.setAlignment(Qt.AlignTop | Qt.AlignLeft)
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setWidget(self.recommendations)
        scroll_area.setStyleSheet("border: none;")
        main_layout.addWidget(scroll_area)

        self.setLayout(main_layout)

    def update_dashboard(self, results: list):
        self.results = results
        self._update_metrics()
        self._update_charts()
        self._update_recommendations()

    def _update_metrics(self):
        total_hosts = len(results)
        total_vulns = 0
        critical_vulns = 0
        total_services = 0

        for host in results:
            ports = [p for p in host.get('ports', []) if p.get('state') == 'open']
            total_services += len(ports)
            for vuln in host.get('vulns', []):
                total_vulns += 1
                if vuln.get('severity') == 'CRITICAL':
                    critical_vulns += 1

        self.metric_cards["Hosts"].findChild(QLabel, '').setText(str(total_hosts))
        self.metric_cards["Vulnerabilidades"].findChild(QLabel, '').setText(str(total_vulns))
        self.metric_cards["Críticas"].findChild(QLabel, '').setText(str(critical_vulns))
        self.metric_cards["Servicios"].findChild(QLabel, '').setText(str(total_services))

        # Actualizar colores
        crit_card = self.metric_cards["Críticas"]
        crit_value_label = crit_card.findChildren(QLabel)[1]
        crit_value_label.setStyleSheet("color: #e74c3c;" if critical_vulns > 0 else "color: #2ecc71;")

    def _update_charts(self):
        # Datos de vulnerabilidades
        vuln_severity = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'INFO': 0}
        os_count = {}

        for host in results:
            # Contar SO
            os_name = host.get('os', 'Desconocido')
            if os_name != 'Desconocido':
                os_count[os_name] = os_count.get(os_name, 0) + 1
            
            # Contar vulnerabilidades
            for vuln in host.get('vulns', []):
                sev = vuln.get('severity', 'INFO')
                if sev in vuln_severity:
                    vuln_severity[sev] += 1

        self.vuln_chart.update_chart(vuln_severity)
        self.os_chart.update_chart(os_count)

    def _update_recommendations(self):
        recommendations = []
        critical_hosts = []
        writable_shares = []
        api_keys_found = False

        for host in results:
            ip = host['ip']
            for vuln in host.get('vulns', []):
                if vuln.get('severity') == 'CRITICAL':
                    critical_hosts.append(ip)
                if vuln.get('id') == 'WRITABLE_SHARE':
                    writable_shares.append(ip)
                if vuln.get('type') == 'API_KEY':
                    api_keys_found = True

        if critical_hosts:
            hosts_str = ", ".join(set(critical_hosts[:3]))
            recommendations.append(f"Atacar hosts críticos: {hosts_str}")
        if writable_shares:
            shares_str = ", ".join(set(writable_shares[:2]))
            recommendations.append(f"Explotar shares SMB escribibles en: {shares_str}")
        if api_keys_found:
            recommendations.append("Claves API expuestas: priorizar robo de credenciales cloud")
        if not recommendations:
            recommendations.append("No se encontraron hallazgos críticos. Continuar con pruebas manuales.")

        self.recommendations.setText("\n".join(f"• {r}" for r in recommendations))