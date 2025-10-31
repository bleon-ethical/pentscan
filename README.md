# 🔍 PentScan

**Suite avanzada de pentesting para Kali Linux y Parrot OS**  
Escaneo de red, detección de CVEs, enumeración de Active Directory, claves API expuestas y generación de reportes PDF — todo en una interfaz gráfica moderna.

---

## 🚀 Características

- **Interfaz gráfica profesional** con panel de análisis en tiempo real
- **Detección de CVEs y vulnerabilidades** con motor NVD local
- **Enumeración de Active Directory**: AS-REP Roasting, Shadow Admins, Delegación
- **Búsqueda de claves API** en JavaScript (AWS, Google, Stripe, GitHub, etc.)
- **Generación de reportes PDF ejecutivos** con CVSS 3.1
- **Modo de agresividad controlada**: `stealth` → `destructive`
- **Shell integrada** para comandos ad-hoc (`crackmapexec`, `bloodhound`, etc.)

---

## 📦 Instalación

### Opción 1: Paquete DEB (Kali/Parrot/Debian)
```bash
wget https://github.com/bleon-ethical/pentscan/releases/latest/download/pentscan_amd64.deb
sudo dpkg -i pentscan_amd64.deb
sudo apt --fix-broken install
```bash
