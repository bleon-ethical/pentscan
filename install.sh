#!/bin/bash
set -e

echo -e "\n[+] Instalando pentscan desde GitHub Releases..."

# Verificar arquitectura
ARCH=$(dpkg --print-architecture)
if [ "$ARCH" != "amd64" ]; then
    echo "[-] Solo se soporta amd64 por ahora."
    exit 1
fi

# Obtener URL del último .deb
URL=$(curl -s https://api.github.com/repos/bleon-ethical/pentscan/releases/latest | \
      grep "browser_download_url.*_amd64.deb" | \
      head -1 | cut -d '"' -f 4)

if [ -z "$URL" ]; then
    echo "[-] No se encontró paquete .deb en los releases."
    exit 1
fi

echo "[+] Descargando: $(basename "$URL")"
wget "$URL" -O /tmp/pentscan.deb

echo "[+] Instalando dependencias..."
sudo apt update
sudo apt install -y python3-pyqt5 nmap wkhtmltopdf smbclient ldap-utils python3-pip

echo "[+] Instalando pentscan..."
sudo dpkg -i /tmp/pentscan.deb || sudo apt --fix-broken install -y

# Configurar ícono de escritorio
echo "[+] Configurando ícono de escritorio..."
sudo mkdir -p /usr/share/icons/hicolor/512x512/apps/
sudo cp /usr/bin/pentscan.png /usr/share/icons/hicolor/512x512/apps/ 2>/dev/null || true
sudo update-desktop-database

echo -e "\n[+] ¡Instalación completada!"
echo "    Ejecuta con: sudo pentscan"
rm -f /tmp/pentscan.deb