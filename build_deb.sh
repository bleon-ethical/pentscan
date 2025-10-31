#!/bin/bash
set -e

VERSION="1.0.0"
ARCH="amd64"
PKG_NAME="pentscan_${VERSION}_${ARCH}.deb"

echo "[+] Creando estructura DEB..."
rm -rf deb_build
mkdir -p deb_build/DEBIAN
mkdir -p deb_build/usr/bin
mkdir -p deb_build/usr/share/applications
mkdir -p deb_build/usr/share/icons/hicolor/512x512/apps

# Copiar binario
cp pentscan.py deb_build/usr/bin/pentscan
chmod +x deb_build/usr/bin/pentscan

# Copiar icono y .desktop
cp pentscan.png deb_build/usr/share/icons/hicolor/512x512/apps/
cp pentscan.desktop deb_build/usr/share/applications/

# Crear control file
cat > deb_build/DEBIAN/control <<EOF
Package: pentscan
Version: ${VERSION}
Architecture: ${ARCH}
Maintainer: Tu Nombre <tu@email.com>
Description: Advanced pentesting suite for Kali and Parrot OS
Homepage: https://github.com/tuusuario/pentscan
Depends: python3-pyqt5, nmap, wkhtmltopdf, smbclient, ldap-utils, python3-pip
Section: utils
Priority: optional
EOF

# Permisos
chmod 755 deb_build/DEBIAN/control

echo "[+] Construyendo paquete DEB..."
dpkg-deb --build deb_build ${PKG_NAME}

echo "[+] Paquete creado: ${PKG_NAME}"
rm -rf deb_build