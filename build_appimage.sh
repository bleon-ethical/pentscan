#!/bin/bash
set -e

VERSION="1.0.0"
APP_NAME="pentscan-${VERSION}-x86_64.AppImage"

echo "[+] Creando AppDir..."
rm -rf pentscan.AppDir
mkdir -p pentscan.AppDir/usr/bin
mkdir -p pentscan.AppDir/usr/share/icons/hicolor/512x512/apps
mkdir -p pentscan.AppDir/usr/lib

# Copiar binario
cp pentscan.py pentscan.AppDir/usr/bin/pentscan
chmod +x pentscan.AppDir/usr/bin/pentscan

# Copiar icono y .desktop
cp pentscan.png pentscan.AppDir/usr/share/icons/hicolor/512x512/apps/
cp pentscan.desktop pentscan.AppDir/

# Crear AppRun
cat > pentscan.AppDir/AppRun <<'EOF'
#!/bin/bash
HERE="$(dirname "$(readlink -f "${0}")")"
export PYTHONPATH="${HERE}/usr/lib/python3.9/site-packages:${PYTHONPATH}"
exec sudo "${HERE}/usr/bin/pentscan" "$@"
EOF
chmod +x pentscan.AppDir/AppRun

# Instalar dependencias en AppDir (opcional, pero recomendado)
# NOTA: Para AppImage ligero, asumimos que el usuario tiene dependencias
# Si quieres AppImage autocontenida, usa python-appimage

echo "[+] Descargando appimagetool..."
wget -c "https://github.com/AppImage/AppImageKit/releases/download/13/appimagetool-x86_64.AppImage" -O appimagetool
chmod +x appimagetool

echo "[+] Construyendo AppImage..."
./appimagetool pentscan.AppDir ${APP_NAME}

echo "[+] AppImage creada: ${APP_NAME}"
rm -rf pentscan.AppDir appimagetool