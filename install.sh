
#!/bin/bash
set -e

# Debe ejecutarse como root
if [[ $EUID -ne 0 ]]; then
   echo "Error: Este script debe ejecutarse como root."
   exit 1
fi

echo "Instalando FirewallFalcon Manager..."

# URLs (forzamos IPv4 para evitar problemas de IPv6 con GitHub)
MENU_URL="https://raw.githubusercontent.com/firewallfalcons/FirewallFalcon-Manager/main/menu.sh"
SSHD_URL="https://raw.githubusercontent.com/firewallfalcons/FirewallFalcon-Manager/main/ssh"

# Instalar el menú
wget -4 -q -O /usr/local/bin/menu "$MENU_URL"
chmod +x /usr/local/bin/menu

echo "Aplicando la configuración SSH de FirewallFalcon..."

SSHD_CONFIG="/etc/ssh/sshd_config"
BACKUP="/etc/ssh/sshd_config.backup.$(date +%F-%H%M%S)"

# Respaldar la configuración SSH actual
cp "$SSHD_CONFIG" "$BACKUP"

# Descargar configuración SSH de FirewallFalcon
wget -4 -q -O "$SSHD_CONFIG" "$SSHD_URL"
chmod 600 "$SSHD_CONFIG"

# Validar configuración SSH (silencioso)
if ! sshd -t 2>/dev/null; then
    echo "ERROR: ¡La configuración de SSH no es válida!"
    echo "Restaurando la configuración anterior..."
    cp "$BACKUP" "$SSHD_CONFIG"
    exit 1
fi

echo "Configuración SSH validada."

# Reiniciar SSH de forma silenciosa y segura
restart_ssh() {
    if command -v systemctl >/dev/null 2>&1; then
        systemctl restart sshd 2>/dev/null \
        || systemctl restart ssh 2>/dev/null \
        || return 1
    elif command -v service >/dev/null 2>&1; then
        service sshd restart 2>/dev/null \
        || service ssh restart 2>/dev/null \
        || return 1
    elif command -v rc-service >/dev/null 2>&1; then
        rc-service sshd restart 2>/dev/null \
        || rc-service ssh restart 2>/dev/null \
        || return 1
    elif [ -x /etc/init.d/sshd ]; then
        /etc/init.d/sshd restart >/dev/null 2>&1
    elif [ -x /etc/init.d/ssh ]; then
        /etc/init.d/ssh restart >/dev/null 2>&1
    else
        return 1
    fi
}

if restart_ssh; then
    echo "Servicio SSH reiniciado."
else
    echo "ADVERTENCIA: El reinicio de SSH no está soportado en este sistema."
    echo "La configuración de SSH se aplicó, pero el servicio no se reinició automáticamente."
fi

# Ejecutar la configuración inicial de FirewallFalcon
bash /usr/local/bin/menu --install-setup

echo "¡Instalación completa!"
echo "Escribe 'menu' para comenzar."
``
