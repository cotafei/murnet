"""
MURNET SYSTEMD INTEGRATION v5.0
Systemd сервисы для VDS deployment
"""

SYSTEMD_SERVICE = """
[Unit]
Description=Murnet P2P Node
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=murnet
Group=murnet
WorkingDirectory=/opt/murnet

# Environment
Environment="PYTHONPATH=/opt/murnet"
Environment="MURNET_PROFILE=vds"
Environment="MURNET_LOG_LEVEL=INFO"

# Execution
ExecStart=/opt/murnet/venv/bin/python -m murnet --config /etc/murnet/config.yaml
ExecReload=/bin/kill -HUP $MAINPID
ExecStop=/bin/kill -TERM $MAINPID

# Restart policy
Restart=on-failure
RestartSec=10
StartLimitInterval=60s
StartLimitBurst=3

# Resource limits
LimitNOFILE=65536
LimitNPROC=4096

# Security
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/murnet /var/log/murnet
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=murnet

[Install]
WantedBy=multi-user.target
"""

SYSTEMD_TIMER = """
[Unit]
Description=Murnet Daily Maintenance

[Timer]
OnCalendar=daily
Persistent=true
RandomizedDelaySec=3600

[Install]
WantedBy=timers.target
"""

SYSTEMD_MAINTENANCE_SERVICE = """
[Unit]
Description=Murnet Maintenance Tasks

[Service]
Type=oneshot
User=murnet
ExecStart=/opt/murnet/venv/bin/python -m murnet.maintenance --vacuum --backup
"""

LOGROTATE_CONFIG = """
/var/log/murnet/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 murnet murnet
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/murnet.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
"""

INSTALL_SCRIPT = """#!/bin/bash
# Murnet VDS Installation Script

set -e

MURNET_USER="murnet"
MURNET_HOME="/opt/murnet"
MURNET_DATA="/var/lib/murnet"
MURNET_LOGS="/var/log/murnet"

echo "🔧 Installing Murnet Node..."

# Создание пользователя
if ! id "$MURNET_USER" &>/dev/null; then
    useradd -r -s /bin/false -d $MURNET_HOME -m $MURNET_USER
fi

# Создание директорий
mkdir -p $MURNET_HOME $MURNET_DATA $MURNET_LOGS
chown -R $MURNET_USER:$MURNET_USER $MURNET_HOME $MURNET_DATA $MURNET_LOGS

# Python venv
python3 -m venv $MURNET_HOME/venv
source $MURNET_HOME/venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Копирование кода
cp -r . $MURNET_HOME/
chown -R $MURNET_USER:$MURNET_USER $MURNET_HOME

# Systemd
cp systemd/murnet.service /etc/systemd/system/
cp systemd/murnet-maintenance.service /etc/systemd/system/
cp systemd/murnet-maintenance.timer /etc/systemd/system/

# Logrotate
cp logrotate/murnet /etc/logrotate.d/

# Конфигурация
mkdir -p /etc/murnet
cat > /etc/murnet/config.yaml << EOF
network:
  bind_host: 0.0.0.0
  port: 8888
  bootstrap_nodes: []

storage:
  data_dir: $MURNET_DATA
  max_size_mb: 2000

api:
  enabled: true
  host: 0.0.0.0
  port: 8080

vds:
  systemd_integration: true
  monitoring_enabled: true
  log_rotation: true
EOF

# Firewall (ufw)
if command -v ufw &> /dev/null; then
    ufw allow 8888/udp
    ufw allow 8080/tcp
    echo "✓ Firewall rules added"
fi

# Запуск
systemctl daemon-reload
systemctl enable murnet
systemctl enable murnet-maintenance.timer
systemctl start murnet

echo "✓ Murnet installed and started!"
echo "  Status: systemctl status murnet"
echo "  Logs: journalctl -u murnet -f"
echo "  API: http://$(hostname -I | awk '{print $1}'):8080"
"""

class SystemdManager:
    """Управление systemd интеграцией"""
    
    @staticmethod
    def generate_service_file(path: str = "systemd/murnet.service"):
        """Генерация service файла"""
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'w') as f:
            f.write(SYSTEMD_SERVICE.strip())
        print(f"✓ Generated {path}")
    
    @staticmethod
    def generate_timer_files(base_path: str = "systemd"):
        """Генерация timer файлов"""
        import os
        os.makedirs(base_path, exist_ok=True)
        
        with open(f"{base_path}/murnet-maintenance.timer", 'w') as f:
            f.write(SYSTEMD_TIMER.strip())
        
        with open(f"{base_path}/murnet-maintenance.service", 'w') as f:
            f.write(SYSTEMD_MAINTENANCE_SERVICE.strip())
        
        print(f"✓ Generated timer files in {base_path}/")
    
    @staticmethod
    def generate_logrotate_config(path: str = "logrotate/murnet"):
        """Генерация logrotate конфига"""
        import os
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'w') as f:
            f.write(LOGROTATE_CONFIG.strip())
        print(f"✓ Generated {path}")
    
    @staticmethod
    def generate_install_script(path: str = "install.sh"):
        """Генерация скрипта установки"""
        with open(path, 'w') as f:
            f.write(INSTALL_SCRIPT.strip())
        
        import stat
        os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        print(f"✓ Generated {path}")
    
    @staticmethod
    def generate_all(output_dir: str = "."):
        """Генерация всех systemd файлов"""
        SystemdManager.generate_service_file(f"{output_dir}/systemd/murnet.service")
        SystemdManager.generate_timer_files(f"{output_dir}/systemd")
        SystemdManager.generate_logrotate_config(f"{output_dir}/logrotate/murnet")
        SystemdManager.generate_install_script(f"{output_dir}/install.sh")
        
        print(f"\n📦 Systemd configuration generated in {output_dir}/")
        print("Installation:")
        print("  sudo ./install.sh")


if __name__ == "__main__":
    SystemdManager.generate_all()