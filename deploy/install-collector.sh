#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo 'Run this installer as root on the collection server.' >&2; exit 1; fi
SOURCE=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ROOT=/opt/wormrecovery-collector
if systemctl is-active --quiet wormrecovery-collector.service; then
    echo 'Collector is running; stop the service before upgrading.' >&2; exit 1
fi
command -v python3 >/dev/null
if ! id wormcollector >/dev/null 2>&1; then useradd --system --home-dir /var/lib/wormrecovery-collector --shell /usr/sbin/nologin wormcollector; fi
install -d -m 755 "$ROOT"
install -m 644 "$SOURCE/collector_server.py" "$SOURCE/diagnostic_transport.py" "$ROOT/"
python3 -m venv "$ROOT/venv"
"$ROOT/venv/bin/python" -m pip install --disable-pip-version-check -r "$SOURCE/deploy/collector-requirements.txt"
install -d -o wormcollector -g wormcollector -m 700 /var/lib/wormrecovery-collector
if [ ! -f /var/lib/wormrecovery-collector/collector-server.json ]; then
    runuser -u wormcollector -- "$ROOT/venv/bin/python" "$ROOT/collector_server.py" init --directory /var/lib/wormrecovery-collector
fi
install -m 644 "$SOURCE/deploy/wormrecovery-collector.service" /etc/systemd/system/wormrecovery-collector.service
systemctl daemon-reload
systemctl enable --now wormrecovery-collector.service
systemctl --no-pager --full status wormrecovery-collector.service
echo 'Allow inbound TCP 10888 in the server firewall and cloud security group.'
echo 'Device enrollment: /var/lib/wormrecovery-collector/devices.enroll'
