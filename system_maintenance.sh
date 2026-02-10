#!/usr/bin/env bash
set -euo pipefail

LOG_DIR="/var/log/system-maintenance"
DATE="$(date +%F_%H-%M-%S)"
LOG_FILE="$LOG_DIR/maintenance_$DATE.log"

if [ "$EUID" -ne 0 ]; then
	echo "Please run as root (use sudo)"
	exit 1
fi

mkdir -p "$LOG_DIR"
chmod 750 "$LOG_DIR"

echo "=== System Maintenance ===" | tee -a "$LOG_FILE"
echo "Date: $(date)" | tee -a "LOG_FILE"
echo "Host: $(hostname)" | tee -a "$LOG_FILE"

apt update | tee -a "$LOG_FILE"
apt -y upgrade | tee -a "$LOG_FILE"
apt -y autoremove | tee -a "$LOG_FILE"
apt -y autoclean | tee -a "$LOG_FILE"

df -h | tee -a "$LOG_FILE"

echo "[+] Done. Log saved to $LOG_FILE" | tee -a "$LOG_FILE"




