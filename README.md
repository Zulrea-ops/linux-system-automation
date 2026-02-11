# linux-system-automation
Collection of Linux automation and security scripts.

---

## System Maintenance Scripts

Bash script for automating basic system maintenance tasks on Debian-based Linux systems.

### Features
- System update and upgrade
- Automatic cleanup (autoremove, autoclean)
- Disk usage reporting
- Timestamped log files
- Root privilege verification

### Environment
- Tested on Debian 13 (headless server)
- Executed with sudo

### Usage

```bash
sudo ./system_maintenance.sh

## SSH Auth Log Analyzer

Python script that analyzes SSH authentication logs via journalctl.

### Features

- Detect failed SSH login attempts
- Identify top attacking IPs
- Detect brute-force patterns (configurable threshold & time window)
- Detect successful logins (password/publickey)
- Count unique source IPs

### Requirements 

- Debian-based system
- systemd / journald
- Python 3.9+

### Usage

```bash
sudo python3 auth_log_analyzer.py
