# Linux System Automation
Collection of Linux automation and security scripts.

## How it works
The Bash script collects basic system information and performs routine maintenance tasks, writing a timestamped log of what was executed.
The Python script parses authentication logs and outputs a summarized report (e.g., failed logins, suspicious IPs) without modifying the system.

## Disclaimer / Educational use
This repository is for educational and defensive purposes only. 
It performs read-only checks and/or routine maintenance, and generates logs/reports to help learning and troubleshooting.
Do not use it to attack systems, bypass security, or access data you do not own or have explicit permission to administer.

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
```

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
```
## Linux Baseline Audit

Bash Script that perfomrs a lightweight security baseline audit.

### Features

- System information collection
- Sensitive file permissions checks
- SSH directory permission checks
- Sticky bit verification on /tmp
- Optional nmap scan (disabled by default)
- Exit codes (0 = OK, 1 = warnings, 2 = critical)

### Usage

```bash
sudo ./linux_baseline_audit.sh -v
```

---

## License

This project is licensed under the MIT License.
