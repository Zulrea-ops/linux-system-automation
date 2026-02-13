#!/usr/bin/env bash
set -euo pipefail

# ----------------------------
# Linux Baseline Audit Script
#-----------------------------

SCRIPT_NAME="linux_baseline_audit.sh"
VERSION="0.1.0"

# Defaults
OUTPUT_FILE="baseline_report.txt"
LOG_FILE="baseline_audit.log"
VERBOSE=0

ENABLE_NMAP=0
NMAP_TARGET="127.0.0.1"
NMAP_ARGS="-sT -sV -Pn"

# Results severity tracking
HAS_WARN=0
HAS_CRIT=0

usage() {
	cat <<EOF
${SCRIPT_NAME} v${VERSION}

Usage:
  ./${SCRIPT_NAME} [options]

Options:
  -o, --output <file>
  -l, --log <file>
  -v, --verbose
  --nmap
  --target <ip>
  ---nmap-args "<args>"
  -h, --help
EOF
}

timestamp() {
	date +"%Y-%m-%d %H:%M:%S"
}

log_line() {
	echo "[$(timestamp)] $*" >> "$LOG_FILE"
}

print_console(){
	if [[ "$VERBOSE" -eq 1 ]]; then
		echo "$*"
	fi
}

report_line() {
	echo "$*" >> "$OUTPUT_FILE"
}

info() {
	log_line "INFO: $*"
	print_console "[INFO] $*"
}

warn() {
	HAS_WARN=1
	log_line "WARN: $*"
	print_console "[WARN] $*"
	report_line "WARN: $*"
}

crit() {
	HAS_CRIT=1
	log_line "CRIT: $*"
	print_console "[CRIT] $*"
	report_line "CRIT: $*"
}

ok() {
	log_line "OK: $*"
	print_console "[OK] $*"
	report_line "OK: $*"
}

require_root_if_needed() {
	if [[ "${EUID}" -ne 0 ]]; then
		warn "Not running as root. Some checks may be skipped or incomplete."
	fi
}

init_files(){
	: > "$LOG_FILE"
	: > "$OUTPUT_FILE"

	report_line "Linux Baseline Audit Report"
	report_line "Generated: $(timestamp)"
	report_line "Host: $(hostname 2>/dev/null || echo unknown)"
	report_line "User: $(id -un 2>/dev/null || echo unknown)"
	report_line "----------------------------------------"
	report_line ""
}

parse_args(){
	while [[ $# -gt 0 ]]; do
		case "$1" in
			-o|--output)
				OUTPUT_FILE="$2"
				shift 2
				;;
			-l|--log)
				LOG_FILE="$2"
				shift 2
				;;
			-v|--verbose)
				VERBOSE=1
				shift
				;;
			--nmap)
				ENABLE_NMAP=1
				shift
				;;
			--target)
				NMAP_TARGET="$2"
				shift 2
				;;
			--nmap-args)
				NMAP_ARGS="$2"
				shift 2
				;;
			-h|--help)
				usage
				exit 0
				;;
			*)
				echo "Unknown option: $1" >&2
				usage >&2
				exit 2
				;;
		esac
	done
}

# ---------------------------------------
# Checks
# ---------------------------------------

check_system_info(){
	report_line "## System info"
	local kernel uptime os

	kernel="$(uname -srmo 2>/dev/null || true)"
	uptime="$(uptime -p 2>/dev/null || true)"

	if [[ -r /etc/os-release ]]; then
		os="$(. /etc/os-release && echo "${PRETTY_NAME:-unknown}")"
	else
		os="unknown"
	fi

	report_line "OS: ${os}"
	report_line "Kernel: ${kernel}"
	report_line "Uptime: ${uptime}"
	report_line ""
	ok "Collected system info"
}

check_sensitive_permissions(){
	report_line "## Sensitive file permissions"

	if ! command -v stat >/dev/null 2>&1; then
		warn "'stat' not found. Skipping permissions checks."
		report_line ""
		return
	fi

	# /etc/shadow
	if [[ -e /etc/shadow ]]; then
		local shadow_perm shadow_owner shadow_group
		shadow_perm="$(stat -c '%a' /etc/shadow 2>/dev/null || echo '')"
		shadow_owner="$(stat -c '%U' /etc/shadow 2>/dev/null || echo '')"
		shadow_group="$(stat -c '%G' /etc/shadow 2>/dev/null || echo '')"

		report_line "/ect/shadow -> perm=${shadow_perm} owner=${shadow_owner} groups=${shadow_group}"

		if [[ "$shadow_owner" != "root" ]]; then
			crit "/etc/shadow owner is not root (owner=${shadow_owner})"
		elif [[ -n "$shadow_perm" && "${shadow_perm:2:1}" -ge 4 ]]; then
			crit "/etc/shadow appears world-readable (perm=${shadow_perm})"
		else
			ok "/etc/shadow ownership/permissions look reasonable"
		fi
	else
		warn "/etc/shadow not found"
	fi

	# /etc/passwd
	if [[ -e /etc/passwd ]]; then
		local passwd_perm passwd_owner
		passwd_perm="$(stat -c '%a' /etc/passwd 2>/dev/null || echo '')"
		passwd_owner="$(stat -c '%U' /etc/passwd 2>/dev/null || echo '')"

		report_line "/etc/passwd -> perm=${passwd_perm} owner=${passwd_owner}"

		if [[ "$passwd_owner" != "root" ]]; then
			warn "/etc/passwd owner is not root (owner=${passwd_owner})"
		else
			ok "/etc/passwd ownership looks reasonable"
		fi
	else
		warn "/ect/passwd not found"
	fi

	# ~/.ssh
	local home_dir ssh_dir
	home_dir="${HOME:-}"
	ssh_dir="${home_dir}/.ssh"

	if [[ -n "$home_dir" && -d "$ssh_dir" ]]; then
		local ssh_perm
		ssh_perm="$(stat -c '%a' "$ssh_dir" 2>/dev/null || echo '')"
		report_line "${ssh_dir} -> perm=${ssh_perm}"

		if [[ -n "$ssh_perm" && "$ssh_perm" -gt 700 ]]; then
			warn "${ssh_dir} permissions are too open (expected 700, got ${ssh_perm})"
		else
			ok "${ssh_dir} permissions look reasonable"
		fi

		for key in id_rsa id_ed25519 id_ecdsa; do
			local key_path
			key_path="${ssh_dir}/${key}"
			if [[ -f "$key_path" ]]; then
				local key_perm
				key_perm="$(stat -c '%a' "$key_path" 2>/dev/null || echo '')"
				report_line "${key_path} -> perm=${key_perm}"
				if [[ -n "$key_perm" && "$key_perm" -gt 600 ]]; then
					warn "${key_path} permissions are too open (expected 600, got ${key_perm})"
				else
					ok "${key_path} permissions  look reasonable"
				fi
			fi
		done
	else
		report_line "~/.ssh -> not present"
		ok "No ~/.ssh directory detected for current user"
	fi

	#Sticky bit /tmp
	if [[ -d /tmp ]]; then
		local tmp_mode
		tmp_mode="$(stat -c '%a' /tmp 2>/dev/null || echo '')"
		report_line "/tmp -> mode=${tmp_mode} (sticky bit expected: 1777)"
		if [[ "$tmp_mode" == "1777" ]]; then
			ok "/tmp has sticky bit (1777)"
		else
			warn "/tmp mode is not 1777 (mode=${tmp_mode})"
		fi
	fi

	report_line ""
}

main(){
	parse_args "$@"
	init_files
	require_root_if_needed

	info "Starting baseline audit"
	check_system_info
	check_sensitive_permissions

	report_line "--------------------------------------------"

	if [[ "$HAS_CRIT" -eq 1 ]]; then
		report_line "Result: Critical findings detected"
		exit 2
	else
		report_line "Result: No issues detected"
		exit 0
	fi
}

main "$@"
