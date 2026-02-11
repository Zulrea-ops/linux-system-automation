#!/usr/bin/env python3
"""
auth_log_analyzer.py

Analyze Linux auth.log to detect authentication events:
- Failed SSH login attempts
- Successful SSH logins
- sudo usage

Tested on Debian 13
"""

import re
import subprocess
from collections import Counter
from datetime import datetime, timedelta
from collections import defaultdict, deque

def read_log():
	result = subprocess.run(
		["journalctl", "-u", "ssh", "--no-pager", "-o", "short-iso"],
		capture_output=True,
		text=True
	)
	if result.returncode != 0:
		print("[!] journalctl failed:", result.stderr.strip())
		return []
	return result.stdout.splitlines()

def main():
	lines = read_log()
	print(f"[+] Loaded {len(lines)} SSH log lines")

	ip_counter = Counter()
	ip_re = re.compile(r"from (\S+)")
	failed_events = []

	accepted_counter = Counter()
	accepted_re = re.compile(r"Accepted (password|publickey) for (\S+) from (\S+)")

	ts_re = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T[^\s]+)\s")

	for line in lines:
		if "Failed password" in line:
			ts_m = ts_re.search(line)
			ip_m = ip_re.search(line)

			if ts_m and ip_m:
				ts = datetime.fromisoformat(ts_m.group("ts"))
				ip = ip_m.group(1)

				failed_events.append((ts, ip))
				ip_counter[ip] += 1
		if "Accepted" in line:
			m = accepted_re.search(line)
			if m:
				method = m.group(1)
				user = m.group(2)
				ip = m.group(3)
				accepted_counter[(ip, user, method)] += 1

	threshold = 5
	window = timedelta(minutes=5)

	events_by_ip = defaultdict(deque)
	alerts = []

	for ts, ip in sorted(failed_events, key=lambda x: x[0]):
		q = events_by_ip[ip]
		q.append(ts)

		while q and (ts - q[0]) > window:
			q.popleft()

		if len(q) >= threshold:
			alerts.append((ip, len(q), q[0], ts))
			q.clear()

	print(f"[+] Failed password lines: {sum(ip_counter.values())}")
	print("[+] Top failed IPs:")
	for ip, count in ip_counter.most_common(10):
		print(f"	{count:>4}  {ip}")

	print(f"\n=== Brute-force alerts (threshold={threshold}, window={window}) ===")
	if not alerts:
		print("No brute-force patterns detected.")
	else:
		for ip, count, start, end in alerts:
			print(f"[!] {ip} -> {count} failed attempts between {start} and {end}")

	print("\n[+] Top accepted logins:")
	if not accepted_counter:
		print("    No accepted logins found.")
	else:
		for (ip, user, method), count in accepted_counter.most_common(10):
			print(f"   {count:>4} {ip} user={user} method={method}")

	print(f"[+] Unique source IPs (failed): {len(ip_counter)}")

if __name__ == "__main__":
	main()
