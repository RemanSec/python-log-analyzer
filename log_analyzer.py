
import re
from collections import Counter
from pathlib import Path

print("#" * 55)
print("          CYBERSECURITY LOG ANALYZER")
print("#" * 55)

# Sample security logs
logs = [
    "2026-11-18 09:10:12 FAILED LOGIN from 192.168.1.10",
    "2026-11-18 09:11:15 SUCCESS LOGIN from 192.168.1.20",
    "2026-11-18 09:12:18 FAILED LOGIN from 192.168.1.10",
    "2026-11-18 09:13:22 FAILED LOGIN from 192.168.1.15",
    "2026-11-18 09:14:30 FAILED LOGIN from 192.168.1.10",
    "2026-11-18 09:15:40 SUCCESS LOGIN from 192.168.1.25",
    "2026-11-18 09:16:45 FAILED LOGIN from 192.168.1.10",
    "2026-11-18 09:17:50 FAILED LOGIN from 192.168.1.15",
]

failed_attempts = Counter()

print("\nScanning security logs...\n")

# Analyze each log entry
for log in logs:
    if "FAILED LOGIN" in log:
        match = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", log)

        if match:
            ip_address = match.group(1)
            failed_attempts[ip_address] += 1

# Display results
print("FAILED LOGIN REPORT")
print("-" * 55)

if not failed_attempts:
    print("No failed login attempts found.")

for ip, count in failed_attempts.most_common():
    print(f"IP Address: {ip} | Failed Attempts: {count}")

    if count >= 3:
        print("WARNING: Suspicious login activity detected!")
    else:
        print("Status: Normal observation")

print("\n" + "=" * 55)
print("ANALYSIS COMPLETED")
print("=" * 55)
