import subprocess
import re
import sys

if len(sys.argv) != 3:
    print(f'[-] Usage: python {sys.argv[0]} <input_file> <output_file>')
    sys.exit()

# Input file with subnet blocks (one per line)
input_file = str(sys.argv[1])
output_file = str(sys.argv[2])

alive_ips = []

with open(input_file, "r") as f:
    subnets = [line.strip() for line in f if line.strip()]

for subnet in subnets:
    print(f"[*] Scanning {subnet} ...")
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T4", subnet],
            capture_output=True, text=True
        )

        # Extract IPs from "Nmap scan report for <IP>"
        for line in result.stdout.splitlines():
            match = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
            if match:
                ip = match.group(1)
                alive_ips.append(ip)
                print(f"[+] Host up: {ip}")

    except Exception as e:
        print(f"Error scanning {subnet}: {e}")

# Save alive IPs to file
with open(output_file, "w") as f:
    f.write("\n".join(alive_ips))

print(f"\nDone! Alive IPs saved to {output_file}")
