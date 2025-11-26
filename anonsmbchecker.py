#!/usr/bin/env python3
import sys
from impacket.smbconnection import SMBConnection

def check_smb_anon(ip):
    try:
        conn = SMBConnection(ip, ip, None, 445, timeout=3)
        conn.login("", "")   # anonymous login attempt

        # If login succeeded, enumerate shares
        shares = []
        for share in conn.listShares():
            shares.append(share['shi1_netname'][:-1])  # remove trailing null

        conn.logoff()
        return True, shares

    except Exception:
        return False, []

def main():
    if len(sys.argv) != 3:
        print("Usage: python3 anonsmbchecker.py <ip_list_file> <output_file>")
        sys.exit(1)

    ip_file = sys.argv[1]
    output_file = sys.argv[2]

    with open(ip_file, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    print(f"[+] Loaded {len(ips)} IPs")

    anon_hosts = []

    for ip in ips:
        ok, shares = check_smb_anon(ip)

        if ok:
            anon_hosts.append(ip)

            if shares:
                print(f"{ip} -> {', '.join(shares)}")
            else:
                print(f"{ip} -> (Anonymous login OK, but no shares listed)")

    # Save hits to output file
    with open(output_file, "w") as f:
        for host in anon_hosts:
            f.write(host + "\n")

    print(f"\n[+] Anonymous SMB hosts saved to: {output_file}")
    print("[+] Done.")

if __name__ == "__main__":
    print(r"""
       █▓▒░ anonsmbchecker ░▒▓█
    ▄████▄   ▄████▄   ▄████▄   ▄████▄   ▄████▄ 
   ███▀▀███  ███▀▀███ ███▀▀███ ███▀▀███ ███▀▀███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀ 
             by Mr. Robot.txt
    """)
    main()
