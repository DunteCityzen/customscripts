import socket
import argparse
import socks
from concurrent.futures import ThreadPoolExecutor, as_completed

TOP_PORTS = list(range(1, 10001))
FULL_PORTS = list(range(1, 65536))

# Nmap-like timing profiles
TIMING_PROFILES = {
    "T1": {"threads": 50, "timeout": 2.0},
    "T2": {"threads": 150, "timeout": 1.2},
    "T3": {"threads": 400, "timeout": 0.6},
    "T4": {"threads": 800, "timeout": 0.3},
    "T5": {"threads": 1500, "timeout": 0.15}
}


def scan_port(ip, port, timeout, use_tor):
    try:
        # Create SOCKS or normal socket
        if use_tor:
            s = socks.socksocket()
            s.set_proxy(
                proxy_type=socks.SOCKS5,
                addr="127.0.0.1",
                port=9050
            )
        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        s.settimeout(timeout)

        result = s.connect_ex((ip, port))

        if result == 0:
            banner = ""
            try:
                banner = s.recv(1024).decode(errors="ignore").strip()
            except:
                pass

            s.close()
            return port, banner

        s.close()

    except Exception:
        return None

    return None


def scan_ip(ip, ports, threads, timeout, use_tor):
    print(f"\n[*] Scanning {ip} | threads={threads} timeout={timeout}s tor={use_tor}")

    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(scan_port, ip, port, timeout, use_tor): port
            for port in ports
        }

        for future in as_completed(futures):
            res = future.result()
            if res:
                port, banner = res
                print(f"[+] {ip}:{port} OPEN  {banner}")
                open_ports.append((port, banner))

    return open_ports


def main():
    parser = argparse.ArgumentParser(description="Fast threaded port scanner with optional Tor proxy")
    parser.add_argument("--ips", required=True, help="File containing IP list")
    parser.add_argument("--mode", choices=["top", "full"],
                        default="top", help="Scan top 10k or full 65535 ports")
    parser.add_argument("--timing", choices=["T1", "T2", "T3", "T4", "T5"],
                        default="T3", help="Timing profile")
    parser.add_argument("--threads", type=int, default=None,
                        help="Override thread count")
    parser.add_argument("--tor", action="store_true",
                        help="Route all scans through Tor SOCKS5 (127.0.0.1:9050)")

    args = parser.parse_args()

    profile = TIMING_PROFILES[args.timing]
    timeout = profile["timeout"]
    threads = args.threads if args.threads else profile["threads"]

    # load IPs
    with open(args.ips, "r") as f:
        ips = [line.strip() for line in f if line.strip()]

    ports = TOP_PORTS if args.mode == "top" else FULL_PORTS

    for ip in ips:
        results = scan_ip(ip, ports, threads, timeout, args.tor)

        print(f"\n[*] Summary for {ip}:")
        for port, banner in results:
            print(f"    Port {port:<6} | Banner: {banner}")
        print("-" * 60)


if __name__ == "__main__":
    print(r"""
       █▓▒░ stealthmap ░▒▓█
    ▄████▄   ▄████▄   ▄████▄   ▄████▄   ▄████▄ 
   ███▀▀███  ███▀▀███ ███▀▀███ ███▀▀███ ███▀▀███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀ 
             by Mr. Robot.txt
    """)
    main()