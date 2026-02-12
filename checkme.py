#!/usr/bin/env python3

import argparse
import requests
import json
import sys
from pathlib import Path

BANNER = r"""
       █▓▒░ checkme ░▒▓█ 
    ▄████▄   ▄████▄   ▄████▄   ▄████▄   ▄████▄ 
   ███▀▀███  ███▀▀███ ███▀▀███ ███▀▀███ ███▀▀███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀ 
             by Mr. Robot.txt
"""

BASE_URL = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools"

HEADERS = {
    "User-Agent": "Mozilla/5.0",
    "Accept": "application/json"
}


# -----------------------------

def pretty(data):
    print(json.dumps(data, indent=4))


def load_file(path):
    try:
        with open(path) as f:
            return [x.strip() for x in f if x.strip()]
    except Exception as e:
        print(f"[!] Could not read file {path}: {e}")
        sys.exit(1)


def build_proxy(proxy_string):
    if not proxy_string:
        return None

    return {
        "http": proxy_string,
        "https": proxy_string
    }


def request_lookup(endpoint, key, value, proxies):
    url = f"{BASE_URL}/{endpoint}"

    try:
        r = requests.get(
            url,
            headers=HEADERS,
            params={key: value},
            proxies=proxies,
            timeout=15
        )
        r.raise_for_status()
        return r.json()

    except Exception as e:
        return {"error": str(e)}


# -----------------------------

def main():
    print(BANNER)

    parser = argparse.ArgumentParser()

    # single
    parser.add_argument("--email")
    parser.add_argument("--domain")
    parser.add_argument("--username")

    # batch
    parser.add_argument("--emailFile")
    parser.add_argument("--domainFile")
    parser.add_argument("--usernameFile")

    parser.add_argument("--proxy", help="http:// or socks5://")
    parser.add_argument("--output", help="Save JSON results to file")

    args = parser.parse_args()

    proxies = build_proxy(args.proxy)

    jobs = []

    # Single inputs
    if args.email:
        jobs.append(("search-by-email", "email", args.email))

    if args.domain:
        jobs.append(("search-by-domain", "domain", args.domain))

    if args.username:
        jobs.append(("search-by-username", "username", args.username))

    # File inputs
    if args.emailFile:
        for item in load_file(args.emailFile):
            jobs.append(("search-by-email", "email", item))

    if args.domainFile:
        for item in load_file(args.domainFile):
            jobs.append(("search-by-domain", "domain", item))

    if args.usernameFile:
        for item in load_file(args.usernameFile):
            jobs.append(("search-by-username", "username", item))

    if not jobs:
        parser.print_help()
        sys.exit(1)

    results = []

    for endpoint, key, value in jobs:
        print(f"\n[+] Checking {key}: {value}")

        data = request_lookup(endpoint, key, value, proxies)

        entry = {
            "type": key,
            "value": value,
            "response": data
        }

        pretty(entry)
        results.append(entry)

    # Save output
    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=4)
        print(f"\n[+] Results saved to {args.output}")


if __name__ == "__main__":
    main()
