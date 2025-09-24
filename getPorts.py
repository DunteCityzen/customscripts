import sys

if len(sys.argv) != 2:
    print(f"[-] Syntax: python {sys.argv[0]} <nmap ports file>")
    sys.exit()

nmapfile = str(sys.argv[1])
lines = []
ports = []

with open(nmapfile, 'r', encoding='utf-8-sig') as f:
    unstripedlines = f.readlines()
    for unstripedline in unstripedlines:
        if "/" in unstripedline.strip() and '#' not in unstripedline.strip():
            lines.append(unstripedline.strip())
        else:
            continue

for line in lines:
    port = line.split('/')
    ports.append(port[0])

for nport in ports:
    print(nport, end=",")