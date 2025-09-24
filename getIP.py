#!/bin/python3

import re
import sys

if len(sys.argv) < 3:
	print("[-]Syntax: python getIP.py <nmap_outfile> <IPs.txt>")
	exit(-1)
	
inputfile = str(sys.argv[1])
outputfile = str(sys.argv[2])

# Regular expression pattern for matching IP addresses
ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')

# List to store found IP addresses
ip_addresses = []

# Open the input file to read from
with open(inputfile, 'r', encoding='utf-8-sig') as infile:
    # Go through each line in the file
    for line in infile:
        # Find all IP addresses in the line
        matches = ip_pattern.findall(line)
        if matches:
            # Add found IP addresses to the list
            ip_addresses.extend(matches)

# Open the output file to write the IP addresses
with open(outputfile, 'w', encoding='utf-8-sig') as outfile:
    # Write each IP address to the output file
    for ip in ip_addresses:
        outfile.write(ip + '\n')

print("IP addresses extraction complete")
