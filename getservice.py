#!/bin/python3

import socket
import threading
import sys

if len(sys.argv) < 4:
	print("[-]Syntax: python getservice.py <port> <allIPsfile> <outfile>")
	exit(-1)

# Define the port to check
PORT = int(sys.argv[1])

# Define file names
input_file = sys.argv[2]
output_file = sys.argv[3]

# List to store open IP addresses
open_ips = []

# Lock for synchronizing access to the shared list
lock = threading.Lock()

def check_port(ip, port):
    """Check if a specific port is open on a given IP address."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)  # Set a timeout for the connection attempt
        try:
            s.connect((ip, port))
            return True
        except (socket.timeout, socket.error):
            return False

def worker(ip):
    """Worker function to check port and update shared list."""
    if check_port(ip, PORT):
        with lock:
            open_ips.append(ip)

# Read IPs from the input file
with open(input_file, 'r') as infile:
    ips = [line.strip() for line in infile]

# Create and start threads
threads = []
for ip in ips:
    thread = threading.Thread(target=worker, args=(ip,))
    thread.start()
    threads.append(thread)

# Wait for all threads to complete
for thread in threads:
    thread.join()

# Write the results to the output file
with open(output_file, 'w') as outfile:
    for ip in open_ips:
        outfile.write(f'{ip}\n')

print("Port checking complete. Results written to", output_file)
