#!/usr/bin/env python3
"""
aescrypt_bruteforce.py
Fast multiprocessing/brute-force utility for pyAesCrypt `.aes` files using a wordlist.
- Uses multiprocessing Pool to use multiple CPU cores (avoids GIL issues by forking processes).
- Each worker receives a chunk of candidate passwords and tries them sequentially.
- On success, prints the found password and exits early (workers terminate).
- Writes a short log of attempts and supports resuming by skipping an initial line offset.
Requirements:
    pip install pyAesCrypt tqdm
Usage:
    python3 aescrypt_bruteforce.py --enc /path/to/file.aes --wordlist rockyou.txt --workers 6 --buf 65536
Notes:
    - This script decrypts to a temporary file per attempt and removes it on failure.
    - For large wordlists and GPUs, consider converting to hashcat format (advanced).
    - Test with small wordlist first to validate environment.
"""

import argparse
import pyAesCrypt
import tempfile
import os
import sys
from multiprocessing import Pool, Manager, Event
from functools import partial
from tqdm import tqdm

BUFFER_DEFAULT = 64 * 1024

def try_passwords_chunk(enc_path, passwords, buffer_size, found_event, result_dict):
    """
    Worker: try a sequential list of candidate passwords.
    If one succeeds, set found_event and write result_dict['password'].
    """
    # If already found by another worker, exit early
    if found_event.is_set():
        return None

    for pw in passwords:
        if found_event.is_set():
            return None
        pw = pw.rstrip("\n\r")
        if pw == "":
            continue
        # use a named temporary file for the decrypted output
        fd, outpath = tempfile.mkstemp(prefix="aes_try_", suffix=".out")
        os.close(fd)
        try:
            # pyAesCrypt will raise on bad password / integrity fail
            pyAesCrypt.decryptFile(enc_path, outpath, pw, buffer_size)
            # If decryptFile returns without exception, password is correct
            result_dict['password'] = pw
            result_dict['outpath'] = outpath
            found_event.set()
            return pw
        except Exception:
            # remove output file on failure if it exists
            try:
                os.remove(outpath)
            except Exception:
                pass
            continue
    return None

def chunked_iterable(fileobj, chunk_size):
    """Yield lists of lines (chunk_size) from a file object (generator)."""
    chunk = []
    for line in fileobj:
        chunk.append(line)
        if len(chunk) >= chunk_size:
            yield chunk
            chunk = []
    if chunk:
        yield chunk

def main():
    parser = argparse.ArgumentParser(description="Multicore AES Crypt (.aes) brute-forcer using pyAesCrypt")
    parser.add_argument("--enc", required=True, help="Path to .aes encrypted file")
    parser.add_argument("--wordlist", required=True, help="Path to candidate wordlist (one password per line)")
    parser.add_argument("--workers", type=int, default=4, help="Number of worker processes (default: 4)")
    parser.add_argument("--chunk-size", type=int, default=1024, help="Number of passwords sent to a worker per task (default: 1024)")
    parser.add_argument("--buf", type=int, default=BUFFER_DEFAULT, help="pyAesCrypt buffer size in bytes (default: BUFFER_DEFAULT)")
    parser.add_argument("--skip", type=int, default=0, help="Skip first N lines of the wordlist (for resume)")
    args = parser.parse_args()

    enc_path = args.enc
    wordlist_path = args.wordlist
    workers = max(1, args.workers)
    chunk_size = max(1, args.chunk_size)
    buffer_size = args.buf
    skip = max(0, args.skip)

    if not os.path.isfile(enc_path):
        print("Encrypted file not found:", enc_path, file=sys.stderr); sys.exit(2)
    if not os.path.isfile(wordlist_path):
        print("Wordlist not found:", wordlist_path, file=sys.stderr); sys.exit(2)

    manager = Manager()
    found_event = manager.Event()
    result_dict = manager.dict()

    # Create pool of worker processes
    pool = Pool(processes=workers)

    try:
        # We will stream the wordlist and submit chunks to the pool to avoid high memory usage
        with open(wordlist_path, "r", errors="ignore") as wf:
            # skip lines if requested
            for _ in range(skip):
                wf.readline()

            # Count total lines for progress bar if possible (best-effort)
            try:
                total_lines = sum(1 for _ in open(wordlist_path, "rb"))
            except Exception:
                total_lines = None

            # Reopen and skip again to position to start
            wf.seek(0)
            for _ in range(skip):
                wf.readline()

            # Prepare iterable of chunks
            chunk_iter = chunked_iterable(wf, chunk_size)
            submitted = 0
            pbar = tqdm(total=total_lines, unit="pw", desc="Passwords", leave=True) if total_lines else tqdm(unit="pw", desc="Passwords", leave=True)
            for chunk in chunk_iter:
                if found_event.is_set():
                    break
                # submit a chunk to the pool using apply_async
                pool.apply_async(try_passwords_chunk, args=(enc_path, chunk, buffer_size, found_event, result_dict))
                submitted += len(chunk)
                pbar.update(len(chunk))
                # Small check to break early if found
                if found_event.is_set():
                    break

            # close pbar
            pbar.close()

            # Wait for workers to finish or for found_event
            pool.close()
            pool.join()

            if found_event.is_set() and 'password' in result_dict:
                print("[+] Password FOUND:", result_dict['password'])
                print("[+] Decrypted output path:", result_dict.get('outpath'))
                sys.exit(0)
            else:
                print("[-] Password not found in wordlist (or run was interrupted).")
                sys.exit(1)

    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Terminating workers...")
        pool.terminate()
        pool.join()
        sys.exit(130)
    except Exception as e:
        print("[!] Error:", str(e), file=sys.stderr)
        pool.terminate()
        pool.join()
        sys.exit(2)

if __name__ == "__main__":
    main()
