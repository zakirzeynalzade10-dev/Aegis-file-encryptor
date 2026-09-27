"""
AEGIS CRYPT - Command Line Interface
=====================================
Usage:
    python aegis.py encrypt -i secret.docx
    python aegis.py encrypt -i secret.docx -o secret.axc
    python aegis.py decrypt -i secret.axc -o secret.docx
    python aegis.py encrypt -i C:\\Documents\\ -r          (recursive, whole folder)
    python aegis.py info -i secret.axc

Passwords are never accepted as a plain command-line argument (they would
leak into shell history and process listings). Use the interactive prompt,
or --password-file to read a password from a file (e.g. for automation).
"""

from __future__ import annotations

import argparse
import getpass
import os
import sys
import time

import aegis_core as core

BANNER = r"""
   ▄████████    ▄████████    ▄██████▄   ▄█     █▄     ▄████████
  ███    ███   ███    ███   ███    ███ ███     ███   ███    ███
  ███    ███   ███    █▀    ███    █▀  ███     ███   ███    █▀
  ███    ███  ▄███▄▄▄       ███       ▄███▄▄▄▄███▄▄  ███
▀███████████ ▀▀███▀▀▀       ███      ▀▀███▀▀▀▀███▀  ▀███████████
  ███    ███   ███    █▄    ███    █▄  ███     ███          ███
  ███    ███   ███    ███   ███    ███ ███     ███    ▄█    ███
  ███    █▀    ██████████   ████████▀  ███     █▀   ▄████████▀
                    AES-256 FILE ENCRYPTION SYSTEM // CLI v1.0
"""


def _read_password(args, confirm: bool) -> str:
    if args.password_file:
        with open(args.password_file, "r", encoding="utf-8") as f:
            return f.readline().rstrip("\n\r")
    pw = getpass.getpass("Passphrase: ")
    if confirm:
        pw2 = getpass.getpass("Confirm passphrase: ")
        if pw != pw2:
            print("[!] Passphrases do not match.", file=sys.stderr)
            sys.exit(2)
    if len(pw) < 8:
        print("[!] Warning: passphrases under 8 characters are weak.", file=sys.stderr)
    return pw


def _progress_printer(label: str):
    start = time.time()

    def cb(p: core.Progress):
        pct = p.fraction * 100
        elapsed = time.time() - start
        rate = (p.bytes_done / elapsed / 1_000_000) if elapsed > 0 else 0
        bar_len = 30
        filled = int(bar_len * p.fraction)
        bar = "█" * filled + "░" * (bar_len - filled)
        sys.stdout.write(f"\r[{bar}] {pct:6.2f}%  {rate:6.1f} MB/s  {label}")
        sys.stdout.flush()
        if p.fraction >= 1.0:
            sys.stdout.write("\n")

    return cb


def _iter_target_files(path: str, recursive: bool):
    if os.path.isfile(path):
        yield path
    elif os.path.isdir(path):
        if not recursive:
            print(f"[!] {path} is a directory. Use -r/--recursive to process folders.", file=sys.stderr)
            sys.exit(2)
        for root, _dirs, files in os.walk(path):
            for name in files:
                yield os.path.join(root, name)
    else:
        print(f"[!] Path not found: {path}", file=sys.stderr)
        sys.exit(2)


def cmd_encrypt(args) -> int:
    password = _read_password(args, confirm=True)
    targets = list(_iter_target_files(args.input, args.recursive))
    exit_code = 0
    for src in targets:
        if src.endswith(".axc"):
            continue
        if args.output and len(targets) == 1:
            dst = args.output
        else:
            dst = src + ".axc"
        try:
            core.encrypt_file(
                src, dst, password,
                chunk_size=args.chunk_size,
                progress_cb=_progress_printer(os.path.basename(src)),
                overwrite=args.force,
            )
            print(f"[+] Encrypted: {src} -> {dst}")
            if args.delete_original:
                os.remove(src)
        except FileExistsError:
            print(f"[!] Skipped (exists, use --force): {dst}", file=sys.stderr)
            exit_code = 1
        except core.AegisError as e:
            print(f"[!] Error encrypting {src}: {e}", file=sys.stderr)
            exit_code = 1
    return exit_code


def cmd_decrypt(args) -> int:
    password = _read_password(args, confirm=False)
    targets = list(_iter_target_files(args.input, args.recursive))
    exit_code = 0
    for src in targets:
        if not core.is_aegis_container(src):
            print(f"[!] Skipped (not an AEGIS container): {src}", file=sys.stderr)
            continue
        if args.output and len(targets) == 1:
            dst = args.output
        elif src.endswith(".axc"):
            dst = src[: -len(".axc")]
        else:
            dst = src + ".decrypted"
        try:
            core.decrypt_file(
                src, dst, password,
                progress_cb=_progress_printer(os.path.basename(src)),
                overwrite=args.force,
            )
            print(f"[+] Decrypted: {src} -> {dst}")
            if args.delete_original:
                os.remove(src)
        except FileExistsError:
            print(f"[!] Skipped (exists, use --force): {dst}", file=sys.stderr)
            exit_code = 1
        except core.InvalidPassword as e:
            print(f"[!] {src}: {e}", file=sys.stderr)
            exit_code = 1
        except core.AegisError as e:
            print(f"[!] Error decrypting {src}: {e}", file=sys.stderr)
            exit_code = 1
    return exit_code


def cmd_info(args) -> int:
    if not core.is_aegis_container(args.input):
        print("Not an AEGIS CRYPT container.")
        return 1
    size = os.path.getsize(args.input)
    print(f"File:   {args.input}")
    print(f"Size:   {size:,} bytes")
    print("Format: AEGIS CRYPT v1 (AES-256-GCM, scrypt KDF, per-chunk authentication)")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="aegis",
        description="AEGIS CRYPT - military-grade AES-256 file encryption.",
    )
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("-i", "--input", required=True, help="File or folder to process.")
    common.add_argument("-o", "--output", help="Output path (single-file operations only).")
    common.add_argument("-r", "--recursive", action="store_true", help="Process a folder recursively.")
    common.add_argument("-f", "--force", action="store_true", help="Overwrite existing output files.")
    common.add_argument("--delete-original", action="store_true", help="Delete the source file after success.")
    common.add_argument("--password-file", help="Read passphrase from this file instead of prompting.")

    pe = sub.add_parser("encrypt", parents=[common], help="Encrypt a file or folder.")
    pe.add_argument("--chunk-size", type=int, default=core.DEFAULT_CHUNK_SIZE, help="Plaintext bytes per chunk.")
    pe.set_defaults(func=cmd_encrypt)

    pd = sub.add_parser("decrypt", parents=[common], help="Decrypt a file or folder.")
    pd.set_defaults(func=cmd_decrypt)

    pi = sub.add_parser("info", help="Show container metadata without decrypting.")
    pi.add_argument("-i", "--input", required=True)
    pi.set_defaults(func=cmd_info)

    return p


def main(argv=None) -> int:
    print(BANNER)
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
