"""
AEGIS CRYPT - Core Encryption Engine
=====================================
AES-256-GCM authenticated, chunked streaming file encryption.

File format (".axc" - AEGIS eXtended Container):

    MAGIC        9 bytes   b"AEGISCRY1"
    N_LOG2       1 byte    scrypt CPU/memory cost, log2(N)
    R            1 byte    scrypt block size parameter
    P            1 byte    scrypt parallelization parameter
    SALT         16 bytes  random KDF salt
    CHUNK_SIZE   4 bytes   big-endian uint32, plaintext bytes per chunk
    ---- repeated for each chunk until EOF ----
    NONCE        12 bytes  random, unique per chunk
    LENGTH       4 bytes   big-endian uint32, ciphertext+tag length
    CIPHERTEXT   variable  AES-256-GCM output (includes 16-byte tag)

Security design notes:
  * Key derivation uses scrypt (memory-hard) to slow down brute force
    and GPU/ASIC-accelerated password guessing.
  * Each chunk gets its own randomly generated 96-bit nonce, so nonce
    reuse under the same key is not a practical concern for realistic
    file sizes (birthday-bound collision risk is negligible below
    billions of chunks).
  * Each chunk's Additional Authenticated Data (AAD) binds the chunk's
    index and a "final chunk" flag into the authentication tag. This
    means an attacker cannot truncate, reorder, or splice chunks
    (including silently dropping the true final chunk) without the
    decryption failing loudly.
  * Decryption verifies the GCM tag before any plaintext is written to
    the output file for that chunk, and refuses to finish successfully
    unless a chunk explicitly flagged "final" was reached.
"""

from __future__ import annotations

import os
import struct
import secrets
from dataclasses import dataclass
from typing import Callable, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b"AEGISCRY1"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32  # AES-256
TAG_SIZE = 16
DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB plaintext per chunk

# scrypt cost parameters. N is stored as log2(N) so it fits in one byte
# and can be tuned upward in future format versions without breaking
# the header layout.
DEFAULT_N_LOG2 = 17  # N = 131072
DEFAULT_R = 8
DEFAULT_P = 1

HEADER_STRUCT = struct.Struct(">9sBBB16sI")  # magic, n_log2, r, p, salt, chunk_size


class AegisError(Exception):
    """Base class for all AEGIS CRYPT errors."""


class InvalidPassword(AegisError):
    """Raised when authentication fails (wrong password or tampered file)."""


class CorruptFile(AegisError):
    """Raised when the container is malformed, truncated, or not ours."""


class UnsupportedFormat(AegisError):
    """Raised when the file magic does not match a known AEGIS container."""


@dataclass
class Progress:
    bytes_done: int
    bytes_total: int

    @property
    def fraction(self) -> float:
        if self.bytes_total <= 0:
            return 1.0
        return min(1.0, self.bytes_done / self.bytes_total)


ProgressCallback = Optional[Callable[[Progress], None]]


def _derive_key(password: str, salt: bytes, n_log2: int, r: int, p: int) -> bytes:
    if not password:
        raise ValueError("Password must not be empty.")
    kdf = Scrypt(salt=salt, length=KEY_SIZE, n=2 ** n_log2, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def _chunk_aad(index: int, is_last: bool) -> bytes:
    """Binds chunk position and finality into the authenticated data."""
    return MAGIC + struct.pack(">Q", index) + (b"\x01" if is_last else b"\x00")


def encrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    progress_cb: ProgressCallback = None,
    overwrite: bool = False,
) -> None:
    """Encrypt input_path into output_path as an AEGIS container."""
    if not overwrite and os.path.exists(output_path):
        raise FileExistsError(f"Output file already exists: {output_path}")
    if chunk_size <= 0 or chunk_size > (1 << 32) - 1:
        raise ValueError("chunk_size out of range.")

    salt = secrets.token_bytes(SALT_SIZE)
    key = _derive_key(password, salt, DEFAULT_N_LOG2, DEFAULT_R, DEFAULT_P)
    aesgcm = AESGCM(key)

    total = os.path.getsize(input_path)
    done = 0
    tmp_path = output_path + ".part"

    try:
        with open(input_path, "rb") as fin, open(tmp_path, "wb") as fout:
            fout.write(
                HEADER_STRUCT.pack(
                    MAGIC, DEFAULT_N_LOG2, DEFAULT_R, DEFAULT_P, salt, chunk_size
                )
            )

            index = 0
            chunk = fin.read(chunk_size)
            while True:
                next_chunk = fin.read(chunk_size)
                is_last = len(next_chunk) == 0
                nonce = secrets.token_bytes(NONCE_SIZE)
                aad = _chunk_aad(index, is_last)
                ct = aesgcm.encrypt(nonce, chunk, aad)
                fout.write(nonce)
                fout.write(struct.pack(">I", len(ct)))
                fout.write(ct)

                done += len(chunk)
                if progress_cb:
                    progress_cb(Progress(done, total))

                if is_last:
                    break
                chunk = next_chunk
                index += 1
        os.replace(tmp_path, output_path)
    finally:
        if os.path.exists(tmp_path):
            try:
                os.remove(tmp_path)
            except OSError:
                pass
    key_wipe = bytearray(key)
    for i in range(len(key_wipe)):
        key_wipe[i] = 0


def decrypt_file(
    input_path: str,
    output_path: str,
    password: str,
    progress_cb: ProgressCallback = None,
    overwrite: bool = False,
) -> None:
    """Decrypt an AEGIS container back into output_path."""
    if not overwrite and os.path.exists(output_path):
        raise FileExistsError(f"Output file already exists: {output_path}")

    total = os.path.getsize(input_path)
    done = 0
    tmp_path = output_path + ".part"

    with open(input_path, "rb") as fin:
        header_bytes = fin.read(HEADER_STRUCT.size)
        if len(header_bytes) != HEADER_STRUCT.size:
            raise CorruptFile("File is too short to be a valid AEGIS container.")

        magic, n_log2, r, p, salt, chunk_size = HEADER_STRUCT.unpack(header_bytes)
        if magic != MAGIC:
            raise UnsupportedFormat("This file is not an AEGIS CRYPT container.")
        if not (1 <= n_log2 <= 30) or r <= 0 or p <= 0:
            raise CorruptFile("Container header parameters are invalid.")

        key = _derive_key(password, salt, n_log2, r, p)
        aesgcm = AESGCM(key)
        done += HEADER_STRUCT.size

        reached_final = False
        try:
            with open(tmp_path, "wb") as fout:
                index = 0
                while True:
                    prefix = fin.read(NONCE_SIZE + 4)
                    if len(prefix) == 0:
                        break
                    if len(prefix) != NONCE_SIZE + 4:
                        raise CorruptFile("Unexpected end of file inside a chunk header.")
                    nonce = prefix[:NONCE_SIZE]
                    (ct_len,) = struct.unpack(">I", prefix[NONCE_SIZE:])
                    ct = fin.read(ct_len)
                    if len(ct) != ct_len:
                        raise CorruptFile("Unexpected end of file inside chunk data.")

                    next_pos = fin.tell()
                    lookahead = fin.read(1)
                    fin.seek(next_pos)
                    is_last = len(lookahead) == 0

                    aad = _chunk_aad(index, is_last)
                    try:
                        pt = aesgcm.decrypt(nonce, ct, aad)
                    except Exception as exc:
                        raise InvalidPassword(
                            "Decryption failed: wrong password, or the file is "
                            "corrupted / has been tampered with."
                        ) from exc

                    fout.write(pt)
                    done += NONCE_SIZE + 4 + ct_len
                    if progress_cb:
                        progress_cb(Progress(done, total))

                    if is_last:
                        reached_final = True
                        break
                    index += 1

            if not reached_final:
                raise CorruptFile(
                    "File ended before the final authenticated chunk was reached "
                    "(the file is truncated or has been tampered with)."
                )
            os.replace(tmp_path, output_path)
        finally:
            if os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

    key_wipe = bytearray(key)
    for i in range(len(key_wipe)):
        key_wipe[i] = 0


def is_aegis_container(path: str) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(len(MAGIC)) == MAGIC
    except OSError:
        return False
