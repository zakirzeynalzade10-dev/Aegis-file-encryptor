import os
import secrets
import sys

sys.path.insert(0, os.path.dirname(__file__))
import aegis_core as core


def test_roundtrip_small():
    data = b"Hello, AEGIS CRYPT! " * 3
    with open("/tmp/plain.bin", "wb") as f:
        f.write(data)
    core.encrypt_file("/tmp/plain.bin", "/tmp/enc.axc", "correct horse battery staple", overwrite=True)
    core.decrypt_file("/tmp/enc.axc", "/tmp/dec.bin", "correct horse battery staple", overwrite=True)
    with open("/tmp/dec.bin", "rb") as f:
        assert f.read() == data
    print("PASS: small roundtrip")


def test_roundtrip_multichunk():
    data = secrets.token_bytes(5_000_000)  # forces multiple chunks at small chunk size
    with open("/tmp/plain2.bin", "wb") as f:
        f.write(data)
    core.encrypt_file("/tmp/plain2.bin", "/tmp/enc2.axc", "pw123!", chunk_size=1_000_000, overwrite=True)
    core.decrypt_file("/tmp/enc2.axc", "/tmp/dec2.bin", "pw123!", overwrite=True)
    with open("/tmp/dec2.bin", "rb") as f:
        assert f.read() == data
    print("PASS: multi-chunk roundtrip (5MB, 1MB chunks)")


def test_empty_file():
    open("/tmp/empty.bin", "wb").close()
    core.encrypt_file("/tmp/empty.bin", "/tmp/empty.axc", "pw", overwrite=True)
    core.decrypt_file("/tmp/empty.axc", "/tmp/empty_out.bin", "pw", overwrite=True)
    assert os.path.getsize("/tmp/empty_out.bin") == 0
    print("PASS: empty file roundtrip")


def test_wrong_password():
    try:
        core.decrypt_file("/tmp/enc.axc", "/tmp/dec_wrong.bin", "totally wrong password", overwrite=True)
        print("FAIL: wrong password did not raise")
    except core.InvalidPassword:
        print("PASS: wrong password rejected")


def test_truncation_detected():
    with open("/tmp/enc2.axc", "rb") as f:
        full = f.read()
    truncated = full[: len(full) - 50]  # chop off end of the last chunk
    with open("/tmp/trunc.axc", "wb") as f:
        f.write(truncated)
    try:
        core.decrypt_file("/tmp/trunc.axc", "/tmp/trunc_out.bin", "pw123!", overwrite=True)
        print("FAIL: truncation was not detected")
    except (core.CorruptFile, core.InvalidPassword):
        print("PASS: truncation detected")


def test_tamper_detected():
    with open("/tmp/enc.axc", "rb") as f:
        data = bytearray(f.read())
    data[-1] ^= 0xFF  # flip a bit in the ciphertext/tag
    with open("/tmp/tampered.axc", "wb") as f:
        f.write(data)
    try:
        core.decrypt_file("/tmp/tampered.axc", "/tmp/tampered_out.bin", "correct horse battery staple", overwrite=True)
        print("FAIL: tampering was not detected")
    except core.InvalidPassword:
        print("PASS: tampering detected")


def test_not_our_format():
    with open("/tmp/notours.bin", "wb") as f:
        f.write(b"just some random bytes that are not an AEGIS container")
    try:
        core.decrypt_file("/tmp/notours.bin", "/tmp/notours_out.bin", "pw", overwrite=True)
        print("FAIL: bad format not detected")
    except core.UnsupportedFormat:
        print("PASS: non-AEGIS file rejected")


if __name__ == "__main__":
    test_roundtrip_small()
    test_roundtrip_multichunk()
    test_empty_file()
    test_wrong_password()
    test_truncation_detected()
    test_tamper_detected()
    test_not_our_format()
    print("\nAll tests completed.")
