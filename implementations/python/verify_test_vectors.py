#!/usr/bin/env python3
"""Verify all test vectors from test_vectors.json."""

import json
import ipaddress
from ipcrypt_deterministic import encrypt as deterministic_encrypt, decrypt as deterministic_decrypt
from ipcrypt_nd import encrypt as nd_encrypt, decrypt as nd_decrypt
from ipcrypt_ndx import aes_xts_encrypt, decrypt as ndx_decrypt, ip_to_bytes, bytes_to_ip
from ipcrypt_pfx import encrypt as pfx_encrypt, decrypt as pfx_decrypt


def verify_deterministic(test_vector):
    """Verify a deterministic test vector."""
    key = bytes.fromhex(test_vector["key"])
    ip = test_vector["ip"]
    expected = test_vector["encrypted_ip"]

    # Test encryption
    encrypted = deterministic_encrypt(ip, key)
    result = str(encrypted)

    if result != expected:
        print(f"✗ ipcrypt-deterministic: {ip} -> expected {expected}, got {result}")
        return False

    # Test decryption
    decrypted = deterministic_decrypt(encrypted, key)
    decrypted_str = str(decrypted)

    if decrypted_str != ip:
        print(f"✗ ipcrypt-deterministic decrypt: {encrypted} -> expected {ip}, got {decrypted_str}")
        return False

    print(f"✓ ipcrypt-deterministic: {ip} -> {result} -> {decrypted_str}")
    return True


def verify_nd(test_vector):
    """Verify an nd test vector."""
    key = bytes.fromhex(test_vector["key"])
    ip = test_vector["ip"]
    tweak = bytes.fromhex(test_vector["tweak"])
    expected = test_vector["output"]

    # Test encryption
    encrypted = nd_encrypt(ip, key, tweak)
    result = encrypted.hex()

    if result != expected:
        print(f"✗ ipcrypt-nd: {ip} -> expected {expected}, got {result}")
        return False

    # Test decryption
    decrypted = nd_decrypt(encrypted, key)
    decrypted_str = str(decrypted)

    if decrypted_str != ip:
        print(f"✗ ipcrypt-nd decrypt: {result[:40]}... -> expected {ip}, got {decrypted_str}")
        return False

    print(f"✓ ipcrypt-nd: {ip} -> {result[:40]}... -> {decrypted_str}")
    return True


def verify_ndx(test_vector):
    """Verify an ndx test vector."""
    key = bytes.fromhex(test_vector["key"])
    ip = test_vector["ip"]
    tweak = bytes.fromhex(test_vector["tweak"])
    expected = test_vector["output"]

    # Convert IP to bytes and encrypt with AES-XTS
    plaintext = ip_to_bytes(ip)
    ciphertext = aes_xts_encrypt(key, tweak, plaintext)

    # Concatenate tweak and ciphertext
    result = (tweak + ciphertext).hex()

    if result != expected:
        print(f"✗ ipcrypt-ndx: {ip} -> expected {expected}, got {result}")
        return False

    # Test decryption
    binary_output = bytes.fromhex(result)
    decrypted = ndx_decrypt(binary_output, key)
    decrypted_str = str(decrypted)

    if decrypted_str != ip:
        print(f"✗ ipcrypt-ndx decrypt: {result[:40]}... -> expected {ip}, got {decrypted_str}")
        return False

    print(f"✓ ipcrypt-ndx: {ip} -> {result[:40]}... -> {decrypted_str}")
    return True


def verify_pfx(test_vector):
    """Verify a pfx test vector."""
    key = bytes.fromhex(test_vector["key"])
    ip = test_vector["ip"]
    expected = test_vector["encrypted_ip"]

    # Test encryption
    encrypted = pfx_encrypt(ip, key)
    result = str(encrypted)

    if result != expected:
        print(f"✗ ipcrypt-pfx: {ip} -> expected {expected}, got {result}")
        return False

    # Test decryption
    decrypted = pfx_decrypt(encrypted, key)
    
    # Compare as IP address objects for proper equality check
    original_ip = ipaddress.ip_address(ip)
    if decrypted != original_ip:
        print(f"✗ ipcrypt-pfx decrypt: {encrypted} -> expected {ip}, got {decrypted}")
        return False

    print(f"✓ ipcrypt-pfx: {ip} -> {result} -> {decrypted}")
    return True


def main():
    """Load and verify all test vectors."""
    with open("test_vectors.json", "r") as f:
        test_vectors = json.load(f)

    passed = 0
    failed = 0

    print("Verifying test vectors from test_vectors.json...")
    print("=" * 60)

    for vector in test_vectors:
        variant = vector["variant"]

        if variant == "ipcrypt-deterministic":
            if verify_deterministic(vector):
                passed += 1
            else:
                failed += 1
        elif variant == "ipcrypt-nd":
            if verify_nd(vector):
                passed += 1
            else:
                failed += 1
        elif variant == "ipcrypt-ndx":
            if verify_ndx(vector):
                passed += 1
            else:
                failed += 1
        elif variant == "ipcrypt-pfx":
            if verify_pfx(vector):
                passed += 1
            else:
                failed += 1
        else:
            print(f"Unknown variant: {variant}")
            failed += 1

    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed")

    if failed == 0:
        print("✅ All test vectors verified successfully!")
    else:
        print(f"❌ {failed} test vector(s) failed verification")
        exit(1)


if __name__ == "__main__":
    main()
