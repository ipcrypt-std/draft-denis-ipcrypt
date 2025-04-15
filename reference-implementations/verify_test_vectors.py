#!/usr/bin/env python3
"""
Verify test vectors from the document against our implementation.
"""

import binascii
from ipcrypt_deterministic import encrypt as det_encrypt, decrypt as det_decrypt
from ipcrypt_nd import encrypt as nd_encrypt, decrypt as nd_decrypt
from ipcrypt_ndx import encrypt as ndx_encrypt, decrypt as ndx_decrypt


def verify_deterministic_vectors():
    """Verify ipcrypt-deterministic test vectors."""
    print("\nVerifying ipcrypt-deterministic test vectors:")

    # Test vector 1
    key = binascii.unhexlify("0123456789abcdeffedcba9876543210")
    ip = "0.0.0.0"
    expected = "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb"
    encrypted = det_encrypt(ip, key)
    print(f"Test vector 1: {ip} -> {encrypted}")
    print(f"Expected: {expected}")
    print(f"Match: {str(encrypted) == expected}")

    # Test vector 2
    key = binascii.unhexlify("1032547698badcfeefcdab8967452301")
    ip = "255.255.255.255"
    expected = "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8"
    encrypted = det_encrypt(ip, key)
    print(f"Test vector 2: {ip} -> {encrypted}")
    print(f"Expected: {expected}")
    print(f"Match: {str(encrypted) == expected}")

    # Test vector 3
    key = binascii.unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
    ip = "192.0.2.1"
    expected = "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777"
    encrypted = det_encrypt(ip, key)
    print(f"Test vector 3: {ip} -> {encrypted}")
    print(f"Expected: {expected}")
    print(f"Match: {str(encrypted) == expected}")


def verify_nd_vectors():
    """Verify ipcrypt-nd test vectors."""
    print("\nVerifying ipcrypt-nd test vectors:")

    # Test vector 1
    key = binascii.unhexlify("0123456789abcdeffedcba9876543210")
    ip = "0.0.0.0"
    tweak = binascii.unhexlify("08e0c289bff23b7c")
    expected = "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16"

    # Use the tweak directly in the encryption
    from ipcrypt_nd import kiasu_bc_encrypt, ip_to_bytes
    plaintext = ip_to_bytes(ip)
    ciphertext = kiasu_bc_encrypt(key, tweak, plaintext)
    output = tweak + ciphertext
    output_hex = binascii.hexlify(output).decode()

    print(f"Test vector 1: {ip} -> {output_hex}")
    print(f"Expected: {expected}")
    print(f"Match: {output_hex == expected}")

    # Test vector 2
    key = binascii.unhexlify("1032547698badcfeefcdab8967452301")
    ip = "192.0.2.1"
    tweak = binascii.unhexlify("21bd1834bc088cd2")
    expected = "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad"

    plaintext = ip_to_bytes(ip)
    ciphertext = kiasu_bc_encrypt(key, tweak, plaintext)
    output = tweak + ciphertext
    output_hex = binascii.hexlify(output).decode()

    print(f"Test vector 2: {ip} -> {output_hex}")
    print(f"Expected: {expected}")
    print(f"Match: {output_hex == expected}")

    # Test vector 3
    key = binascii.unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
    ip = "2001:db8::1"
    tweak = binascii.unhexlify("b4ecbe30b70898d7")
    expected = "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96"

    plaintext = ip_to_bytes(ip)
    ciphertext = kiasu_bc_encrypt(key, tweak, plaintext)
    output = tweak + ciphertext
    output_hex = binascii.hexlify(output).decode()

    print(f"Test vector 3: {ip} -> {output_hex}")
    print(f"Expected: {expected}")
    print(f"Match: {output_hex == expected}")


def verify_ndx_vectors():
    """Verify ipcrypt-ndx test vectors."""
    print("\nVerifying ipcrypt-ndx test vectors:")

    # Test vector 1
    key = binascii.unhexlify(
        "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301")
    ip = "0.0.0.0"
    tweak = binascii.unhexlify("21bd1834bc088cd2b4ecbe30b70898d7")
    expected = "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5"

    # Use the tweak directly in the encryption
    from ipcrypt_ndx import aes_xts_encrypt, ip_to_bytes
    plaintext = ip_to_bytes(ip)
    ciphertext = aes_xts_encrypt(key, tweak, plaintext)
    output = tweak + ciphertext
    output_hex = binascii.hexlify(output).decode()

    print(f"Test vector 1: {ip} -> {output_hex}")
    print(f"Expected: {expected}")
    print(f"Match: {output_hex == expected}")

    # Test vector 2
    key = binascii.unhexlify(
        "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210")
    ip = "192.0.2.1"
    tweak = binascii.unhexlify("08e0c289bff23b7cb4ecbe30b70898d7")
    expected = "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a"

    plaintext = ip_to_bytes(ip)
    ciphertext = aes_xts_encrypt(key, tweak, plaintext)
    output = tweak + ciphertext
    output_hex = binascii.hexlify(output).decode()

    print(f"Test vector 2: {ip} -> {output_hex}")
    print(f"Expected: {expected}")
    print(f"Match: {output_hex == expected}")

    # Test vector 3
    key = binascii.unhexlify(
        "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b")
    ip = "2001:db8::1"
    tweak = binascii.unhexlify("21bd1834bc088cd2b4ecbe30b70898d7")
    expected = "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4"

    plaintext = ip_to_bytes(ip)
    ciphertext = aes_xts_encrypt(key, tweak, plaintext)
    output = tweak + ciphertext
    output_hex = binascii.hexlify(output).decode()

    print(f"Test vector 3: {ip} -> {output_hex}")
    print(f"Expected: {expected}")
    print(f"Match: {output_hex == expected}")


def main():
    """Verify all test vectors."""
    verify_deterministic_vectors()
    verify_nd_vectors()
    verify_ndx_vectors()


if __name__ == '__main__':
    main()
