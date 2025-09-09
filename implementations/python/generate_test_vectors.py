#!/usr/bin/env python3
"""
Generate test vectors for all ipcrypt variants:
- ipcrypt-deterministic (AES128)
- ipcrypt-nd (KIASU-BC)
- ipcrypt-ndx (AES-XTS)
- ipcrypt-pfx (Prefix-preserving)
"""

import json
import binascii
import ipaddress
from ipcrypt_deterministic import (
    encrypt as det_encrypt,
    decrypt as det_decrypt,
    ip_to_bytes,
)
from ipcrypt_nd import decrypt as nd_decrypt, kiasu_bc_encrypt
from ipcrypt_ndx import decrypt as ndx_decrypt, aes_xts_encrypt
from ipcrypt_pfx import encrypt as pfx_encrypt, decrypt as pfx_decrypt


def normalize_ip(ip):
    """Convert IPv4-mapped IPv6 addresses to IPv4 addresses."""
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        return ip.ipv4_mapped
    return ip


def generate_test_vectors():
    """Generate test vectors for all ipcrypt variants."""
    vectors = []

    # Keys for ipcrypt-pfx (32 bytes)
    pfx_keys = [
        bytes.fromhex(
            "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301"
        ),
        bytes.fromhex(
            "2b7e151628aed2a6abf7158809cf4f3ca9f5ba40db214c3798f2e1c23456789a"
        ),
    ]

    keys_16 = [
        bytes(
            [
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xAB,
                0xCD,
                0xEF,
                0xFE,
                0xDC,
                0xBA,
                0x98,
                0x76,
                0x54,
                0x32,
                0x10,
            ]
        ),
        bytes(
            [
                0x10,
                0x32,
                0x54,
                0x76,
                0x98,
                0xBA,
                0xDC,
                0xFE,
                0xEF,
                0xCD,
                0xAB,
                0x89,
                0x67,
                0x45,
                0x23,
                0x01,
            ]
        ),
        bytes(
            [
                0x2B,
                0x7E,
                0x15,
                0x16,
                0x28,
                0xAE,
                0xD2,
                0xA6,
                0xAB,
                0xF7,
                0x15,
                0x88,
                0x09,
                0xCF,
                0x4F,
                0x3C,
            ]
        ),
    ]

    keys_32 = [
        bytes(
            [
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xAB,
                0xCD,
                0xEF,
                0xFE,
                0xDC,
                0xBA,
                0x98,
                0x76,
                0x54,
                0x32,
                0x10,
                0x10,
                0x32,
                0x54,
                0x76,
                0x98,
                0xBA,
                0xDC,
                0xFE,
                0xEF,
                0xCD,
                0xAB,
                0x89,
                0x67,
                0x45,
                0x23,
                0x01,
            ]
        ),
        bytes(
            [
                0x10,
                0x32,
                0x54,
                0x76,
                0x98,
                0xBA,
                0xDC,
                0xFE,
                0xEF,
                0xCD,
                0xAB,
                0x89,
                0x67,
                0x45,
                0x23,
                0x01,
                0x01,
                0x23,
                0x45,
                0x67,
                0x89,
                0xAB,
                0xCD,
                0xEF,
                0xFE,
                0xDC,
                0xBA,
                0x98,
                0x76,
                0x54,
                0x32,
                0x10,
            ]
        ),
        bytes(
            [
                0x2B,
                0x7E,
                0x15,
                0x16,
                0x28,
                0xAE,
                0xD2,
                0xA6,
                0xAB,
                0xF7,
                0x15,
                0x88,
                0x09,
                0xCF,
                0x4F,
                0x3C,
                0x3C,
                0x4F,
                0xCF,
                0x09,
                0x88,
                0x15,
                0xF7,
                0xAB,
                0xA6,
                0xD2,
                0xAE,
                0x28,
                0x16,
                0x15,
                0x7E,
                0x2B,
            ]
        ),
    ]

    tweak_8 = bytes([0x08, 0xE0, 0xC2, 0x89, 0xBF, 0xF2, 0x3B, 0x7C])
    tweak_16 = bytes(
        [
            0x21,
            0xBD,
            0x18,
            0x34,
            0xBC,
            0x08,
            0x8C,
            0xD2,
            0xB4,
            0xEC,
            0xBE,
            0x30,
            0xB7,
            0x08,
            0x98,
            0xD7,
        ]
    )

    test_cases = [
        {
            "ip": "0.0.0.0",
            "key_16": keys_16[0],
            "key_32": keys_32[0],
            "expected_encrypted": "7a73:3179:bcf3:5036:5f4b:754d:9518:fb70",
        },
        {
            "ip": "255.255.255.255",
            "key_16": keys_16[1],
            "key_32": keys_32[1],
            "expected_encrypted": "105d:f4d1:e4b7:4dca:12b3:f38c:4c3c:d9c",
        },
        {
            "ip": "192.0.2.1",
            "key_16": keys_16[2],
            "key_32": keys_32[2],
            "expected_encrypted": "2001:db8:85a3::8a2e:370:7334",
        },
        {
            "ip": "2001:db8:85a3::8a2e:370:7334",
            "key_16": keys_16[0],
            "key_32": keys_32[0],
            "expected_encrypted": "192.0.2.1",
        },
        {
            "ip": "192.0.2.1",
            "key_16": keys_16[1],
            "key_32": keys_32[1],
            "expected_encrypted": "2001:db8:85a3::8a2e:370:7334",
        },
    ]

    for case in test_cases:
        ip = normalize_ip(case["ip"])
        print(f"\nTesting with IP: {ip}")

        encrypted_ip = det_encrypt(ip, case["key_16"])
        decrypted_ip = normalize_ip(det_decrypt(encrypted_ip, case["key_16"]))
        print(f"Deterministic: {ip} -> {encrypted_ip} -> {decrypted_ip}")
        print(f"Expected: {case['expected_encrypted']}")
        assert str(decrypted_ip) == str(ip)
        vectors.append(
            {
                "variant": "ipcrypt-deterministic",
                "key": binascii.hexlify(case["key_16"]).decode(),
                "ip": str(ip),
                "encrypted_ip": str(encrypted_ip),
            }
        )

        plaintext = ip_to_bytes(ip)
        ciphertext = kiasu_bc_encrypt(case["key_16"], tweak_8, plaintext)
        binary_output = tweak_8 + ciphertext
        decrypted_ip = normalize_ip(nd_decrypt(binary_output, case["key_16"]))
        print(
            f"KIASU-BC: {ip} -> {binascii.hexlify(binary_output).decode()} -> {decrypted_ip}"
        )
        assert str(decrypted_ip) == str(ip)
        vectors.append(
            {
                "variant": "ipcrypt-nd",
                "key": binascii.hexlify(case["key_16"]).decode(),
                "ip": str(ip),
                "tweak": binascii.hexlify(tweak_8).decode(),
                "output": binascii.hexlify(binary_output).decode(),
            }
        )

        plaintext = ip_to_bytes(ip)
        ciphertext = aes_xts_encrypt(case["key_32"], tweak_16, plaintext)
        binary_output = tweak_16 + ciphertext
        decrypted_ip = normalize_ip(ndx_decrypt(binary_output, case["key_32"]))
        print(
            f"AES-XTS: {ip} -> {binascii.hexlify(binary_output).decode()} -> {decrypted_ip}"
        )
        assert str(decrypted_ip) == str(ip)
        vectors.append(
            {
                "variant": "ipcrypt-ndx",
                "key": binascii.hexlify(case["key_32"]).decode(),
                "ip": str(ip),
                "tweak": binascii.hexlify(tweak_16).decode(),
                "output": binascii.hexlify(binary_output).decode(),
            }
        )

    # Generate ipcrypt-pfx test vectors
    print("\n=== ipcrypt-pfx Test Vectors ===")

    # Basic test vectors
    pfx_basic_tests = [
        ("0.0.0.0", pfx_keys[0]),
        ("255.255.255.255", pfx_keys[0]),
        ("192.0.2.1", pfx_keys[0]),
        ("2001:db8::1", pfx_keys[0]),
    ]

    for ip, key in pfx_basic_tests:
        encrypted = pfx_encrypt(ip, key)
        decrypted = pfx_decrypt(encrypted, key)
        print(f"PFX: {ip} -> {encrypted} -> {decrypted}")
        # Verify round-trip
        assert str(ipaddress.ip_address(decrypted)) == str(ipaddress.ip_address(ip))
        vectors.append(
            {
                "variant": "ipcrypt-pfx",
                "key": binascii.hexlify(key).decode(),
                "ip": str(ip),
                "encrypted_ip": str(encrypted),
            }
        )

    # Prefix-preserving test vectors (IPv4 /24)
    pfx_ipv4_24 = [
        "10.0.0.47",
        "10.0.0.129",
        "10.0.0.234",
    ]

    for ip in pfx_ipv4_24:
        encrypted = pfx_encrypt(ip, pfx_keys[1])
        decrypted = pfx_decrypt(encrypted, pfx_keys[1])
        print(f"PFX /24: {ip} -> {encrypted}")
        assert str(ipaddress.ip_address(decrypted)) == str(ipaddress.ip_address(ip))
        vectors.append(
            {
                "variant": "ipcrypt-pfx",
                "key": binascii.hexlify(pfx_keys[1]).decode(),
                "ip": str(ip),
                "encrypted_ip": str(encrypted),
            }
        )

    # Prefix-preserving test vectors (IPv4 /16)
    pfx_ipv4_16 = [
        "172.16.5.193",
        "172.16.97.42",
        "172.16.248.177",
    ]

    for ip in pfx_ipv4_16:
        encrypted = pfx_encrypt(ip, pfx_keys[1])
        decrypted = pfx_decrypt(encrypted, pfx_keys[1])
        print(f"PFX /16: {ip} -> {encrypted}")
        assert str(ipaddress.ip_address(decrypted)) == str(ipaddress.ip_address(ip))
        vectors.append(
            {
                "variant": "ipcrypt-pfx",
                "key": binascii.hexlify(pfx_keys[1]).decode(),
                "ip": str(ip),
                "encrypted_ip": str(encrypted),
            }
        )

    # Prefix-preserving test vectors (IPv6 /64)
    pfx_ipv6_64 = [
        "2001:db8::a5c9:4e2f:bb91:5a7d",
        "2001:db8::7234:d8f1:3c6e:9a52",
        "2001:db8::f1e0:937b:26d4:8c1a",
    ]

    for ip in pfx_ipv6_64:
        encrypted = pfx_encrypt(ip, pfx_keys[1])
        decrypted = pfx_decrypt(encrypted, pfx_keys[1])
        print(f"PFX /64: {ip} -> {encrypted}")
        assert str(ipaddress.ip_address(decrypted)) == str(ipaddress.ip_address(ip))
        vectors.append(
            {
                "variant": "ipcrypt-pfx",
                "key": binascii.hexlify(pfx_keys[1]).decode(),
                "ip": str(ip),
                "encrypted_ip": str(encrypted),
            }
        )

    # Prefix-preserving test vectors (IPv6 /32)
    pfx_ipv6_32 = [
        "2001:db8:3a5c::e7d1:4b9f:2c8a:f673",
        "2001:db8:9f27::b4e2:7a3d:5f91:c8e6",
        "2001:db8:d8b4::193c:a5e7:8b2f:46d1",
    ]

    for ip in pfx_ipv6_32:
        encrypted = pfx_encrypt(ip, pfx_keys[1])
        decrypted = pfx_decrypt(encrypted, pfx_keys[1])
        print(f"PFX /32: {ip} -> {encrypted}")
        assert str(ipaddress.ip_address(decrypted)) == str(ipaddress.ip_address(ip))
        vectors.append(
            {
                "variant": "ipcrypt-pfx",
                "key": binascii.hexlify(pfx_keys[1]).decode(),
                "ip": str(ip),
                "encrypted_ip": str(encrypted),
            }
        )

    return vectors


def main():
    """Generate and save test vectors."""
    vectors = generate_test_vectors()
    with open("test_vectors.json", "w") as f:
        json.dump(vectors, f, indent=2)
    print(f"\nGenerated {len(vectors)} test vectors")
    print(
        f"- {sum(1 for v in vectors if v['variant'] == 'ipcrypt-deterministic')} deterministic vectors"
    )
    print(
        f"- {sum(1 for v in vectors if v['variant'] == 'ipcrypt-nd')} KIASU-BC vectors"
    )
    print(
        f"- {sum(1 for v in vectors if v['variant'] == 'ipcrypt-ndx')} AES-XTS vectors"
    )
    print(
        f"- {sum(1 for v in vectors if v['variant'] == 'ipcrypt-pfx')} ipcrypt-pfx vectors"
    )


if __name__ == "__main__":
    main()
