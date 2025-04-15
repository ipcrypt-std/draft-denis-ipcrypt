#!/usr/bin/env python3
"""
Implementation of ipcrypt-deterministic using AES-128.
"""

import ipaddress
import os
from Crypto.Cipher import AES


def ip_to_bytes(ip):
    """Convert an IP address to its 16-byte representation."""
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)

    if isinstance(ip, ipaddress.IPv4Address):
        # Convert to IPv4-mapped IPv6 format
        return b'\x00' * 10 + b'\xff\xff' + ip.packed
    else:
        return ip.packed


def bytes_to_ip(bytes16):
    """Convert a 16-byte representation back to an IP address."""
    if len(bytes16) != 16:
        raise ValueError("Input must be 16 bytes")

    # Check for IPv4-mapped IPv6 format
    if bytes16[:10] == b'\x00' * 10 and bytes16[10:12] == b'\xff\xff':
        return ipaddress.IPv4Address(bytes16[12:])
    else:
        return ipaddress.IPv6Address(bytes16)


def encrypt(ip, key):
    """Encrypt an IP address using AES-128."""
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")

    # Convert IP to 16 bytes
    plaintext = ip_to_bytes(ip)
    print(f"Key: {binascii.hexlify(key).decode()}")
    print(f"Plaintext: {binascii.hexlify(plaintext).decode()}")

    # Encrypt using AES-128
    cipher = AES.new(key, AES.MODE_ECB)
    ciphertext = cipher.encrypt(plaintext)
    print(f"Ciphertext: {binascii.hexlify(ciphertext).decode()}")

    # Convert back to IP address
    return bytes_to_ip(ciphertext)


def decrypt(ip, key):
    """Decrypt an IP address using AES-128."""
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")

    # Convert IP to 16 bytes
    ciphertext = ip_to_bytes(ip)
    print(f"Key: {binascii.hexlify(key).decode()}")
    print(f"Ciphertext: {binascii.hexlify(ciphertext).decode()}")

    # Decrypt using AES-128
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    print(f"Plaintext: {binascii.hexlify(plaintext).decode()}")

    # Convert back to IP address
    return bytes_to_ip(plaintext)
