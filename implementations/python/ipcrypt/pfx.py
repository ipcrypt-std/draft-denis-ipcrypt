#!/usr/bin/env python3
"""Implementation of ipcrypt-pfx using AES-128 for prefix-preserving encryption."""

import ipaddress
from Crypto.Cipher import AES


def ip_to_bytes(ip):
    """Convert an IP address to its 16-byte representation."""
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    if isinstance(ip, ipaddress.IPv4Address):
        # Convert IPv4 to IPv4-mapped IPv6 format (::ffff:0:0/96)
        return b"\x00" * 10 + b"\xff\xff" + ip.packed
    else:
        return ip.packed


def bytes_to_ip(bytes16):
    """Convert a 16-byte representation back to an IP address."""
    if len(bytes16) != 16:
        raise ValueError("Input must be 16 bytes")

    # Check for IPv4-mapped IPv6 format
    if bytes16[:10] == b"\x00" * 10 and bytes16[10:12] == b"\xff\xff":
        return ipaddress.IPv4Address(bytes16[12:])
    else:
        return ipaddress.IPv6Address(bytes16)


def is_ipv4_mapped(bytes16):
    """Check if a 16-byte array has the IPv4-mapped IPv6 prefix (::ffff:0:0/96)."""
    if len(bytes16) != 16:
        return False
    # Check for IPv4-mapped prefix: first 10 bytes are 0x00, bytes 10-11 are 0xFF
    return bytes16[:10] == b"\x00" * 10 and bytes16[10:12] == b"\xff\xff"


def get_bit(data, position):
    """Extract bit at position from 16-byte array.
    position: 0 = LSB of byte 15, 127 = MSB of byte 0
    """
    byte_index = 15 - (position // 8)
    bit_index = position % 8
    return (data[byte_index] >> bit_index) & 1


def set_bit(data, position, value):
    """Set bit at position in 16-byte array.
    position: 0 = LSB of byte 15, 127 = MSB of byte 0
    """
    byte_index = 15 - (position // 8)
    bit_index = position % 8
    data[byte_index] |= value << bit_index
    # Clearing can be done but is not necessary for ipcrypt-pfx


def shift_left_one_bit(data):
    """Shift a 16-byte array one bit to the left.

    The most significant bit is lost, and a zero bit is shifted in from the right.
    """
    if len(data) != 16:
        raise ValueError("Input must be 16 bytes")

    result = bytearray(16)
    carry = 0

    # Process from least significant byte (byte 15) to most significant (byte 0)
    for i in range(15, -1, -1):
        # Current byte shifted left by 1, with carry from previous byte
        result[i] = ((data[i] << 1) | carry) & 0xFF
        # Extract the bit that will be carried to the next byte
        carry = (data[i] >> 7) & 1

    return result


# Constants for padding prefixes
PAD_PREFIX_0 = bytearray(
    [0] * 15 + [0x01]
)  # Separator bit at position 0 (LSB of byte 15)
PAD_PREFIX_96 = bytearray(
    [0, 0, 0, 0x01] + [0] * 10 + [0xFF, 0xFF]
)  # Separator in byte 3, followed by IPv4-mapped prefix


def encrypt(ip, key):
    """Encrypt an IP address using ipcrypt-pfx."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    # Split the key into two AES-128 keys
    K1 = key[:16]
    K2 = key[16:32]

    # Check that K1 and K2 are different
    if K1 == K2:
        raise ValueError("The two halves of the key must be different")

    # Convert IP to 16-byte representation
    bytes16 = ip_to_bytes(ip)

    # Initialize encrypted result with zeros
    encrypted = bytearray(16)

    # Determine starting point
    if is_ipv4_mapped(bytes16):
        prefix_start = 96
        # If IPv4-mapped, copy the IPv4-mapped prefix
        encrypted[:12] = bytes16[:12]
    else:
        prefix_start = 0

    # Create AES cipher objects
    cipher1 = AES.new(K1, AES.MODE_ECB)
    cipher2 = AES.new(K2, AES.MODE_ECB)

    # Initialize padded_prefix for the starting prefix length
    if is_ipv4_mapped(bytes16):
        padded_prefix = PAD_PREFIX_96.copy()
    else:  # prefix_start == 0
        padded_prefix = PAD_PREFIX_0.copy()

    # Process each bit position
    for prefix_len_bits in range(prefix_start, 128):
        # Compute pseudorandom function with dual AES encryption
        e1 = cipher1.encrypt(bytes(padded_prefix))
        e2 = cipher2.encrypt(bytes(padded_prefix))

        # XOR the two encryptions
        e = bytes(a ^ b for a, b in zip(e1, e2))
        # We only need the least significant bit of the first byte
        cipher_bit = e[15] & 1

        # Extract the current bit from the original IP
        current_bit_pos = 127 - prefix_len_bits

        # Set the bit in the encrypted result
        original_bit = get_bit(bytes16, current_bit_pos)
        set_bit(encrypted, current_bit_pos, cipher_bit ^ original_bit)

        # Prepare padded_prefix for next iteration
        # Shift left by 1 bit and insert the next bit from bytes16
        padded_prefix = shift_left_one_bit(padded_prefix)
        set_bit(padded_prefix, 0, original_bit)

    return bytes_to_ip(bytes(encrypted))


def decrypt(encrypted_ip, key):
    """Decrypt an IP address using ipcrypt-pfx."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")

    # Split the key into two AES-128 keys
    K1 = key[:16]
    K2 = key[16:32]

    # Check that K1 and K2 are different
    if K1 == K2:
        raise ValueError("The two halves of the key must be different")

    # Convert encrypted IP to 16-byte representation
    encrypted_bytes = ip_to_bytes(encrypted_ip)

    # Initialize decrypted result
    decrypted = bytearray(16)

    # For decryption, we need to determine if this was originally IPv4-mapped
    # IPv4-mapped addresses are encrypted with prefix_start=96
    if is_ipv4_mapped(encrypted_bytes):
        prefix_start = 96
        # If this was originally IPv4, set up the IPv4-mapped IPv6 prefix
        decrypted[10:12] = b"\xff\xff"
    else:
        prefix_start = 0

    # Create AES cipher objects
    cipher1 = AES.new(K1, AES.MODE_ECB)
    cipher2 = AES.new(K2, AES.MODE_ECB)

    # Initialize padded_prefix for the starting prefix length
    if prefix_start == 0:
        padded_prefix = PAD_PREFIX_0.copy()
    else:  # prefix_start == 96
        padded_prefix = PAD_PREFIX_96.copy()

    # Process each bit position
    for prefix_len_bits in range(prefix_start, 128):
        # Compute pseudorandom function with dual AES encryption
        e1 = cipher1.encrypt(bytes(padded_prefix))
        e2 = cipher2.encrypt(bytes(padded_prefix))

        # XOR the two encryptions
        e = bytes(a ^ b for a, b in zip(e1, e2))
        # We only need the least significant bit of the first byte
        cipher_bit = e[15] & 1

        # Extract the current bit from the encrypted IP
        current_bit_pos = 127 - prefix_len_bits

        # Set the bit in the decrypted result
        encrypted_bit = get_bit(encrypted_bytes, current_bit_pos)
        original_bit = cipher_bit ^ encrypted_bit
        set_bit(decrypted, current_bit_pos, original_bit)

        # Prepare padded_prefix for next iteration
        # Shift left by 1 bit and insert the next bit from decrypted
        padded_prefix = shift_left_one_bit(padded_prefix)
        set_bit(padded_prefix, 0, original_bit)

    return bytes_to_ip(bytes(decrypted))
