#!/usr/bin/env python3
"""Implementation of ipcrypt-nd using KIASU-BC."""

import ipaddress
import os

# AES S-box and inverse S-box
SBOX = bytes(
    [
        0x63,
        0x7C,
        0x77,
        0x7B,
        0xF2,
        0x6B,
        0x6F,
        0xC5,
        0x30,
        0x01,
        0x67,
        0x2B,
        0xFE,
        0xD7,
        0xAB,
        0x76,
        0xCA,
        0x82,
        0xC9,
        0x7D,
        0xFA,
        0x59,
        0x47,
        0xF0,
        0xAD,
        0xD4,
        0xA2,
        0xAF,
        0x9C,
        0xA4,
        0x72,
        0xC0,
        0xB7,
        0xFD,
        0x93,
        0x26,
        0x36,
        0x3F,
        0xF7,
        0xCC,
        0x34,
        0xA5,
        0xE5,
        0xF1,
        0x71,
        0xD8,
        0x31,
        0x15,
        0x04,
        0xC7,
        0x23,
        0xC3,
        0x18,
        0x96,
        0x05,
        0x9A,
        0x07,
        0x12,
        0x80,
        0xE2,
        0xEB,
        0x27,
        0xB2,
        0x75,
        0x09,
        0x83,
        0x2C,
        0x1A,
        0x1B,
        0x6E,
        0x5A,
        0xA0,
        0x52,
        0x3B,
        0xD6,
        0xB3,
        0x29,
        0xE3,
        0x2F,
        0x84,
        0x53,
        0xD1,
        0x00,
        0xED,
        0x20,
        0xFC,
        0xB1,
        0x5B,
        0x6A,
        0xCB,
        0xBE,
        0x39,
        0x4A,
        0x4C,
        0x58,
        0xCF,
        0xD0,
        0xEF,
        0xAA,
        0xFB,
        0x43,
        0x4D,
        0x33,
        0x85,
        0x45,
        0xF9,
        0x02,
        0x7F,
        0x50,
        0x3C,
        0x9F,
        0xA8,
        0x51,
        0xA3,
        0x40,
        0x8F,
        0x92,
        0x9D,
        0x38,
        0xF5,
        0xBC,
        0xB6,
        0xDA,
        0x21,
        0x10,
        0xFF,
        0xF3,
        0xD2,
        0xCD,
        0x0C,
        0x13,
        0xEC,
        0x5F,
        0x97,
        0x44,
        0x17,
        0xC4,
        0xA7,
        0x7E,
        0x3D,
        0x64,
        0x5D,
        0x19,
        0x73,
        0x60,
        0x81,
        0x4F,
        0xDC,
        0x22,
        0x2A,
        0x90,
        0x88,
        0x46,
        0xEE,
        0xB8,
        0x14,
        0xDE,
        0x5E,
        0x0B,
        0xDB,
        0xE0,
        0x32,
        0x3A,
        0x0A,
        0x49,
        0x06,
        0x24,
        0x5C,
        0xC2,
        0xD3,
        0xAC,
        0x62,
        0x91,
        0x95,
        0xE4,
        0x79,
        0xE7,
        0xC8,
        0x37,
        0x6D,
        0x8D,
        0xD5,
        0x4E,
        0xA9,
        0x6C,
        0x56,
        0xF4,
        0xEA,
        0x65,
        0x7A,
        0xAE,
        0x08,
        0xBA,
        0x78,
        0x25,
        0x2E,
        0x1C,
        0xA6,
        0xB4,
        0xC6,
        0xE8,
        0xDD,
        0x74,
        0x1F,
        0x4B,
        0xBD,
        0x8B,
        0x8A,
        0x70,
        0x3E,
        0xB5,
        0x66,
        0x48,
        0x03,
        0xF6,
        0x0E,
        0x61,
        0x35,
        0x57,
        0xB9,
        0x86,
        0xC1,
        0x1D,
        0x9E,
        0xE1,
        0xF8,
        0x98,
        0x11,
        0x69,
        0xD9,
        0x8E,
        0x94,
        0x9B,
        0x1E,
        0x87,
        0xE9,
        0xCE,
        0x55,
        0x28,
        0xDF,
        0x8C,
        0xA1,
        0x89,
        0x0D,
        0xBF,
        0xE6,
        0x42,
        0x68,
        0x41,
        0x99,
        0x2D,
        0x0F,
        0xB0,
        0x54,
        0xBB,
        0x16,
    ]
)
INV_SBOX = bytes(
    [
        0x52,
        0x09,
        0x6A,
        0xD5,
        0x30,
        0x36,
        0xA5,
        0x38,
        0xBF,
        0x40,
        0xA3,
        0x9E,
        0x81,
        0xF3,
        0xD7,
        0xFB,
        0x7C,
        0xE3,
        0x39,
        0x82,
        0x9B,
        0x2F,
        0xFF,
        0x87,
        0x34,
        0x8E,
        0x43,
        0x44,
        0xC4,
        0xDE,
        0xE9,
        0xCB,
        0x54,
        0x7B,
        0x94,
        0x32,
        0xA6,
        0xC2,
        0x23,
        0x3D,
        0xEE,
        0x4C,
        0x95,
        0x0B,
        0x42,
        0xFA,
        0xC3,
        0x4E,
        0x08,
        0x2E,
        0xA1,
        0x66,
        0x28,
        0xD9,
        0x24,
        0xB2,
        0x76,
        0x5B,
        0xA2,
        0x49,
        0x6D,
        0x8B,
        0xD1,
        0x25,
        0x72,
        0xF8,
        0xF6,
        0x64,
        0x86,
        0x68,
        0x98,
        0x16,
        0xD4,
        0xA4,
        0x5C,
        0xCC,
        0x5D,
        0x65,
        0xB6,
        0x92,
        0x6C,
        0x70,
        0x48,
        0x50,
        0xFD,
        0xED,
        0xB9,
        0xDA,
        0x5E,
        0x15,
        0x46,
        0x57,
        0xA7,
        0x8D,
        0x9D,
        0x84,
        0x90,
        0xD8,
        0xAB,
        0x00,
        0x8C,
        0xBC,
        0xD3,
        0x0A,
        0xF7,
        0xE4,
        0x58,
        0x05,
        0xB8,
        0xB3,
        0x45,
        0x06,
        0xD0,
        0x2C,
        0x1E,
        0x8F,
        0xCA,
        0x3F,
        0x0F,
        0x02,
        0xC1,
        0xAF,
        0xBD,
        0x03,
        0x01,
        0x13,
        0x8A,
        0x6B,
        0x3A,
        0x91,
        0x11,
        0x41,
        0x4F,
        0x67,
        0xDC,
        0xEA,
        0x97,
        0xF2,
        0xCF,
        0xCE,
        0xF0,
        0xB4,
        0xE6,
        0x73,
        0x96,
        0xAC,
        0x74,
        0x22,
        0xE7,
        0xAD,
        0x35,
        0x85,
        0xE2,
        0xF9,
        0x37,
        0xE8,
        0x1C,
        0x75,
        0xDF,
        0x6E,
        0x47,
        0xF1,
        0x1A,
        0x71,
        0x1D,
        0x29,
        0xC5,
        0x89,
        0x6F,
        0xB7,
        0x62,
        0x0E,
        0xAA,
        0x18,
        0xBE,
        0x1B,
        0xFC,
        0x56,
        0x3E,
        0x4B,
        0xC6,
        0xD2,
        0x79,
        0x20,
        0x9A,
        0xDB,
        0xC0,
        0xFE,
        0x78,
        0xCD,
        0x5A,
        0xF4,
        0x1F,
        0xDD,
        0xA8,
        0x33,
        0x88,
        0x07,
        0xC7,
        0x31,
        0xB1,
        0x12,
        0x10,
        0x59,
        0x27,
        0x80,
        0xEC,
        0x5F,
        0x60,
        0x51,
        0x7F,
        0xA9,
        0x19,
        0xB5,
        0x4A,
        0x0D,
        0x2D,
        0xE5,
        0x7A,
        0x9F,
        0x93,
        0xC9,
        0x9C,
        0xEF,
        0xA0,
        0xE0,
        0x3B,
        0x4D,
        0xAE,
        0x2A,
        0xF5,
        0xB0,
        0xC8,
        0xEB,
        0xBB,
        0x3C,
        0x83,
        0x53,
        0x99,
        0x61,
        0x17,
        0x2B,
        0x04,
        0x7E,
        0xBA,
        0x77,
        0xD6,
        0x26,
        0xE1,
        0x69,
        0x14,
        0x63,
        0x55,
        0x21,
        0x0C,
        0x7D,
    ]
)

# AES round constants
RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36])

# Precomputed multiplication tables for AES operations
MUL2 = bytes([(x << 1) & 0xFF ^ (0x1B if x & 0x80 else 0) & 0xFF for x in range(256)])
MUL3 = bytes(
    [((x << 1) & 0xFF ^ (0x1B if x & 0x80 else 0) & 0xFF) ^ x for x in range(256)]
)


def sub_bytes(state):
    return bytes(SBOX[b] for b in state)


def inv_sub_bytes(state):
    return bytes(INV_SBOX[b] for b in state)


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def rot_word(word):
    """Rotate a 4-byte word."""
    return word[1:] + word[:1]


def expand_key(key):
    """Generate AES round keys."""
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")

    round_keys = [key]
    for i in range(10):
        prev_key = round_keys[-1]
        temp = prev_key[-4:]
        temp = rot_word(temp)
        temp = sub_bytes(temp)
        temp = bytes([temp[0] ^ RCON[i]]) + temp[1:]

        new_key = bytearray(16)
        for j in range(4):
            word = prev_key[j * 4 : (j + 1) * 4]
            if j == 0:
                word = xor_bytes(word, temp)
            else:
                word = xor_bytes(word, new_key[(j - 1) * 4 : j * 4])
            new_key[j * 4 : (j + 1) * 4] = word
        round_keys.append(bytes(new_key))

    return round_keys


def pad_tweak(tweak):
    """Pad an 8-byte tweak to 16 bytes by placing each 2-byte pair at the start of each 4-byte group."""
    if len(tweak) != 8:
        raise ValueError("Tweak must be 8 bytes")

    padded_tweak = bytearray(16)
    for i in range(4):
        padded_tweak[i * 4] = tweak[i * 2]
        padded_tweak[i * 4 + 1] = tweak[i * 2 + 1]
        padded_tweak[i * 4 + 2] = 0
        padded_tweak[i * 4 + 3] = 0
    return bytes(padded_tweak)


def shift_rows(state):
    """Perform AES ShiftRows operation."""
    return bytes(
        [
            state[0],
            state[5],
            state[10],
            state[15],
            state[4],
            state[9],
            state[14],
            state[3],
            state[8],
            state[13],
            state[2],
            state[7],
            state[12],
            state[1],
            state[6],
            state[11],
        ]
    )


def inv_shift_rows(state):
    """Perform inverse AES ShiftRows operation."""
    return bytes(
        [
            state[0],
            state[13],
            state[10],
            state[7],
            state[4],
            state[1],
            state[14],
            state[11],
            state[8],
            state[5],
            state[2],
            state[15],
            state[12],
            state[9],
            state[6],
            state[3],
        ]
    )


def mix_columns(state):
    """Perform AES MixColumns operation."""
    new_state = bytearray(16)
    for i in range(4):
        s0, s1, s2, s3 = state[i * 4 : i * 4 + 4]
        new_state[i * 4] = MUL2[s0] ^ MUL3[s1] ^ s2 ^ s3
        new_state[i * 4 + 1] = s0 ^ MUL2[s1] ^ MUL3[s2] ^ s3
        new_state[i * 4 + 2] = s0 ^ s1 ^ MUL2[s2] ^ MUL3[s3]
        new_state[i * 4 + 3] = MUL3[s0] ^ s1 ^ s2 ^ MUL2[s3]
    return bytes(new_state)


def mul_09(b):
    """Multiply byte by 0x09 in GF(2^8)."""
    return MUL2[MUL2[MUL2[b]]] ^ b


def mul_0B(b):
    """Multiply byte by 0x0B in GF(2^8)."""
    return MUL2[MUL2[MUL2[b]]] ^ MUL2[b] ^ b


def mul_0D(b):
    """Multiply byte by 0x0D in GF(2^8)."""
    x2 = MUL2[b]
    x4 = MUL2[x2]
    x8 = MUL2[x4]
    return x8 ^ x4 ^ b


def mul_0E(b):
    """Multiply byte by 0x0E in GF(2^8)."""
    x2 = MUL2[b]
    x4 = MUL2[x2]
    x8 = MUL2[x4]
    return x8 ^ x4 ^ x2


def inv_mix_columns(state):
    """Perform inverse AES MixColumns operation."""
    new_state = bytearray(16)
    for i in range(4):
        col = state[4 * i : 4 * i + 4]
        result = [
            mul_0E(col[0]) ^ mul_0B(col[1]) ^ mul_0D(col[2]) ^ mul_09(col[3]),
            mul_09(col[0]) ^ mul_0E(col[1]) ^ mul_0B(col[2]) ^ mul_0D(col[3]),
            mul_0D(col[0]) ^ mul_09(col[1]) ^ mul_0E(col[2]) ^ mul_0B(col[3]),
            mul_0B(col[0]) ^ mul_0D(col[1]) ^ mul_09(col[2]) ^ mul_0E(col[3]),
        ]
        for j in range(4):
            new_state[4 * i + j] = result[j]
    return bytes(new_state)


def kiasu_bc_encrypt(key, tweak, plaintext):
    """Encrypt using KIASU-BC construction."""
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(tweak) != 8:
        raise ValueError("Tweak must be 8 bytes")
    if len(plaintext) != 16:
        raise ValueError("Plaintext must be 16 bytes")

    round_keys = expand_key(key)
    padded_tweak = pad_tweak(tweak)

    state = xor_bytes(plaintext, xor_bytes(round_keys[0], padded_tweak))
    for i in range(9):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = xor_bytes(state, xor_bytes(round_keys[i + 1], padded_tweak))

    state = sub_bytes(state)
    state = shift_rows(state)
    state = xor_bytes(state, xor_bytes(round_keys[10], padded_tweak))

    return state


def kiasu_bc_decrypt(key, tweak, ciphertext):
    """Decrypt using KIASU-BC construction."""
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(tweak) != 8:
        raise ValueError("Tweak must be 8 bytes")
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext must be 16 bytes")

    round_keys = expand_key(key)
    padded_tweak = pad_tweak(tweak)

    state = xor_bytes(ciphertext, xor_bytes(round_keys[10], padded_tweak))
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    for i in range(9, 0, -1):
        state = xor_bytes(state, xor_bytes(round_keys[i], padded_tweak))
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

    state = xor_bytes(state, xor_bytes(round_keys[0], padded_tweak))

    return state


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


def encrypt(ip_address, key, tweak=None):
    """Encrypt an IP address using ipcrypt-nd."""
    # Convert IP to bytes
    ip_bytes = ip_to_bytes(ip_address)

    # Use provided tweak or generate random 8-byte tweak
    if tweak is None:
        tweak = os.urandom(8)
    elif len(tweak) != 8:
        raise ValueError("Tweak must be 8 bytes")

    # Encrypt using KIASU-BC
    ciphertext = kiasu_bc_encrypt(key, tweak, ip_bytes)

    # Return tweak || ciphertext
    return tweak + ciphertext


def decrypt(encrypted_data, key):
    """Decrypt an IP address using ipcrypt-nd."""
    if len(encrypted_data) != 24:  # 8 bytes tweak + 16 bytes ciphertext
        raise ValueError("Encrypted data must be 24 bytes")

    # Split into tweak and ciphertext
    tweak = encrypted_data[:8]
    ciphertext = encrypted_data[8:]

    # Decrypt using KIASU-BC
    ip_bytes = kiasu_bc_decrypt(key, tweak, ciphertext)

    # Convert back to IP address
    return bytes_to_ip(ip_bytes)
