#!/usr/bin/env python3
"""
Implementation of ipcrypt-nd using KIASU-BC with an 8-byte tweak.
"""

import ipaddress
from Crypto.Cipher import AES
import os

# AES S-box
SBOX = bytes([
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
])

# Add inverse S-box after the regular S-box
INV_SBOX = bytes([
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
])

# AES round constants
RCON = bytes([0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36])

def sub_bytes(state):
    """Apply S-box to each byte in state."""
    return bytes(SBOX[b] for b in state)

def rot_word(word):
    """Rotate a 4-byte word."""
    return word[1:] + word[:1]

def xor_bytes(a, b):
    """XOR two byte sequences."""
    return bytes(x ^ y for x, y in zip(a, b))

def expand_key(key):
    """Generate AES round keys."""
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    
    # First generate regular AES round keys
    round_keys = [key]
    for i in range(10):
        prev_key = round_keys[-1]
        temp = prev_key[-4:]
        temp = rot_word(temp)
        temp = sub_bytes(temp)
        temp = bytes([temp[0] ^ RCON[i]]) + temp[1:]
        
        new_key = bytearray(16)
        for j in range(4):
            word = prev_key[j*4:(j+1)*4]
            if j == 0:
                word = xor_bytes(word, temp)
            else:
                word = xor_bytes(word, new_key[(j-1)*4:j*4])
            new_key[j*4:(j+1)*4] = word
        round_keys.append(bytes(new_key))
    
    return round_keys

def pad_tweak(tweak):
    """Pad an 8-byte tweak to 16 bytes by placing each 2-byte pair at the start of each 4-byte group."""
    if len(tweak) != 8:
        raise ValueError("Tweak must be 8 bytes")
    
    padded_tweak = bytearray(16)
    for i in range(4):  # We have 4 groups of 4 bytes
        padded_tweak[i*4] = tweak[i*2]      # First byte of the pair
        padded_tweak[i*4 + 1] = tweak[i*2 + 1]  # Second byte of the pair
        padded_tweak[i*4 + 2] = 0           # Padding
        padded_tweak[i*4 + 3] = 0           # Padding
    return bytes(padded_tweak)

def shift_rows(state):
    """Perform AES ShiftRows operation."""
    return bytes([
        state[0], state[5], state[10], state[15],
        state[4], state[9], state[14], state[3],
        state[8], state[13], state[2], state[7],
        state[12], state[1], state[6], state[11]
    ])

def mix_columns(state):
    """Perform AES MixColumns operation."""
    def mul2(a):
        if a & 0x80:
            return ((a << 1) ^ 0x1B) & 0xFF
        return (a << 1) & 0xFF
    
    def mul3(a):
        return mul2(a) ^ a
    
    new_state = bytearray(16)
    for i in range(4):
        s0, s1, s2, s3 = state[i*4:i*4+4]
        new_state[i*4] = mul2(s0) ^ mul3(s1) ^ s2 ^ s3
        new_state[i*4+1] = s0 ^ mul2(s1) ^ mul3(s2) ^ s3
        new_state[i*4+2] = s0 ^ s1 ^ mul2(s2) ^ mul3(s3)
        new_state[i*4+3] = mul3(s0) ^ s1 ^ s2 ^ mul2(s3)
    return bytes(new_state)

def kiasu_bc_encrypt(key, tweak, plaintext):
    """Encrypt using KIASU-BC construction."""
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(tweak) != 8:
        raise ValueError("Tweak must be 8 bytes")
    if len(plaintext) != 16:
        raise ValueError("Plaintext must be 16 bytes")
    
    # Generate round keys
    round_keys = expand_key(key)
    
    # Get padded tweak
    padded_tweak = pad_tweak(tweak)
    
    # Initial round
    state = xor_bytes(plaintext, xor_bytes(round_keys[0], padded_tweak))
    
    # Main rounds
    for i in range(9):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = xor_bytes(state, xor_bytes(round_keys[i + 1], padded_tweak))
    
    # Final round (no MixColumns)
    state = sub_bytes(state)
    state = shift_rows(state)
    state = xor_bytes(state, xor_bytes(round_keys[10], padded_tweak))
    
    return state

def inv_sub_bytes(state):
    """Apply inverse S-box to each byte in state."""
    return bytes(INV_SBOX[b] for b in state)

def inv_shift_rows(state):
    """Perform inverse AES ShiftRows operation."""
    return bytes([
        state[0], state[13], state[10], state[7],
        state[4], state[1], state[14], state[11],
        state[8], state[5], state[2], state[15],
        state[12], state[9], state[6], state[3]
    ])

def inv_mix_columns(state):
    """Perform inverse AES MixColumns operation."""
    def mul(a, b):
        """Multiply two bytes in GF(2^8)."""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # AES irreducible polynomial
            b >>= 1
        return p & 0xFF

    def mul_by_matrix(col):
        """Multiply a column by the inverse MixColumns matrix."""
        a, b, c, d = col
        return [
            mul(0x0E, a) ^ mul(0x0B, b) ^ mul(0x0D, c) ^ mul(0x09, d),
            mul(0x09, a) ^ mul(0x0E, b) ^ mul(0x0B, c) ^ mul(0x0D, d),
            mul(0x0D, a) ^ mul(0x09, b) ^ mul(0x0E, c) ^ mul(0x0B, d),
            mul(0x0B, a) ^ mul(0x0D, b) ^ mul(0x09, c) ^ mul(0x0E, d)
        ]

    new_state = bytearray(16)
    for i in range(4):
        col = state[4*i:4*i+4]
        result = mul_by_matrix(col)
        for j in range(4):
            new_state[4*i+j] = result[j]
    return bytes(new_state)

def kiasu_bc_decrypt(key, tweak, ciphertext):
    """Decrypt using KIASU-BC construction."""
    if len(key) != 16:
        raise ValueError("Key must be 16 bytes")
    if len(tweak) != 8:
        raise ValueError("Tweak must be 8 bytes")
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext must be 16 bytes")
    
    # Generate round keys
    round_keys = expand_key(key)
    
    # Get padded tweak
    padded_tweak = pad_tweak(tweak)
    
    # Initial round
    state = xor_bytes(ciphertext, xor_bytes(round_keys[10], padded_tweak))  # Start with last round key
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    
    # Main rounds
    for i in range(9, 0, -1):
        state = xor_bytes(state, xor_bytes(round_keys[i], padded_tweak))
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
    
    # Final round
    state = xor_bytes(state, xor_bytes(round_keys[0], padded_tweak))
    
    return state

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

def test_zero_tweak():
    """Test that KIASU-BC with zero tweak matches regular AES."""
    key = os.urandom(16)
    plaintext = os.urandom(16)
    zero_tweak = b'\x00' * 8
    
    # KIASU-BC with zero tweak
    kiasu_result = kiasu_bc_encrypt(key, zero_tweak, plaintext)
    
    # Regular AES
    cipher = AES.new(key, AES.MODE_ECB)
    aes_result = cipher.encrypt(plaintext)
    
    assert kiasu_result == aes_result, "KIASU-BC with zero tweak should match AES"
    
def test_kiasu_bc():
    """Test that KIASU-BC decryption correctly reverses encryption."""
    key = os.urandom(16)
    tweak = os.urandom(8)
    plaintext = os.urandom(16)
    
    # Encrypt
    ciphertext = kiasu_bc_encrypt(key, tweak, plaintext)
    
    # Decrypt
    decrypted = kiasu_bc_decrypt(key, tweak, ciphertext)
    
    # Verify
    assert decrypted == plaintext, "Decryption failed to recover plaintext"
    print("KIASU-BC encryption/decryption test passed!")

if __name__ == '__main__':
    test_zero_tweak()
    test_kiasu_bc()
    print("All tests passed!") 