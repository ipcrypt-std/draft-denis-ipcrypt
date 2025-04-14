#!/usr/bin/env python3
"""
Implementation of ipcrypt-ndx using AES-XTS with a 16-byte tweak.
"""

import ipaddress
from Crypto.Cipher import AES
import os

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

def aes_xts_encrypt(key, tweak, plaintext):
    """Encrypt using AES-XTS construction."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(tweak) != 16:
        raise ValueError("Tweak must be 16 bytes")
    if len(plaintext) != 16:
        raise ValueError("Plaintext must be 16 bytes")
    
    # Split key into two halves
    k1 = key[:16]
    k2 = key[16:]
    
    # Encrypt tweak with second key
    cipher2 = AES.new(k2, AES.MODE_ECB)
    et = cipher2.encrypt(tweak)
    
    # XOR plaintext with encrypted tweak
    xored = bytes(a ^ b for a, b in zip(plaintext, et))
    
    # Encrypt with first key
    cipher1 = AES.new(k1, AES.MODE_ECB)
    encrypted = cipher1.encrypt(xored)
    
    # XOR result with encrypted tweak
    return bytes(a ^ b for a, b in zip(encrypted, et))

def aes_xts_decrypt(key, tweak, ciphertext):
    """Decrypt using AES-XTS construction."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(tweak) != 16:
        raise ValueError("Tweak must be 16 bytes")
    if len(ciphertext) != 16:
        raise ValueError("Ciphertext must be 16 bytes")
    
    # Split key into two halves
    k1 = key[:16]
    k2 = key[16:]
    
    # Encrypt tweak with second key
    cipher2 = AES.new(k2, AES.MODE_ECB)
    et = cipher2.encrypt(tweak)
    
    # XOR ciphertext with encrypted tweak
    xored = bytes(a ^ b for a, b in zip(ciphertext, et))
    
    # Decrypt with first key
    cipher1 = AES.new(k1, AES.MODE_ECB)
    decrypted = cipher1.decrypt(xored)
    
    # XOR result with encrypted tweak
    return bytes(a ^ b for a, b in zip(decrypted, et))

def encrypt(ip, key):
    """Encrypt an IP address using AES-XTS."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    
    # Generate random 16-byte tweak
    tweak = os.urandom(16)
    
    # Convert IP to 16 bytes
    plaintext = ip_to_bytes(ip)
    
    # Encrypt using AES-XTS
    ciphertext = aes_xts_encrypt(key, tweak, plaintext)
    
    # Return tweak and ciphertext concatenated as hex string
    return tweak + ciphertext

def decrypt(binary_output, key):
    """Decrypt a binary output using AES-XTS."""
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    if len(binary_output) != 32:  # 16 bytes tweak + 16 bytes ciphertext
        raise ValueError("Binary output must be 32 bytes")
    
    # Split into tweak and ciphertext
    tweak = binary_output[:16]
    ciphertext = binary_output[16:]
    
    # Decrypt using AES-XTS
    plaintext = aes_xts_decrypt(key, tweak, ciphertext)
    
    # Convert back to IP address
    return bytes_to_ip(plaintext) 