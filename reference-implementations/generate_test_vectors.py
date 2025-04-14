#!/usr/bin/env python3
"""
Generate test vectors for all ipcrypt variants:
- ipcrypt-deterministic (AES128)
- ipcrypt-nd (KIASU-BC)
- ipcrypt-ndx (AES-XTS)
"""

import json
import binascii
import ipaddress
from ipcrypt_deterministic import encrypt as det_encrypt, decrypt as det_decrypt, ip_to_bytes, bytes_to_ip
from ipcrypt_nd import encrypt as nd_encrypt, decrypt as nd_decrypt, kiasu_bc_encrypt
from ipcrypt_ndx import encrypt as ndx_encrypt, decrypt as ndx_decrypt, aes_xts_encrypt

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
    
    # Test keys (16 bytes for AES128 and KIASU-BC)
    keys_16 = [
        bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,  # Big-endian pattern
               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]),
        bytes([0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,  # Little-endian pattern
               0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]),
        bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,  # AES test vector key
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
    ]
    
    # Test keys (32 bytes for AES-XTS)
    keys_32 = [
        bytes([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,  # Big-endian pattern
               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
               0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,  # Little-endian pattern
               0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01]),
        bytes([0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,  # Little-endian pattern
               0xef, 0xcd, 0xab, 0x89, 0x67, 0x45, 0x23, 0x01,
               0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,  # Big-endian pattern
               0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]),
        bytes([0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,  # K1: AES test vector key
               0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
               0x3c, 0x4f, 0xcf, 0x09, 0x88, 0x15, 0xf7, 0xab,  # K2: Reversed AES test vector key
               0xa6, 0xd2, 0xae, 0x28, 0x16, 0x15, 0x7e, 0x2b])
    ]
    
    # Fixed tweaks for test vectors
    tweak_8 = bytes([0x08, 0xe0, 0xc2, 0x89, 0xbf, 0xf2, 0x3b, 0x7c])  # For ipcrypt-nd
    tweak_16 = bytes([0x21, 0xbd, 0x18, 0x34, 0xbc, 0x08, 0x8c, 0xd2,  # For ipcrypt-ndx
                     0xb4, 0xec, 0xbe, 0x30, 0xb7, 0x08, 0x98, 0xd7])
    
    # Test IP addresses
    test_cases = [
        # Test vector 1
        {
            'ip': '0.0.0.0',
            'key_16': keys_16[0],
            'key_32': keys_32[0],
            'expected_encrypted': '7a73:3179:bcf3:5036:5f4b:754d:9518:fb70'
        },
        # Test vector 2
        {
            'ip': '255.255.255.255',
            'key_16': keys_16[1],
            'key_32': keys_32[1],
            'expected_encrypted': '105d:f4d1:e4b7:4dca:12b3:f38c:4c3c:d9c'
        },
        # Test vector 3
        {
            'ip': '192.0.2.1',
            'key_16': keys_16[2],
            'key_32': keys_32[2],
            'expected_encrypted': '2001:db8:85a3::8a2e:370:7334'
        },
        # Test vector 4 (IPv6 to IPv4)
        {
            'ip': '2001:db8:85a3::8a2e:370:7334',
            'key_16': keys_16[0],
            'key_32': keys_32[0],
            'expected_encrypted': '192.0.2.1'
        },
        # Test vector 5 (IPv4 to IPv6)
        {
            'ip': '192.0.2.1',
            'key_16': keys_16[1],
            'key_32': keys_32[1],
            'expected_encrypted': '2001:db8:85a3::8a2e:370:7334'
        }
    ]
    
    # Generate test vectors
    for case in test_cases:
        ip = normalize_ip(case['ip'])
        print(f"\nTesting with IP: {ip}")
        
        # ipcrypt-deterministic
        encrypted_ip = det_encrypt(ip, case['key_16'])
        decrypted_ip = normalize_ip(det_decrypt(encrypted_ip, case['key_16']))
        print(f"Deterministic: {ip} -> {encrypted_ip} -> {decrypted_ip}")
        print(f"Expected: {case['expected_encrypted']}")
        assert str(decrypted_ip) == str(ip)
        vectors.append({
            'variant': 'ipcrypt-deterministic',
            'key': binascii.hexlify(case['key_16']).decode(),
            'ip': str(ip),
            'encrypted_ip': str(encrypted_ip)
        })
        
        # ipcrypt-nd
        # Use fixed tweak instead of random
        plaintext = ip_to_bytes(ip)
        ciphertext = kiasu_bc_encrypt(case['key_16'], tweak_8, plaintext)
        binary_output = tweak_8 + ciphertext
        decrypted_ip = normalize_ip(nd_decrypt(binary_output, case['key_16']))
        print(f"KIASU-BC: {ip} -> {binascii.hexlify(binary_output).decode()} -> {decrypted_ip}")
        assert str(decrypted_ip) == str(ip)
        vectors.append({
            'variant': 'ipcrypt-nd',
            'key': binascii.hexlify(case['key_16']).decode(),
            'ip': str(ip),
            'tweak': binascii.hexlify(tweak_8).decode(),
            'output': binascii.hexlify(binary_output).decode()
        })
        
        # ipcrypt-ndx
        # Use fixed tweak instead of random
        plaintext = ip_to_bytes(ip)
        ciphertext = aes_xts_encrypt(case['key_32'], tweak_16, plaintext)
        binary_output = tweak_16 + ciphertext
        decrypted_ip = normalize_ip(ndx_decrypt(binary_output, case['key_32']))
        print(f"AES-XTS: {ip} -> {binascii.hexlify(binary_output).decode()} -> {decrypted_ip}")
        assert str(decrypted_ip) == str(ip)
        vectors.append({
            'variant': 'ipcrypt-ndx',
            'key': binascii.hexlify(case['key_32']).decode(),
            'ip': str(ip),
            'tweak': binascii.hexlify(tweak_16).decode(),
            'output': binascii.hexlify(binary_output).decode()
        })
    
    return vectors

def main():
    """Generate and save test vectors."""
    vectors = generate_test_vectors()
    with open('test_vectors.json', 'w') as f:
        json.dump(vectors, f, indent=2)
    print(f"\nGenerated {len(vectors)} test vectors")
    print(f"- {sum(1 for v in vectors if v['variant'] == 'ipcrypt-deterministic')} deterministic vectors")
    print(f"- {sum(1 for v in vectors if v['variant'] == 'ipcrypt-nd')} KIASU-BC vectors")
    print(f"- {sum(1 for v in vectors if v['variant'] == 'ipcrypt-ndx')} AES-XTS vectors")

if __name__ == '__main__':
    main() 