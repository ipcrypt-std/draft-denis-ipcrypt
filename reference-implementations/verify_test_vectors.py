#!/usr/bin/env python3
"""
Verify test vectors from the document against our implementation.
"""

import binascii
from ipcrypt_deterministic import encrypt as det_encrypt
from ipcrypt_nd import encrypt as nd_encrypt, kiasu_bc_encrypt, ip_to_bytes
from ipcrypt_ndx import encrypt as ndx_encrypt, aes_xts_encrypt

TEST_VECTORS = {
    'deterministic': [
        {
            'key': "0123456789abcdeffedcba9876543210",
            'ip': "0.0.0.0",
            'expected': "bde9:6789:d353:824c:d7c6:f58a:6bd2:26eb"
        },
        {
            'key': "1032547698badcfeefcdab8967452301",
            'ip': "255.255.255.255",
            'expected': "aed2:92f6:ea23:58c3:48fd:8b8:74e8:45d8"
        },
        {
            'key': "2b7e151628aed2a6abf7158809cf4f3c",
            'ip': "192.0.2.1",
            'expected': "1dbd:c1b9:fff1:7586:7d0b:67b4:e76e:4777"
        }
    ],
    'nd': [
        {
            'key': "0123456789abcdeffedcba9876543210",
            'ip': "0.0.0.0",
            'tweak': "08e0c289bff23b7c",
            'expected': "08e0c289bff23b7cb349aadfe3bcef56221c384c7c217b16"
        },
        {
            'key': "1032547698badcfeefcdab8967452301",
            'ip': "192.0.2.1",
            'tweak': "21bd1834bc088cd2",
            'expected': "21bd1834bc088cd2e5e1fe55f95876e639faae2594a0caad"
        },
        {
            'key': "2b7e151628aed2a6abf7158809cf4f3c",
            'ip': "2001:db8::1",
            'tweak': "b4ecbe30b70898d7",
            'expected': "b4ecbe30b70898d7553ac8974d1b4250eafc4b0aa1f80c96"
        }
    ],
    'ndx': [
        {
            'key': "0123456789abcdeffedcba98765432101032547698badcfeefcdab8967452301",
            'ip': "0.0.0.0",
            'tweak': "21bd1834bc088cd2b4ecbe30b70898d7",
            'expected': "21bd1834bc088cd2b4ecbe30b70898d782db0d4125fdace61db35b8339f20ee5"
        },
        {
            'key': "1032547698badcfeefcdab89674523010123456789abcdeffedcba9876543210",
            'ip': "192.0.2.1",
            'tweak': "08e0c289bff23b7cb4ecbe30b70898d7",
            'expected': "08e0c289bff23b7cb4ecbe30b70898d7766a533392a69edf1ad0d3ce362ba98a"
        },
        {
            'key': "2b7e151628aed2a6abf7158809cf4f3c3c4fcf098815f7aba6d2ae2816157e2b",
            'ip': "2001:db8::1",
            'tweak': "21bd1834bc088cd2b4ecbe30b70898d7",
            'expected': "21bd1834bc088cd2b4ecbe30b70898d76089c7e05ae30c2d10ca149870a263e4"
        }
    ]
}


def verify_vectors():
    """Verify all test vectors."""
    for variant, vectors in TEST_VECTORS.items():
        print(f"\nVerifying ipcrypt-{variant} test vectors:")
        for i, test in enumerate(vectors, 1):
            key = binascii.unhexlify(test['key'])
            if variant == 'deterministic':
                result = str(det_encrypt(test['ip'], key))
            else:
                tweak = binascii.unhexlify(test['tweak'])
                if variant == 'nd':
                    plaintext = ip_to_bytes(test['ip'])
                    ciphertext = kiasu_bc_encrypt(key, tweak, plaintext)
                    result = binascii.hexlify(tweak + ciphertext).decode()
                else:  # ndx
                    plaintext = ip_to_bytes(test['ip'])
                    ciphertext = aes_xts_encrypt(key, tweak, plaintext)
                    result = binascii.hexlify(tweak + ciphertext).decode()

            print(f"Test vector {i}: {test['ip']} -> {result}")
            print(f"Expected: {test['expected']}")
            print(f"Match: {result == test['expected']}")


if __name__ == '__main__':
    verify_vectors()
