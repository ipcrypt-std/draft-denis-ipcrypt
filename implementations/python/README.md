# IPCrypt

A Python implementation of IP address encryption and obfuscation methods as defined in the IPCrypt specification.

## Features

IPCrypt provides several methods for encrypting and obfuscating IP addresses:

- **Deterministic**: Deterministic, format-preserving IP address encryption
- **ND (Non-deterministic)**: Non-deterministic IP address encryption with random padding
- **NDX (Non-deterministic Extended)**: Extended non-deterministic encryption with variable-length output
- **PFX (Prefix-preserving)**: Prefix-preserving IP address encryption

All methods support both IPv4 and IPv6 addresses.

## Installation

Install using pip:

```bash
pip install ipcrypt
```

## Usage

### Deterministic Encryption

```python
from ipcrypt import deterministic_encrypt, deterministic_decrypt

# Encrypt an IP address
key = b'sixteen byte key'  # 16-byte key for AES-128
encrypted = deterministic_encrypt('192.168.1.1', key)
print(f"Encrypted: {encrypted}")

# Decrypt it back
decrypted = deterministic_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")
```

### Non-deterministic Encryption (ND)

```python
from ipcrypt import nd_encrypt, nd_decrypt

key = b'sixteen byte key'
encrypted = nd_encrypt('192.168.1.1', key)
print(f"Encrypted: {encrypted}")

decrypted = nd_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")
```

### Non-deterministic Extended (NDX)

```python
from ipcrypt import ndx_encrypt, ndx_decrypt

key = b'sixteen byte key'
encrypted = ndx_encrypt('192.168.1.1', key)
print(f"Encrypted: {encrypted}")

decrypted = ndx_decrypt(encrypted, key)
print(f"Decrypted: {decrypted}")
```

### Prefix-preserving Encryption (PFX)

```python
from ipcrypt import pfx_encrypt, pfx_decrypt

key = b'sixteen byte key'
prefix_len = 8  # Preserve first 8 bits

# Encrypt while preserving prefix
encrypted = pfx_encrypt('192.168.1.1', key, prefix_len)
print(f"Encrypted: {encrypted}")

# Decrypt it back
decrypted = pfx_decrypt(encrypted, key, prefix_len)
print(f"Decrypted: {decrypted}")
```

## Requirements

- Python 3.8 or higher
- cryptography >= 41.0.0
- pycryptodome >= 3.18.0

## Development

To set up a development environment:

```bash
# Clone the repository
git clone https://github.com/ipcrypt-std/draft-denis-ipcrypt
cd draft-denis-ipcrypt/implementations/python

# Install in development mode
pip install -e ".[dev]"

# Run tests
pytest

# Run linting
ruff check .
black --check .
```

## License

This project is licensed under the BSD 3-Clause License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please see the [contributing guidelines](https://github.com/ipcrypt-std/draft-denis-ipcrypt/blob/main/CONTRIBUTING.md) for more information.

## Links

- [IPCrypt Specification](https://ipcrypt-std.github.io/draft-denis-ipcrypt/)
- [GitHub Repository](https://github.com/ipcrypt-std/draft-denis-ipcrypt)
- [Issue Tracker](https://github.com/ipcrypt-std/draft-denis-ipcrypt/issues)