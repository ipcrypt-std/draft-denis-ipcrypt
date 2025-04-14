---
title: "Methods for IP Address Encryption and Obfuscation"
abbrev: "ipcrypt"
docname: draft-denis-ipcrypt-latest
category: info
ipr: trust200902
keyword: Internet-Draft
author:
  - name: "Frank Denis"
    organization: "Fastly Inc."
    email: fde@00f.net
date: "2025-04-14"
v: 3
stand_alone: yes
smart_quotes: yes
pi: [toc, sortrefs, symrefs]

normative:
  FIPS-197:
    title: "Advanced Encryption Standard (AES)"
    author:
      - ins: NIST
        org: National Institute of Standards and Technology
    date: 2001-11-26
    seriesinfo:
      FIPS: PUB 197
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
  NIST-SP-800-38G:
    title: "Recommendation for Block Cipher Modes of Operation: Methods for Format-Preserving Encryption"
    author:
      - ins: NIST
        org: National Institute of Standards and Technology
    date: 2016-03
    seriesinfo:
      NIST: SP 800-38G
    target: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-38G.pdf

informative:
  LRW2002:
    title: "Tweakable Block Ciphers"
    author:
      - ins: M. Liskov
      - ins: R. Rivest
      - ins: D. Wagner
    date: 2002
    seriesinfo:
      Fast Software Encryption: 2002
    target: https://www.cs.berkeley.edu/~daw/papers/tweak-crypto02.pdf
    doi: 10.1007/3-540-45661-9_17
  IEEE-P1619:
    title: "IEEE Standard for Cryptographic Protection of Data on Block-Oriented Storage Devices"
    author:
      - ins: IEEE
    date: 2007-12-18
    seriesinfo:
      IEEE: 1619-2007
    target: https://standards.ieee.org/ieee/1619/2041/
  BRW2005:
    title: "Format-Preserving Encryption"
    author:
      - ins: M. Bellare
      - ins: P. Rogaway
      - ins: D. Wagner
    date: 2005
    seriesinfo:
      CRYPTO: 2005
    target: https://www.cs.ucdavis.edu/~rogaway/papers/subset.pdf
    doi: 10.1007/11535218_24
  KIASU-BC:
    title: "Tweaks and Keys for Block Ciphers: the TWEAKEY Framework"
    author:
      - ins: J. Jean
      - ins: I. Nikolić
      - ins: T. Peyrin
    date: 2014
    seriesinfo:
      Cryptology ePrint Archive: Paper 2014/831
    target: https://eprint.iacr.org/2014/831
    eprint: 2014/831
  XTS-AES:
    title: "The XTS-AES Mode for Disk Encryption"
    author:
      - ins: J. Black
      - ins: E. Dawson
      - ins: S. Gueron
      - ins: P. Rogaway
    date: 2010
    seriesinfo:
      IEEE: 1619-2007
    target: https://web.cs.ucdavis.edu/~rogaway/papers/xts.pdf
    doi: 10.1109/TC.2010.58
  IPCrypt2:
    title: "ipcrypt2: IP address encryption/obfuscation tool"
    author:
      - ins: F. Denis
    date: 2025
    target: https://github.com/jedisct1/ipcrypt2

--- abstract

This document specifies methods for encrypting and obfuscating IP addresses, providing both deterministic format‑preserving and non‑deterministic constructions. These methods address privacy concerns raised in {{!RFC6973}} and {{!RFC7258}} regarding pervasive monitoring and data collection.

The methods apply uniformly to both IPv4 and IPv6 addresses by converting them into a 16‑byte representation. Two generic constructions are defined—one using a 128‑bit block cipher and the other using a 128‑bit tweakable block cipher—along with three concrete instantiations:

- **`ipcrypt-deterministic`:** Deterministic encryption using AES128 (applied as a single‑block operation).
- **`ipcrypt-nd`:** Non‑deterministic encryption using the KIASU‑BC tweakable block cipher with an 8‑byte tweak.
- **`ipcrypt-ndx`:** Non‑deterministic encryption using the AES‑XEX tweakable block cipher with a 16‑byte tweak.

Deterministic mode produces a 16‑byte ciphertext (enabling format preservation), while non‑deterministic modes prepend a randomly sampled tweak (which MUST be uniformly random when generated, as specified in {{!RFC4086}}) to produce larger ciphertexts that resist correlation attacks.

--- middle

# Introduction

This document specifies a standard for the encryption and obfuscation of IP addresses for both operational use and privacy preservation. The objective is to enable network operators, researchers, and privacy advocates to share or analyze data while protecting sensitive address information, addressing concerns raised in {{!RFC7624}} regarding confidentiality in the face of pervasive surveillance.

## Use Cases and Motivations

The main motivations include:

- **Privacy Protection:** Encrypting IP addresses prevents the disclosure of user-specific information when data is logged or measured, as discussed in {{!RFC6973}}.
- **Format Preservation:** Ensuring that the encrypted output remains a valid IP address allows network devices to process the data without modification.
- **Mitigation of Correlation Attacks:** Deterministic encryption reveals repeated inputs; non‑deterministic modes use a random tweak to obscure linkability while keeping the underlying input confidential.

# Terminology

The key words "MUST", "MUST NOT", "REQUIRED", "SHALL", "SHALL NOT", "SHOULD", "SHOULD NOT", "RECOMMENDED", "NOT RECOMMENDED", "MAY", and "OPTIONAL" in this document are to be interpreted as described in BCP 14 {{!RFC8174}} when, and only when, they appear in all capitals, as shown here.

Throughout this document, the following terms and conventions apply:

- **IP Address:** An IPv4 or IPv6 address as defined in {{!RFC4291}}.
- **16‑Byte Representation:** A fixed-length representation used for both IPv4 (via IPv4‑mapped IPv6) and IPv6 addresses.
- **Tweak:** A non‑secret, additional input to a tweakable block cipher that further randomizes the output.
- **Deterministic Encryption:** Encryption that always produces the same ciphertext for a given input and key.
- **Non‑Deterministic Encryption:** Encryption that produces different ciphertexts for the same input due to the inclusion of a randomly sampled tweak.
- **(Input, Tweak) Collision:** A scenario where the same input is encrypted with the same tweak; this reveals that the input was repeated but not the input's value.

# IP Address Conversion

This section describes the conversion of IP addresses to and from a 16‑byte representation. This conversion is necessary to operate a 128‑bit cipher on both IPv4 and IPv6 addresses.

## Converting to a 16‑Byte Representation

### IPv6 Addresses

IPv6 addresses are natively 128 bits and are converted directly using network‑byte order (big‑endian) as specified in {{!RFC4291}}.

_Example:_

~~~
IPv6 Address:    2001:0db8:85a3:0000:0000:8a2e:0370:7334
16-Byte Representation: [20 01 0d b8 85 a3 00 00 00 00 8a 2e 03 70 73 34]
~~~

### IPv4 Addresses

IPv4 addresses (32 bits) are mapped using the IPv4‑mapped IPv6 format:

~~~
IPv4 Address:    192.0.2.1
16-Byte Representation: [00 00 00 00 00 00 00 00 00 00 FF FF C0 00 02 01]
~~~

## Converting from a 16‑Byte Representation to an IP Address

The conversion algorithm is as follows:

1. Examine the first 12 bytes of the 16-byte representation
2. If they match the IPv4‑mapped prefix (10 bytes of 0x00 followed by 0xFF, 0xFF):
   - Interpret the last 4 bytes as an IPv4 address in dotted‑decimal notation
3. Otherwise:
   - Interpret the 16 bytes as an IPv6 address in colon‑hexadecimal notation

(For additional illustration, see Appendix B.)

# Generic Constructions

This specification defines two generic cryptographic constructions:

1. **128-bit Block Cipher Construction:**
   - Used in deterministic encryption
   - Operates on a single 16-byte block
   - Example: AES‑128 treated as a permutation

2. **128-bit Tweakable Block Cipher (TBC) Construction:**
   - Used in non‑deterministic encryption
   - Accepts a key, a tweak, and a message
   - The tweak is typically randomly sampled (and MUST be uniformly random when generated)
   - Reuse of the same tweak on different inputs does not compromise confidentiality

Valid options for implementing a tweakable block cipher include, but are not limited to:

- **SKINNY**
- **DEOXYS-BC**
- **KIASU-BC**
- **AES-XEX**

Implementers MUST choose a cipher that meets the required security properties and provides robust resistance against related-tweak and other cryptographic attacks.

# Deterministic Encryption

Deterministic encryption applies a 128‑bit block cipher directly to the 16‑byte representation of an IP address.

## Specific Instantiation: ipcrypt-deterministic

This instantiation employs AES128 in a single‑block operation. Since AES128 is a permutation, every distinct 16‑byte input maps to a unique 16‑byte ciphertext, preserving the IP address format.

### Operation Flow Diagram

~~~
      +---------------------+
      |      IP Address     |
      |    (IPv4 or IPv6)   |
      +---------------------+
                 |
                 v
      +---------------------+
      | Convert to 16 Bytes |
      +---------------------+
                 |
                 v
      +---------------------+
      |   AES128 Encrypt    |
      |   (Single Block)    |
      +---------------------+
                 |
                 v
      +---------------------+
      |    16-Byte Output   |
      +---------------------+
                 |
                 v
      +---------------------+
      | Convert to IP Format|
      +---------------------+
~~~

## Format Preservation

- If the 16‑byte ciphertext begins with an IPv4‑mapped prefix, it **MUST** be rendered as a dotted‑decimal IPv4 address.
- Otherwise, it is interpreted as an IPv6 address.

> **Note:**
> To ensure IPv4 format preservation, implementers **MUST** consider using cycle‑walking or an FPE mode if required.

# Non‑Deterministic Encryption

Non‑deterministic encryption leverages a tweakable block cipher together with a random tweak.

Although the tweak is generated uniformly at random (and thus may occasionally collide per birthday bounds), such collisions are benign when they occur with different inputs. An (input, tweak) collision reveals that the same input was encrypted with the same tweak but does not disclose the input's value.

The usage limits discussed below apply per cryptographic key; rotating keys can extend secure usage beyond these bounds.

This document defines two instantiations:

- **`ipcrypt-nd`:** Uses the KIASU‑BC tweakable block cipher with an 8‑byte (64‑bit) tweak.
  See [KIASU-BC] for details.
- **`ipcrypt-ndx`:** Uses the AES‑XEX tweakable block cipher with a 16‑byte (128‑bit) tweak.
  See [XTS-AES] for background.

In both cases, if a tweak is generated randomly, it **MUST be uniformly random**. Reusing the same randomly generated tweak on different inputs is acceptable from a confidentiality standpoint.

## ipcrypt-nd (KIASU‑BC)

- **Tweak:** 8 bytes (64 bits).
- **Output:** 24 bytes total (8‑byte tweak concatenated with a 16‑byte ciphertext).

### Usage Considerations

Random sampling of an 8‑byte tweak yields an expected collision for a specific tweak value after about 2^(64/2) = 2^32 operations.

If an (input, tweak) collision occurs, it indicates that the same input was processed with that tweak without revealing the input's value. These collision bounds apply per cryptographic key; by rotating keys regularly, secure usage can be extended well beyond these bounds.

Ultimately, the effective security is determined by the underlying block cipher's strength (≈2^128 for AES‑128).

## ipcrypt-ndx (AES‑XEX)

- **Tweak:** 16 bytes (128 bits).
- **Output:** 32 bytes total (16‑byte tweak concatenated with a 16‑byte ciphertext).

### Usage Considerations

Independent sampling of a 16‑byte tweak results in an expected collision after about 2^(128/2) = 2^64 operations.

As with ipcrypt-nd, an (input, tweak) collision reveals repetition without compromising the input value.

These limits are per key; regular key rotation further extends secure usage. The effective security is governed by the strength of AES‑128 (approximately 2^128 operations).

## Comparison of Modes

- **Deterministic (`ipcrypt-deterministic`):**
  Produces a 16‑byte output; preserves format but reveals repeated inputs.
- **Non‑Deterministic:**
  - **`ipcrypt-nd` (KIASU‑BC):** Produces a 24‑byte output using an 8‑byte tweak; (input, tweak) collisions reveal repeated inputs (with the same tweak) but not their values.
  - **`ipcrypt-ndx` (AES‑XEX):** Produces a 32‑byte output using a 16‑byte tweak; supports higher secure operation counts per key.

# Security Considerations

- **Deterministic Mode:**
  AES‑128's permutation behavior ensures distinct inputs yield distinct outputs; however, repeated inputs result in identical ciphertexts, thereby revealing repetition.

- **Non‑Deterministic Mode:**
  The inclusion of a random tweak ensures that encrypting the same input generally produces different outputs.

  In cases where an (input, tweak) collision occurs, an attacker learns only that the same input was processed with that tweak, not the value of the input itself. Security is determined by the underlying block cipher (≈2^128 for AES‑128) on a per-key basis.

  Key rotation is recommended to extend secure usage beyond the per-key collision bounds.

# IANA Considerations

This document does not require any IANA actions.

--- back

# Acknowledgments

The author gratefully acknowledges the contributions and insightful comments from members of the IETF independent stream community and the broader cryptographic community that have helped shape this specification.

# Appendices

## Appendix A. Pseudocode and Examples

This appendix provides detailed pseudocode for key operations described in this document.

### IPv4 Address Conversion

~~~pseudocode
function IPv4To16Bytes(ipv4_address):
    // Split the IPv4 address into its octets
    parts = ipv4_address.split(".")
    if length(parts) != 4:
         raise Error("Invalid IPv4 address")
    // Create a 16-byte array with the IPv4-mapped prefix
    bytes16 = [0x00] * 10         // 10 bytes of 0x00
    bytes16.append(0xFF)          // 11th byte: 0xFF
    bytes16.append(0xFF)          // 12th byte: 0xFF
    // Append each octet (converted to an 8-bit integer)
    for part in parts:
         bytes16.append(int(part) & 0xFF)
    return bytes16
~~~

_Example:_ For `"192.0.2.1"`, the function returns

~~~
[00, 00, 00, 00, 00, 00, 00, 00, 00, 00, FF, FF, C0, 00, 02, 01]
~~~

### IPv6 Address Conversion

~~~pseudocode
function IPv6To16Bytes(ipv6_address):
    // Parse the IPv6 address into eight 16-bit words.
    words = parseIPv6(ipv6_address)  // Expands shorthand notation and returns 8 words
    bytes16 = []
    for word in words:
         high_byte = (word >> 8) & 0xFF
         low_byte = word & 0xFF
         bytes16.append(high_byte)
         bytes16.append(low_byte)
    return bytes16
~~~

_Example:_ For `"2001:0db8:85a3:0000:0000:8a2e:0370:7334"`, the output is the corresponding 16‑byte sequence.

### Conversion from a 16-Byte Array to an IP Address

~~~pseudocode
function Bytes16ToIP(bytes16):
    if length(bytes16) != 16:
         raise Error("Invalid byte array")
    // Check for the IPv4-mapped prefix
    if bytes16[0:10] == [0x00]*10 and bytes16[10] == 0xFF and bytes16[11] == 0xFF:
         ipv4_parts = []
         for i from 12 to 15:
             ipv4_parts.append(str(bytes16[i]))
         ipv4_address = join(ipv4_parts, ".")
         return ipv4_address
    else:
         words = []
         for i from 0 to 15 step 2:
             word = (bytes16[i] << 8) | bytes16[i+1]
             words.append(format(word, "x"))
         ipv6_address = join(words, ":")
         return ipv6_address
~~~

### Deterministic Encryption (ipcrypt-deterministic)

~~~pseudocode
function ipcrypt_deterministic(ip_address, key):
    bytes16 = convertTo16Bytes(ip_address)
    ciphertext = AES128_encrypt(key, bytes16)
    encrypted_ip = Bytes16ToIP(ciphertext)
    return encrypted_ip
~~~

### Non‑Deterministic Encryption using KIASU‑BC (ipcrypt-nd)

~~~pseudocode
function ipcrypt_nd(ip_address, key):
    bytes16 = convertTo16Bytes(ip_address)
    // Generate an 8-byte random tweak (MUST be uniformly random)
    tweak = random_bytes(8)
    ciphertext = KIASU_BC_encrypt(key, tweak, bytes16)
    result = concatenate(tweak, ciphertext)  // 8 bytes || 16 bytes = 24 bytes total
    return result
~~~

### Non‑Deterministic Encryption using AES‑XEX (ipcrypt-ndx)

~~~pseudocode
function ipcrypt_ndx(ip_address, key):
    bytes16 = convertTo16Bytes(ip_address)
    // Generate a 16-byte random tweak (MUST be uniformly random)
    tweak = random_bytes(16)
    ciphertext = AES_XEX_encrypt(key, tweak, bytes16)
    result = concatenate(tweak, ciphertext)  // 16 bytes || 16 bytes = 32 bytes total
    return result
~~~

## Appendix B. Diagrams

### IPv4 Address Conversion Diagram

~~~
       IPv4: 192.0.2.1
           |
           v
  Octets:  C0  00  02  01
           |
           v
   16-Byte Array:
[00 00 00 00 00 00 00 00 00 00 | FF FF | C0 00 02 01]
~~~

### Deterministic Encryption Flow

~~~
            IP Address
                |
                v
      [Convert to 16 Bytes]
                |
                v
       [AES128 Single-Block Encrypt]
                |
                v
        16-Byte Ciphertext
                |
                v
        [Convert to IP Format]
                |
                v
         Encrypted IP Address
~~~

### Non‑Deterministic Encryption Flow (ipcrypt-nd)

~~~
              IP Address
                  |
                  v
      [Convert to 16 Bytes] ---> 16-Byte Representation
                  |
                  v
    [Generate Random 8-Byte Tweak]
                  |
                  v
       [KIASU-BC Tweakable Encrypt]
                  |
                  v
         16-Byte Ciphertext
                  |
                  v
    [Concatenate Tweak || Ciphertext]
                  |
                  v
         24-Byte Output (`ipcrypt-nd`)
~~~

### Non‑Deterministic Encryption Flow (ipcrypt-ndx)

~~~
              IP Address
                  |
                  v
      [Convert to 16 Bytes] ---> 16-Byte Representation
                  |
                  v
    [Generate Random 16-Byte Tweak]
                  |
                  v
       [AES-XEX Tweakable Encrypt]
                  |
                  v
         16-Byte Ciphertext
                  |
                  v
    [Concatenate Tweak || Ciphertext]
                  |
                  v
         32-Byte Output (`ipcrypt-ndx`)
~~~
