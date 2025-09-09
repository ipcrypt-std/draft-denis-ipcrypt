"""IPCrypt: IP address encryption and obfuscation methods.

This package provides implementations of various IP address encryption
and obfuscation algorithms as defined in the IPCrypt specification.
"""

__version__ = "0.1.0"
__author__ = "IPCrypt Contributors"

from .deterministic import encrypt as deterministic_encrypt
from .deterministic import decrypt as deterministic_decrypt

from .nd import encrypt as nd_encrypt
from .nd import decrypt as nd_decrypt

from .ndx import encrypt as ndx_encrypt
from .ndx import decrypt as ndx_decrypt

from .pfx import encrypt as pfx_encrypt
from .pfx import decrypt as pfx_decrypt

__all__ = [
    "deterministic_encrypt",
    "deterministic_decrypt",
    "nd_encrypt",
    "nd_decrypt",
    "ndx_encrypt",
    "ndx_decrypt",
    "pfx_encrypt",
    "pfx_decrypt",
]