"""Encrypted column type with integrity checking (#88).

`AesGcmEngine` uses a random nonce per value (equal plaintexts no longer give equal
ciphertexts) and an authentication tag, so a tampered or wrongly keyed value is refused
instead of decrypting to garbage. A refused value must never become a 500 or leak details:
it reads as UNREADABLE, the request is flagged so an audit row is written once, and the
marker can never be written back over the stored ciphertext.
"""

import logging

from flask import g, has_request_context
from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesGcmEngine, InvalidCiphertextError

logger = logging.getLogger(__name__)

UNREADABLE = "[unreadable: failed integrity check]"


def _note_unreadable():
    logger.warning("An encrypted value failed its integrity check")  # never the value
    if has_request_context():
        g.unreadable_encrypted_values = g.get("unreadable_encrypted_values", 0) + 1


class IntegrityCheckedEncryptedType(EncryptedType):
    """EncryptedType with AES-GCM that turns integrity failures into a safe marker."""

    cache_ok = True

    def __init__(self, type_in, key):
        super().__init__(type_in, key, AesGcmEngine)

    def process_bind_param(self, value, dialect):
        if value == UNREADABLE:
            # Saving the marker would overwrite (destroy) the evidence of tampering.
            raise ValueError("Refusing to store the unreadable marker over an encrypted value.")
        return super().process_bind_param(value, dialect)

    def process_result_value(self, value, dialect):
        try:
            return super().process_result_value(value, dialect)
        except (InvalidCiphertextError, ValueError, UnicodeDecodeError):
            _note_unreadable()
            return UNREADABLE
