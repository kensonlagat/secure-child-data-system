"""Purpose-specific keys derived from SECRET_KEY (#73).

SECRET_KEY signs sessions. Every other keyed hash uses its own subkey,
HMAC-SHA256(SECRET_KEY, label), so no key is ever used directly for two purposes.
Purposes are a fixed allowlist so a typo can't silently create a new key.
"""

import hashlib
import hmac

from flask import current_app

SUBKEY_PURPOSES = frozenset({"audit-identifier", "change-phone-context"})
_LABEL_PREFIX = "cds-subkey-v1|"  # bump the version to rotate every subkey at once


def derive_subkey(purpose: str) -> bytes:
    if purpose not in SUBKEY_PURPOSES:
        raise ValueError(f"Unknown subkey purpose: {purpose!r}")
    secret = current_app.config["SECRET_KEY"]
    secret = secret if isinstance(secret, bytes) else secret.encode()
    return hmac.new(secret, (_LABEL_PREFIX + purpose).encode(), hashlib.sha256).digest()


def keyed_hash(purpose: str, message: str) -> str:
    """Hex HMAC-SHA256 of message under the purpose's subkey."""
    return hmac.new(derive_subkey(purpose), message.encode(), hashlib.sha256).hexdigest()
