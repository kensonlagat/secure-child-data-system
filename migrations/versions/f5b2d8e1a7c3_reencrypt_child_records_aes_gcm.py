"""re-encrypt sensitive child record columns with AES-GCM (#88)

Revision ID: f5b2d8e1a7c3
Revises: e3a8c6b2f415
Create Date: 2026-11-16 23:00:00.000000

full_name, guardian_contact and medical_notes were encrypted with AesEngine, which uses a
fixed IV derived from the key, so equal plaintexts gave equal ciphertexts. This rewrites
every stored value with AesGcmEngine (random nonce, authentication tag). The column type
(bytea) does not change.

Safety:
- Needs FIELD_ENCRYPTION_KEY (the same key the app uses). Take a backup first.
- Every value is decrypted with the old engine, encrypted with the new one, and decrypted
  again; any mismatch, or any value the old engine cannot read, stops the migration and
  rolls everything back. Error messages carry row ids only, never values.
- Values that already decrypt with AES-GCM are left alone, so a rerun is safe.
- The downgrade reverses the process (AES-GCM back to AesEngine).
"""
import os

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'f5b2d8e1a7c3'
down_revision = 'e3a8c6b2f415'
branch_labels = None
depends_on = None

COLUMNS = ("full_name", "guardian_contact", "medical_notes")


def _key():
    key = None
    try:
        from flask import current_app

        key = current_app.config.get("FIELD_ENCRYPTION_KEY")
    except RuntimeError:
        pass
    key = key or os.environ.get("FIELD_ENCRYPTION_KEY")
    if not key:
        raise RuntimeError("FIELD_ENCRYPTION_KEY is required to re-encrypt child records.")
    return key


def _types(key):
    import warnings

    from sqlalchemy_utils import EncryptedType
    from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine, AesGcmEngine

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        old = EncryptedType(sa.String, key, AesEngine, "pkcs5")
        new = EncryptedType(sa.String, key, AesGcmEngine)
    return old, new


def _try_decrypt(type_, raw, dialect):
    try:
        return True, type_.process_result_value(raw, dialect)
    except Exception:
        return False, None


def _rewrite(source, target, *, to_gcm):
    gcm = target if to_gcm else source
    conn = op.get_bind()
    dialect = conn.dialect
    rows = conn.execute(sa.text(f"SELECT id, {', '.join(COLUMNS)} FROM child_records ORDER BY id")).all()
    unreadable, rewritten = [], 0
    for row in rows:
        updates = {}
        for column in COLUMNS:
            stored = getattr(row, column)
            if stored is None:
                continue
            raw = bytes(stored)  # psycopg2 returns memoryview; EncryptedType only decrypts bytes
            # Always ask the authenticated engine (AES-GCM) first: AesEngine has no tag, so it
            # can occasionally "decrypt" a GCM value into garbage without raising.
            is_gcm, gcm_plaintext = _try_decrypt(gcm, raw, dialect)
            if to_gcm and is_gcm:
                continue  # already re-encrypted (rerun)
            if not to_gcm and not is_gcm:
                if _try_decrypt(target, raw, dialect)[0]:
                    continue  # already back in the old format (rerun)
                unreadable.append(f"{row.id}.{column}")
                continue
            if is_gcm:
                ok, plaintext = True, gcm_plaintext
            else:
                ok, plaintext = _try_decrypt(source, raw, dialect)
            if not ok or plaintext is None:
                unreadable.append(f"{row.id}.{column}")
                continue
            new_raw = target.process_bind_param(plaintext, dialect)
            check_ok, check_value = _try_decrypt(target, bytes(new_raw), dialect)
            if not check_ok or check_value != plaintext:
                raise RuntimeError(f"Round-trip check failed for child_records {row.id}.{column}; nothing was changed.")
            updates[column] = new_raw
        if updates:
            assignments = ", ".join(f"{column} = :{column}" for column in updates)
            conn.execute(sa.text(f"UPDATE child_records SET {assignments} WHERE id = :id"), {**updates, "id": row.id})
            rewritten += 1
    if unreadable:
        raise RuntimeError(
            f"{len(unreadable)} stored value(s) could not be read with the current key "
            f"(child_records {', '.join(unreadable[:20])}); nothing was changed."
        )

    # Final check: every stored value is now in the target format.
    for row in conn.execute(sa.text(f"SELECT id, {', '.join(COLUMNS)} FROM child_records")).all():
        for column in COLUMNS:
            stored = getattr(row, column)
            if stored is None:
                continue
            is_gcm = _try_decrypt(gcm, bytes(stored), dialect)[0]
            if is_gcm != to_gcm or not _try_decrypt(target, bytes(stored), dialect)[0]:
                raise RuntimeError(f"child_records {row.id}.{column} is not in the target format after re-encryption.")
    return rewritten


def upgrade():
    old, new = _types(_key())
    _rewrite(source=old, target=new, to_gcm=True)


def downgrade():
    old, new = _types(_key())
    _rewrite(source=new, target=old, to_gcm=False)
