"""
Child Record model.

Shared core schema + mode-specific extension fields, matching your proposal's
database design decision (School Mode vs Children's Home Mode share a core
record but diverge on sensitive fields).

Sensitive columns use EncryptedType from sqlalchemy-utils (field-level
encryption backed by FIELD_ENCRYPTION_KEY), so data is encrypted at rest
even if the raw DB file/backup is exposed.
"""
from datetime import datetime
from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine
from app import db
from app.config import BaseConfig


def _encryption_key():
    return BaseConfig.FIELD_ENCRYPTION_KEY


class ChildRecord(db.Model):
    __tablename__ = "child_records"

    id = db.Column(db.Integer, primary_key=True)

    # --- Core fields (shared by both modes) ---
    full_name = db.Column(EncryptedType(db.String, _encryption_key, AesEngine, "pkcs5"))
    date_of_birth = db.Column(db.Date, nullable=False)
    institution_mode = db.Column(db.String(20), nullable=False)
    # "school" or "childrens_home" — determines which extension fields apply

    # --- School Mode fields ---
    guardian_contact = db.Column(EncryptedType(db.String, _encryption_key, AesEngine, "pkcs5"))
    # Legacy free text (#48): no longer read for scoping or writable. Kept read-only for one
    # release, then dropped. The current class comes from `enrolments` (see class_label).
    class_assigned = db.Column(db.String(50))

    # --- Children's Home Mode fields ---
    legal_status = db.Column(db.String(50))
    # e.g. "in_state_care", "eligible_for_adoption", "placed"
    caseload_worker_id = db.Column(db.Integer, db.ForeignKey("users.id"))
    caseload_worker = db.relationship("User", foreign_keys=[caseload_worker_id])
    medical_notes = db.Column(EncryptedType(db.String, _encryption_key, AesEngine, "pkcs5"))

    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    deleted_at = db.Column(db.DateTime)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    @property
    def class_label(self):
        """Label of the child's current class (#48), or None when not enrolled. Read-only:
        enrolment changes go through app/services/enrolment_service.py."""
        from app.models.school_class import Enrolment

        enrolment = Enrolment.query.filter_by(child_record_id=self.id, ended_on=None).first()
        return enrolment.school_class.label if enrolment else None

    def __repr__(self):
        return f"<ChildRecord id={self.id} mode={self.institution_mode}>"
