"""
User and Role models.

Design note: Role is a separate table (not an enum column) because your
proposal's roles carry different permission sets per institution mode
(Teacher/Nurse in School Mode; Social Worker/Legal Officer in Home Mode).
A table lets the Administrator manage roles without a code change.
"""
from datetime import datetime
from flask_login import UserMixin
from app import db


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    # e.g. "administrator", "teacher", "school_nurse",
    #      "social_worker", "legal_officer", "parent_guardian"
    institution_mode = db.Column(db.String(20), nullable=False)
    # "school", "childrens_home", or "both" (e.g. administrator)

    users = db.relationship("User", back_populates="role")

    def __repr__(self):
        return f"<Role {self.name}>"


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    full_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    phone_number = db.Column(db.String(20), nullable=False)
    # OTP and SMS notifications are delivered here via Africa's Talking

    password_hash = db.Column(db.String(255), nullable=False)

    role_id = db.Column(db.Integer, db.ForeignKey("roles.id"), nullable=False)
    role = db.relationship("Role", back_populates="users")

    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    audit_entries = db.relationship("AuditLogEntry", back_populates="user")

    def __repr__(self):
        return f"<User {self.email} ({self.role.name if self.role else 'no role'})>"
