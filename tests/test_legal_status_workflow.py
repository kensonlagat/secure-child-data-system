"""End-to-end tests for the two-person legal-status workflow (hard rule 3)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.legal_status_change_request import LegalStatusChangeRequest
from app.models.otp_event import OTPEvent
from app.models.user import Role, User

PASSWORD = "Password#2026"


@pytest.fixture()
def sms(monkeypatch):
    """Capture (phone, code) instead of sending."""
    sent = []

    def fake_send_sms(phone_number, message):
        sent.append((phone_number, message.split("code is ")[1].split(".")[0]))

    monkeypatch.setattr("app.services.otp_service.send_sms", fake_send_sms)
    return sent


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        legal = Role(name="legal_officer", institution_mode="childrens_home")
        worker = Role(name="social_worker", institution_mode="childrens_home")
        db.session.add_all([legal, worker])
        db.session.flush()
        phones = {}
        for index, (key, role) in enumerate((("legal1", legal), ("legal2", legal), ("legal3", legal),
                                             ("worker", worker)), start=1):
            phones[key] = f"+25470000000{index}"
            db.session.add(User(email=f"{key}@example.com", full_name=key, phone_number=phones[key],
                                password_hash=generate_password_hash(PASSWORD), role_id=role.id, is_active=True))
        record = ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1),
                             institution_mode="childrens_home", legal_status="in_state_care")
        db.session.add(record)
        db.session.commit()
        application.config.update(RECORD=record.id, PHONES=phones)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": "childrens_home"}).status_code == 302
    return client


def code_for(app, sms, key):
    return [code for phone, code in sms if phone == app.config["PHONES"][key]][-1]


def legal_status(app):
    with app.app_context():
        return db.session.get(ChildRecord, app.config["RECORD"]).legal_status


def actions(app):
    with app.app_context():
        return [row.action for row in AuditLogEntry.query.order_by(AuditLogEntry.id) if row.action.startswith("legal_")]


def start_request(app, sms, requester, status="eligible_for_adoption"):
    """Requester asks for a change and confirms their own code. Returns the request id."""
    response = requester.post(f"/home-mode/legal-status/{app.config['RECORD']}/request-change",
                              json={"requested_status": status})
    assert response.status_code == 201
    request_id = response.get_json()["change_request_id"]
    confirm = requester.post(f"/home-mode/legal-status/confirm-request/{request_id}",
                             json={"otp_code": code_for(app, sms, "legal1")})
    assert confirm.status_code == 200 and confirm.get_json()["status"] == "pending_approval"
    return request_id


def test_two_different_officers_complete_the_change(app, sms):
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    request_id = start_request(app, sms, legal1)

    assert legal2.post(f"/home-mode/legal-status/approve/{request_id}").status_code == 200
    done = legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}",
                       json={"otp_code": code_for(app, sms, "legal2")})

    assert done.status_code == 200 and done.get_json()["status"] == "approved"
    assert legal_status(app) == "eligible_for_adoption"
    assert actions(app) == ["legal_status_change_requested", "legal_status_change_otp_verified",
                            "legal_status_change_approval_requested", "legal_status_change_approved"]


def test_requester_cannot_approve_their_own_request(app, sms):
    legal1 = sign_in(app, "legal1")
    request_id = start_request(app, sms, legal1)

    response = legal1.post(f"/home-mode/legal-status/approve/{request_id}")

    assert response.status_code == 403
    assert legal_status(app) == "in_state_care"
    assert "legal_status_approval_denied_same_user" in actions(app)


def test_requester_cannot_reject_their_own_request(app, sms):
    legal1 = sign_in(app, "legal1")
    request_id = start_request(app, sms, legal1)
    assert legal1.post(f"/home-mode/legal-status/reject/{request_id}").status_code == 403


def test_only_the_requester_can_confirm_the_request_code(app, sms):
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    response = legal1.post(f"/home-mode/legal-status/{app.config['RECORD']}/request-change",
                           json={"requested_status": "placed"})
    request_id = response.get_json()["change_request_id"]

    stolen = legal2.post(f"/home-mode/legal-status/confirm-request/{request_id}",
                         json={"otp_code": code_for(app, sms, "legal1")})

    assert stolen.status_code == 403
    with app.app_context():
        assert db.session.get(LegalStatusChangeRequest, request_id).status == "pending_otp"


def test_only_the_approver_can_use_the_approval_code(app, sms):
    legal1, legal2, legal3 = sign_in(app, "legal1"), sign_in(app, "legal2"), sign_in(app, "legal3")
    request_id = start_request(app, sms, legal1)
    legal2.post(f"/home-mode/legal-status/approve/{request_id}")

    stolen = legal3.post(f"/home-mode/legal-status/confirm-approval/{request_id}",
                         json={"otp_code": code_for(app, sms, "legal2")})

    assert stolen.status_code == 403
    assert legal_status(app) == "in_state_care"


def test_approval_code_is_single_use(app, sms):
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    request_id = start_request(app, sms, legal1)
    legal2.post(f"/home-mode/legal-status/approve/{request_id}")
    code = code_for(app, sms, "legal2")
    assert legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}", json={"otp_code": code}).status_code == 200

    replay = legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}", json={"otp_code": code})
    assert replay.status_code == 400


def test_approval_code_locks_after_five_wrong_attempts(app, sms):
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    request_id = start_request(app, sms, legal1)
    legal2.post(f"/home-mode/legal-status/approve/{request_id}")
    code = code_for(app, sms, "legal2")
    wrong = "000000" if code != "000000" else "111111"
    for _ in range(5):
        legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}", json={"otp_code": wrong})

    response = legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}", json={"otp_code": code})

    assert response.status_code == 400
    assert legal_status(app) == "in_state_care"


def test_expired_approval_code_is_refused(app, sms):
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    request_id = start_request(app, sms, legal1)
    legal2.post(f"/home-mode/legal-status/approve/{request_id}")
    with app.app_context():
        request_row = db.session.get(LegalStatusChangeRequest, request_id)
        db.session.get(OTPEvent, request_row.approver_otp_event_id).expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()

    response = legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}",
                           json={"otp_code": code_for(app, sms, "legal2")})
    assert response.status_code == 400
    assert legal_status(app) == "in_state_care"


def test_unknown_status_is_refused(app, sms):
    response = sign_in(app, "legal1").post(f"/home-mode/legal-status/{app.config['RECORD']}/request-change",
                                           json={"requested_status": "adopted_abroad"})
    assert response.status_code == 400
    assert sms == []


def test_rejected_request_cannot_be_approved(app, sms):
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    request_id = start_request(app, sms, legal1)
    assert legal2.post(f"/home-mode/legal-status/reject/{request_id}").status_code == 200

    assert legal2.post(f"/home-mode/legal-status/approve/{request_id}").status_code == 400
    assert legal_status(app) == "in_state_care"


def test_non_legal_roles_cannot_start_a_change(app, sms):
    response = sign_in(app, "worker").post(f"/home-mode/legal-status/{app.config['RECORD']}/request-change",
                                           json={"requested_status": "placed"})
    assert response.status_code == 403
    assert sms == []


def test_legal_status_is_not_writable_through_patch(app, sms):
    response = sign_in(app, "legal1").patch(f"/home-mode/records/{app.config['RECORD']}",
                                            json={"legal_status": "placed"})
    assert response.status_code in (400, 403, 404)
    assert legal_status(app) == "in_state_care"


def test_audit_rows_never_contain_otp_codes(app, sms):
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    request_id = start_request(app, sms, legal1)
    legal2.post(f"/home-mode/legal-status/approve/{request_id}")
    legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}", json={"otp_code": code_for(app, sms, "legal2")})

    with app.app_context():
        details = " ".join(row.details or "" for row in AuditLogEntry.query.all())
    for _, code in sms:
        assert code not in details


def test_confirm_approval_before_an_approval_code_exists_is_refused_cleanly(app, sms):
    """#98: this used to raise AttributeError (a 500)."""
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    request_id = start_request(app, sms, legal1)  # pending_approval, but nobody asked for the approver code

    response = legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}", json={"otp_code": "123456"})

    assert response.status_code == 400
    assert legal_status(app) == "in_state_care"
    assert "legal_status_change_approval_otp_failed" in actions(app)


def test_confirm_approval_while_the_request_code_is_still_pending_is_refused(app, sms):
    legal1, legal2 = sign_in(app, "legal1"), sign_in(app, "legal2")
    response = legal1.post(f"/home-mode/legal-status/{app.config['RECORD']}/request-change",
                           json={"requested_status": "placed"})
    request_id = response.get_json()["change_request_id"]  # still pending_otp

    assert legal2.post(f"/home-mode/legal-status/confirm-approval/{request_id}",
                       json={"otp_code": "123456"}).status_code == 400
    assert legal_status(app) == "in_state_care"
