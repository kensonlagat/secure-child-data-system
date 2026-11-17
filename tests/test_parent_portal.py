"""Parent portal (#67): phone sign-in with no enumeration, rate limits, active-link scoping, a
minimal field set, guardian links verified by an admin OTP, and no staff routes for parents."""

import re
import time
from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.blueprints.parent import routes as parent_routes
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.guardian_link import GuardianLink
from app.models.otp_event import OTPEvent
from app.models.user import Role, User

PASSWORD = "Password#2026"
PARENT_PHONE = "+254711000001"
OTHER_PARENT_PHONE = "+254711000009"
UNLINKED_PARENT_PHONE = "+254711000002"
STAFF_PHONE = "+254722000002"
UNKNOWN_PHONE = "+254733000003"


@pytest.fixture()
def sms(monkeypatch):
    sent = []
    monkeypatch.setattr("app.services.otp_service.send_sms", lambda phone, message: sent.append((phone, message)))
    return sent


@pytest.fixture()
def app(monkeypatch, sms):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setattr(parent_routes, "MIN_RESPONSE_SECONDS", 0.05)
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        roles = {name: Role(name=name, institution_mode=mode) for name, mode in
                 (("administrator", "both"), ("teacher", "school"), ("parent_guardian", "school"))}
        db.session.add_all(roles.values())
        db.session.flush()
        admin = User(email="admin@example.com", full_name="Admin", phone_number="+254700000001",
                     password_hash=generate_password_hash(PASSWORD), role_id=roles["administrator"].id, is_active=True)
        admin2 = User(email="admin2@example.com", full_name="Admin Two", phone_number="+254700000002",
                      password_hash=generate_password_hash(PASSWORD), role_id=roles["administrator"].id, is_active=True)
        teacher = User(email="teacher@example.com", full_name="Teacher", phone_number=STAFF_PHONE,
                       password_hash=generate_password_hash(PASSWORD), role_id=roles["teacher"].id, is_active=True)
        parents = {phone: User(full_name=f"Parent {phone[-1]}", email=None, login_phone=phone, phone_number=phone,
                               password_hash=generate_password_hash("x" * 40), role_id=roles["parent_guardian"].id,
                               is_active=True)
                   for phone in (PARENT_PHONE, OTHER_PARENT_PHONE, UNLINKED_PARENT_PHONE)}
        db.session.add_all([admin, admin2, teacher, *parents.values()])
        db.session.flush()
        kids = {key: ChildRecord(full_name=f"Child {key}", date_of_birth=date(2015, 1, 1), institution_mode="school",
                                 medical_notes="Asthma, secret") for key in ("A", "B", "C", "D", "E")}
        kids["H"] = ChildRecord(full_name="Child H", date_of_birth=date(2012, 1, 1), institution_mode="childrens_home")
        db.session.add_all(kids.values())
        db.session.flush()
        parent = parents[PARENT_PHONE]
        for key, status in (("A", "active"), ("C", "pending"), ("D", "revoked"), ("H", "active")):
            db.session.add(GuardianLink(child_record_id=kids[key].id, guardian_user_id=parent.id, relationship="mother",
                                        identity_document_type="national_id", status=status, created_by=admin.id))
        db.session.add(GuardianLink(child_record_id=kids["E"].id, guardian_user_id=parents[OTHER_PARENT_PHONE].id,
                                    relationship="father", identity_document_type="passport", status="active",
                                    created_by=admin.id))
        db.session.commit()
        application.config.update(KIDS={k: v.id for k, v in kids.items()}, PARENT=parent.id, ADMIN=admin.id)
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def codes_for(sms, phone):
    return [re.search(r"\b(\d{6})\b", message).group(1) for to, message in sms if to == phone]


def parent_client(app, sms, phone=PARENT_PHONE):
    client = app.test_client()
    client.post("/parent/login", data={"phone": phone})
    response = client.post("/parent/verify", data={"code": codes_for(sms, phone)[-1]})
    assert response.status_code == 302, response.status_code
    return client


def staff_client(app, email):
    client = app.test_client()
    assert client.post("/login", data={"email": email, "password": PASSWORD, "portal": "school"}).status_code == 302
    return client


def without_csrf(body):
    """CSRF tokens differ per session by design; everything else must match."""
    return re.sub(r'(name="csrf-token" content|name="csrf_token" value)="[^"]*"', r'=""', body)


def count(app, action):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action=action).count()


# --- No enumeration -------------------------------------------------------------------------------


@pytest.mark.parametrize("as_json", [False, True])
def test_code_requests_answer_identically_for_every_kind_of_number(app, sms, as_json):
    responses = []
    for phone in (PARENT_PHONE, UNKNOWN_PHONE, UNLINKED_PARENT_PHONE, STAFF_PHONE, "not a number"):
        client = app.test_client()
        response = client.post("/parent/login", json={"phone": phone}) if as_json \
            else client.post("/parent/login", data={"phone": phone})
        responses.append((response.status_code, without_csrf(response.get_data(as_text=True)),
                          response.headers.get("Location")))
    assert len(set(responses)) == 1
    assert [to for to, _ in sms] == [PARENT_PHONE]  # only the active linked parent gets a code


def test_verification_failures_answer_identically(app, sms):
    answers = []
    for phone in (PARENT_PHONE, UNKNOWN_PHONE, UNLINKED_PARENT_PHONE, STAFF_PHONE):
        client = app.test_client()
        client.post("/parent/login", data={"phone": phone})
        response = client.post("/parent/verify", data={"code": "000000"})
        answers.append((response.status_code, without_csrf(response.get_data(as_text=True))))
    assert len(set(answers)) == 1 and answers[0][0] == 401


def test_every_sign_in_response_has_the_response_floor(app, sms, monkeypatch):
    monkeypatch.setattr(parent_routes, "MIN_RESPONSE_SECONDS", 0.4)
    client = app.test_client()
    for path, data in (("/parent/login", {"phone": UNKNOWN_PHONE}), ("/parent/login", {"phone": PARENT_PHONE}),
                       ("/parent/verify", {"code": "000000"})):
        started = time.monotonic()
        client.post(path, data=data)
        assert time.monotonic() - started >= 0.38  # Windows timer resolution is about 15 ms


def test_phone_numbers_never_appear_in_audit_rows(app, sms):
    parent_client(app, sms)
    app.test_client().post("/parent/login", data={"phone": UNKNOWN_PHONE})
    with app.app_context():
        for row in AuditLogEntry.query.all():
            text = f"{row.details} {row.attempted_identifier}"
            for phone in (PARENT_PHONE, UNKNOWN_PHONE, UNKNOWN_PHONE[1:], PARENT_PHONE[4:]):
                assert phone not in text


# --- Codes ------------------------------------------------------------------------------------------


def test_the_right_code_signs_in_and_is_single_use(app, sms):
    client = parent_client(app, sms)
    assert client.get("/parent/").status_code == 200
    again = app.test_client()
    with again.session_transaction() as session:
        session[parent_routes.PENDING_PHONE_KEY] = PARENT_PHONE
    assert again.post("/parent/verify", data={"code": codes_for(sms, PARENT_PHONE)[-1]}).status_code == 401
    assert count(app, "parent_login_succeeded") == 1


def test_codes_are_bound_to_the_number_they_were_sent_for(app, sms):
    app.test_client().post("/parent/login", data={"phone": OTHER_PARENT_PHONE})
    other_code = codes_for(sms, OTHER_PARENT_PHONE)[-1]
    client = app.test_client()
    client.post("/parent/login", data={"phone": PARENT_PHONE})
    assert client.post("/parent/verify", data={"code": other_code}).status_code == 401


def test_an_expired_code_fails(app, sms):
    client = app.test_client()
    client.post("/parent/login", data={"phone": PARENT_PHONE})
    with app.app_context():
        otp = OTPEvent.query.filter_by(action_context="parent_login").one()
        otp.expires_at = datetime.utcnow() - timedelta(seconds=1)
        db.session.commit()
    assert client.post("/parent/verify", data={"code": codes_for(sms, PARENT_PHONE)[-1]}).status_code == 401


def test_five_failures_lock_the_account_even_for_the_right_code(app, sms):
    client = app.test_client()
    client.post("/parent/login", data={"phone": PARENT_PHONE})
    code = codes_for(sms, PARENT_PHONE)[-1]
    wrong = f"{(int(code) + 1) % 1000000:06d}"
    for _ in range(5):
        assert client.post("/parent/verify", data={"code": wrong}).status_code == 401
    assert client.post("/parent/verify", data={"code": code}).status_code == 401
    assert count(app, "login_blocked") == 1


# --- Rate limits ------------------------------------------------------------------------------------


def test_fourth_request_per_number_in_an_hour_sends_nothing_and_is_audited_once(app, sms):
    client = app.test_client()
    first = client.post("/parent/login", data={"phone": PARENT_PHONE})
    for _ in range(5):
        response = client.post("/parent/login", data={"phone": PARENT_PHONE})
        assert (response.status_code, response.headers.get("Location")) == (first.status_code,
                                                                           first.headers.get("Location"))
    assert len(codes_for(sms, PARENT_PHONE)) == 3
    assert count(app, "parent_login_rate_limited") == 1


def test_twenty_first_request_from_one_ip_sends_nothing(app, sms):
    client = app.test_client()
    for number in range(20):
        client.post("/parent/login", data={"phone": f"+2547440000{number:02d}"})
    client.post("/parent/login", data={"phone": PARENT_PHONE})
    assert codes_for(sms, PARENT_PHONE) == []
    assert count(app, "parent_login_rate_limited") == 1


# --- Scoping and fields -----------------------------------------------------------------------------


def test_a_parent_sees_only_actively_linked_school_children(app, sms):
    client = parent_client(app, sms)
    kids = app.config["KIDS"]
    home = client.get("/parent/", headers={"Accept": "application/json"}).get_json()
    assert [item["id"] for item in home["items"]] == [kids["A"]]
    assert client.get(f"/parent/children/{kids['A']}").status_code == 200
    for key in ("B", "C", "D", "E", "H"):  # unlinked, pending, revoked, another parent's, children's home
        assert client.get(f"/parent/children/{kids[key]}").status_code == 404, key


def test_revoking_takes_effect_on_the_next_request(app, sms):
    client = parent_client(app, sms)
    kids = app.config["KIDS"]
    assert client.get(f"/parent/children/{kids['A']}").status_code == 200
    with app.app_context():
        link = GuardianLink.query.filter_by(child_record_id=kids["A"]).one()
        link.status = "revoked"
        db.session.commit()
    assert client.get(f"/parent/children/{kids['A']}").status_code == 404
    assert client.get("/parent/", headers={"Accept": "application/json"}).get_json()["items"] == []


def test_only_the_minimal_field_set_is_shown(app, sms):
    client = parent_client(app, sms)
    kid = app.config["KIDS"]["A"]
    data = client.get(f"/parent/children/{kid}", headers={"Accept": "application/json"}).get_json()
    assert set(data) == {"id", "full_name", "class_label", "absences_last_30_days", "consent"}
    page = client.get(f"/parent/children/{kid}").get_data(as_text=True)
    assert "Asthma" not in page and "Asthma" not in str(data)


# --- No staff routes for parents, no parent routes for staff ------------------------------------------


def test_parents_get_403_on_every_staff_route(app, sms):
    client = parent_client(app, sms)
    kid = app.config["KIDS"]["A"]
    checked = 0
    for rule in app.url_map.iter_rules():
        if "GET" not in rule.methods or rule.endpoint in ("static", "auth.logout", "index") \
                or rule.endpoint.startswith("parent."):
            continue
        url = rule.rule
        for argument in rule.arguments:
            url = url.replace(f"<int:{argument}>", str(kid)).replace(f"<{argument}>", "x")
        response = client.get(url)
        assert response.status_code == 403, (rule.endpoint, response.status_code)
        checked += 1
    assert checked > 50
    for path in ("/admin/guardian-links", f"/consent/records/{kid}"):
        assert client.post(path, data={}).status_code in (403, 405)


def test_staff_cannot_open_parent_pages(app, sms):
    client = staff_client(app, "teacher@example.com")
    assert client.get("/parent/").status_code == 403
    assert client.get(f"/parent/children/{app.config['KIDS']['A']}").status_code == 403


def test_the_staff_sign_in_never_works_for_a_parent_account(app):
    response = app.test_client().post("/login", data={"email": "", "password": "x" * 40, "portal": "school"})
    assert response.status_code == 401


# --- Guardian links ---------------------------------------------------------------------------------


def test_a_new_link_is_pending_records_the_document_type_only_and_gives_no_access(app, sms):
    admin = staff_client(app, "admin@example.com")
    kid = app.config["KIDS"]["B"]
    admin.post("/admin/guardian-links", data={"child_record_id": kid, "phone": "+254755000005", "full_name": "New Mum",
                                              "relationship": "mother", "identity_document_type": "national_id",
                                              "identity_document_number": "12345678"})
    with app.app_context():
        link = GuardianLink.query.filter_by(child_record_id=kid).one()
        assert link.status == "pending" and link.identity_document_type == "national_id"
        assert not any("number" in column.name for column in GuardianLink.__table__.columns)
        for row in AuditLogEntry.query.all():
            assert "12345678" not in (row.details or "") and "+254755000005" not in (row.details or "")
    sms.clear()
    app.test_client().post("/parent/login", data={"phone": "+254755000005"})
    assert sms == []  # a pending link gives no sign-in


def test_verifying_a_link_needs_the_admins_code_for_that_link(app, sms):
    admin = staff_client(app, "admin@example.com")
    kids = app.config["KIDS"]
    for key, phone in (("B", "+254755000005"), ("E", "+254755000006")):
        admin.post("/admin/guardian-links", data={"child_record_id": kids[key], "phone": phone, "full_name": "Pat Parent",
                                                  "relationship": "guardian", "identity_document_type": "passport"})
    with app.app_context():
        first = GuardianLink.query.filter_by(child_record_id=kids["B"]).one().id
        second = GuardianLink.query.filter_by(child_record_id=kids["E"], status="pending").one().id
    admin.post(f"/admin/guardian-links/{first}/request-code")
    code_for_first = codes_for(sms, "+254700000001")[-1]
    # The code for the first link can't verify the second one.
    admin.post(f"/admin/guardian-links/{second}/request-code")
    admin.post(f"/admin/guardian-links/{second}/verify", data={"code": code_for_first})
    # Another administrator can't use the first administrator's code.
    admin2 = staff_client(app, "admin2@example.com")
    admin2.post(f"/admin/guardian-links/{first}/verify", data={"code": code_for_first})
    with app.app_context():
        assert db.session.get(GuardianLink, second).status == "pending"
        assert db.session.get(GuardianLink, first).status == "pending"
    admin.post(f"/admin/guardian-links/{first}/verify", data={"code": code_for_first})
    with app.app_context():
        link = db.session.get(GuardianLink, first)
        assert link.status == "active" and link.verified_by == app.config["ADMIN"]
    assert count(app, "guardian_link_verified") == 1
    assert count(app, "guardian_link_verify_failed") == 2


def test_only_administrators_manage_links(app, sms):
    teacher = staff_client(app, "teacher@example.com")
    assert teacher.get("/admin/guardian-links").status_code == 403
    assert teacher.post("/admin/guardian-links", data={}).status_code == 403


def test_a_staff_number_cannot_be_linked_as_a_parent(app, sms):
    admin = staff_client(app, "admin@example.com")
    with app.app_context():
        teacher = User.query.filter_by(email="teacher@example.com").one()
        teacher.login_phone = STAFF_PHONE
        db.session.commit()
    admin.post("/admin/guardian-links", data={"child_record_id": app.config["KIDS"]["B"], "phone": STAFF_PHONE,
                                              "full_name": "X", "relationship": "other",
                                              "identity_document_type": "other"})
    with app.app_context():
        assert GuardianLink.query.filter_by(child_record_id=app.config["KIDS"]["B"]).count() == 0


# --- CSRF -------------------------------------------------------------------------------------------


def test_csrf_is_enforced_on_parent_sign_in(app, sms):
    app.config["WTF_CSRF_ENABLED"] = True
    client = app.test_client()
    # Form posts without a token are refused with a flash and a redirect (the app's CSRF handler);
    # JSON posts get 400. Either way nothing is sent and nobody is signed in.
    assert client.post("/parent/login", data={"phone": PARENT_PHONE}).status_code == 302
    assert client.post("/parent/login", json={"phone": PARENT_PHONE}).status_code == 400
    assert client.post("/parent/verify", json={"phone": PARENT_PHONE, "code": "123456"}).status_code == 400
    assert sms == []
    assert count(app, "parent_login_code_requested") == 0
    assert client.get("/parent/").status_code in (302, 401)
