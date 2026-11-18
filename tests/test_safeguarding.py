"""Safeguarding concerns (#62)."""

from datetime import date, datetime, timedelta

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import text
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.audit_log import AuditLogEntry
from app.models.child_record import ChildRecord
from app.models.safeguarding import SafeguardingConcern, SafeguardingConcernAction
from app.models.user import Role, User
from app.services.safeguarding_service import LEAD_SMS, NO_LEAD_SMS
from tests.class_helpers import put_in_class

PASSWORD = "Password#2026"
MARKER = "marker-s4feguard narrative"
ACTION_MARKER = "marker-acti0n note"
CHILD_NAME = "Amani Wanjiru"
ROLE_MODES = {"administrator": "both", "teacher": "school", "school_nurse": "school", "principal": "school",
              "social_worker": "childrens_home", "legal_officer": "childrens_home", "parent_guardian": "school"}
# key: (role, safeguarding lead?)
USERS = {"admin": ("administrator", False), "admin_lead": ("administrator", True), "teacher": ("teacher", False),
         "teacher2": ("teacher", False), "lead": ("school_nurse", True), "lead2": ("principal", True),
         "worker": ("social_worker", False), "home_lead": ("legal_officer", True)}
PORTAL = {"both": "school", "school": "school", "childrens_home": "childrens_home"}


@pytest.fixture()
def sms(monkeypatch):
    sent = []
    monkeypatch.setattr("app.services.sms_service.send_sms", lambda phone, message: sent.append((phone, message)))
    return sent


@pytest.fixture()
def app(monkeypatch, sms):
    monkeypatch.setattr(BaseConfig, "FIELD_ENCRYPTION_KEY", Fernet.generate_key().decode())
    application = create_app("testing")
    with application.app_context():
        db.create_all()
        roles = {name: Role(name=name, institution_mode=mode) for name, mode in ROLE_MODES.items()}
        db.session.add_all(roles.values())
        db.session.flush()
        users = {}
        for index, (key, (role, lead)) in enumerate(USERS.items(), start=1):
            users[key] = User(email=f"{key}@example.com", full_name=f"Staff {key}", phone_number=f"+2547000000{index:02d}",
                              password_hash=generate_password_hash(PASSWORD), role_id=roles[role].id, is_active=True,
                              is_safeguarding_lead=lead)
        users["parent"] = User(email=None, login_phone="+254711000001", phone_number="+254711000001",
                               full_name="Parent", password_hash=generate_password_hash("x" * 40),
                               role_id=roles["parent_guardian"].id, is_active=True)
        db.session.add_all(users.values())
        db.session.flush()
        kids = {"in": ChildRecord(full_name=CHILD_NAME, date_of_birth=date(2015, 1, 1), institution_mode="school"),
                "out": ChildRecord(full_name="Other Class Child", date_of_birth=date(2015, 1, 1),
                                   institution_mode="school"),
                "archived": ChildRecord(full_name="Archived Child", date_of_birth=date(2015, 1, 1),
                                        institution_mode="school", is_archived=True),
                "home": ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1),
                                    institution_mode="childrens_home")}
        db.session.add_all(kids.values())
        db.session.flush()
        put_in_class("Grade 6A", children=[kids["in"], kids["archived"]], teachers=[users["teacher"]])
        put_in_class("Grade 7B", children=[kids["out"]], teachers=[users["teacher2"]])
        db.session.commit()
        application.config.update(U={k: v.id for k, v in users.items()}, K={k: v.id for k, v in kids.items()},
                                  PHONES={k: v.phone_number for k, v in users.items()})
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key):
    client = app.test_client()
    role = USERS[key][0]
    assert client.post("/login", data={"email": f"{key}@example.com", "password": PASSWORD,
                                       "portal": PORTAL[ROLE_MODES[role]]}).status_code == 302
    return client


def raise_concern(app, client, child_key="in", urgency="high", **extra):
    data = {"urgency": urgency, "narrative": MARKER, "involves_staff": "no", **extra}
    if child_key:
        data["child_record_id"] = str(app.config["K"][child_key])
    return client.post("/concerns/new", data=data)


def only_concern(app):
    with app.app_context():
        concern = SafeguardingConcern.query.one()
        db.session.expunge(concern)
        return concern


def count(app, action, **filters):
    with app.app_context():
        return AuditLogEntry.query.filter_by(action=action, **filters).count()


def all_details(app):
    with app.app_context():
        return " ".join((row.details or "") for row in AuditLogEntry.query.all())


# --- Raising --------------------------------------------------------------------------------------


def test_teacher_raises_a_concern_about_a_child_in_their_class(app, sms):
    response = raise_concern(app, sign_in(app, "teacher"))
    assert response.status_code == 302 and response.headers["Location"].endswith("/concerns/mine")
    concern = only_concern(app)
    assert concern.child_record_id == app.config["K"]["in"] and concern.institution_mode == "school"
    assert concern.reporter_id == app.config["U"]["teacher"] and concern.status == "open"
    assert count(app, "concern_raised") == 1


@pytest.mark.parametrize("child_key", ["out", "archived", "home"])
def test_raising_about_a_child_outside_scope_is_404_and_audited(app, sms, child_key):
    response = raise_concern(app, sign_in(app, "teacher"), child_key=child_key)
    assert response.status_code == 404
    with app.app_context():
        assert SafeguardingConcern.query.count() == 0
        refusal = AuditLogEntry.query.filter_by(action="access_denied", user_id=app.config["U"]["teacher"]).one()
        assert refusal.target_record_id == app.config["K"][child_key]
    assert sms == []


def test_a_concern_with_no_child_is_allowed_and_takes_the_reporters_mode(app, sms):
    raise_concern(app, sign_in(app, "worker"), child_key=None)
    concern = only_concern(app)
    assert concern.child_record_id is None and concern.institution_mode == "childrens_home"


def test_bad_input_saves_nothing(app, sms):
    client = sign_in(app, "teacher")
    raise_concern(app, client, urgency="whenever")
    raise_concern(app, client, narrative="   ")
    raise_concern(app, client, narrative="x" * 5001)
    with app.app_context():
        assert SafeguardingConcern.query.count() == 0


# --- Reporter -------------------------------------------------------------------------------------


def test_reporter_sees_status_only_never_the_narrative_or_others(app, sms):
    teacher = sign_in(app, "teacher")
    raise_concern(app, teacher)
    raise_concern(app, sign_in(app, "worker"), child_key=None)  # someone else's
    mine = teacher.get("/concerns/mine", headers={"Accept": "application/json"}).get_json()["items"]
    assert len(mine) == 1 and set(mine[0]) == {"id", "raised_at", "status", "mode"}
    html = teacher.get("/concerns/mine").get_data(as_text=True)
    assert MARKER not in html
    with app.app_context():
        own = SafeguardingConcern.query.filter_by(reporter_id=app.config["U"]["teacher"]).one().id
        other = SafeguardingConcern.query.filter_by(reporter_id=app.config["U"]["worker"]).one().id
    # Later narrative (a lead's note) and the concerns themselves: 404 for the reporter.
    sign_in(app, "lead").post(f"/safeguarding/concerns/{own}/actions", data={"action_type": "note",
                                                                            "body": ACTION_MARKER})
    for concern_id in (own, other):
        assert teacher.get(f"/safeguarding/concerns/{concern_id}").status_code == 404
    assert teacher.get("/safeguarding/concerns").status_code == 404
    assert ACTION_MARKER not in teacher.get("/concerns/mine").get_data(as_text=True)


# --- Administrators: metadata only ------------------------------------------------------------------


@pytest.mark.parametrize("admin_key", ["admin", "admin_lead"])
def test_admins_see_metadata_only_in_html_and_json(app, sms, admin_key):
    raise_concern(app, sign_in(app, "teacher"), involves_staff="yes")
    concern = only_concern(app)
    sign_in(app, "lead").post(f"/safeguarding/concerns/{concern.id}/actions",
                              data={"action_type": "note", "body": ACTION_MARKER})
    admin = sign_in(app, admin_key)
    body = admin.get("/admin/concerns", headers={"Accept": "application/json"}).get_json()
    assert set(body["items"][0]) == {"id", "raised_at", "status", "mode", "involves_staff", "reporter"}
    assert body["items"][0]["involves_staff"] is True
    responses = [admin.get("/admin/concerns").get_data(as_text=True), str(body),
                 admin.get("/concerns/mine").get_data(as_text=True), admin.get("/admin/dashboard").get_data(as_text=True)]
    for page in responses:
        assert MARKER not in page and ACTION_MARKER not in page and CHILD_NAME not in page.split("<option")[0]
    # Even an administrator flagged as a lead never reads narratives (D62.3).
    assert admin.get(f"/safeguarding/concerns/{concern.id}").status_code == 404
    assert admin.get("/safeguarding/concerns").status_code == 404
    assert admin.post(f"/safeguarding/concerns/{concern.id}/actions",
                      data={"action_type": "closure", "body": "x"}).status_code == 404
    assert count(app, "concern_narrative_viewed") == 0


def test_admin_count_of_concerns_untriaged_for_24_hours(app, sms):
    raise_concern(app, sign_in(app, "teacher"))
    with app.app_context():
        concern = SafeguardingConcern.query.one()
        concern.created_at = datetime.utcnow() - timedelta(hours=25)
        db.session.commit()
    body = sign_in(app, "admin").get("/admin/concerns", headers={"Accept": "application/json"}).get_json()
    assert body["untriaged_over_24h"] == {"school": 1, "childrens_home": 0}


# --- Leads -------------------------------------------------------------------------------------------


def test_lead_reads_with_exactly_one_audit_row_per_read(app, sms):
    raise_concern(app, sign_in(app, "teacher"))
    concern = only_concern(app)
    lead = sign_in(app, "lead")
    for reads in (1, 2, 3):
        page = lead.get(f"/safeguarding/concerns/{concern.id}")
        assert page.status_code == 200 and MARKER in page.get_data(as_text=True)
        assert CHILD_NAME in page.get_data(as_text=True)
        assert count(app, "concern_narrative_viewed") == reads
    with app.app_context():
        row = AuditLogEntry.query.filter_by(action="concern_narrative_viewed").first()
        assert row.user_id == app.config["U"]["lead"] and row.target_record_id == concern.id
        assert str(app.config["K"]["in"]) in row.details
    assert MARKER not in all_details(app) and CHILD_NAME not in all_details(app)


def test_lead_list_shows_no_narrative(app, sms):
    raise_concern(app, sign_in(app, "teacher"))
    html = sign_in(app, "lead").get("/safeguarding/concerns").get_data(as_text=True)
    assert "#1" in html and MARKER not in html
    assert count(app, "concern_narrative_viewed") == 0


def test_a_lead_from_the_other_mode_and_non_leads_get_404(app, sms):
    raise_concern(app, sign_in(app, "teacher"))
    concern = only_concern(app)
    for key in ("home_lead", "teacher2", "worker"):
        assert sign_in(app, key).get(f"/safeguarding/concerns/{concern.id}").status_code == 404
    assert count(app, "concern_narrative_viewed") == 0


def test_a_lead_cannot_read_or_act_on_a_concern_they_reported(app, sms):
    lead = sign_in(app, "lead")
    raise_concern(app, lead)
    concern = only_concern(app)
    assert lead.get(f"/safeguarding/concerns/{concern.id}").status_code == 404
    assert lead.post(f"/safeguarding/concerns/{concern.id}/actions",
                     data={"action_type": "closure", "body": "self"}).status_code == 404
    assert "#1" not in lead.get("/safeguarding/concerns").get_data(as_text=True)
    # Another lead in the mode can.
    assert sign_in(app, "lead2").get(f"/safeguarding/concerns/{concern.id}").status_code == 200


def test_lead_actions_status_referral_and_closure(app, sms):
    raise_concern(app, sign_in(app, "teacher"))
    concern = only_concern(app)
    lead = sign_in(app, "lead")
    url = f"/safeguarding/concerns/{concern.id}/actions"
    lead.post(url, data={"action_type": "status_change", "status": "triaged", "body": ""})
    lead.post(url, data={"action_type": "referral", "referral_agency": "childrens_officer", "body": ACTION_MARKER})
    lead.post(url, data={"action_type": "closure", "body": "Resolved with the children's officer"})
    lead.post(url, data={"action_type": "note", "body": "after closing"})  # refused
    with app.app_context():
        concern = db.session.get(SafeguardingConcern, concern.id)
        assert concern.status == "closed" and concern.closed_by == app.config["U"]["lead"]
        assert [a.action_type for a in SafeguardingConcernAction.query.order_by(SafeguardingConcernAction.id)] == \
            ["status_change", "referral", "closure"]
    assert count(app, "concern_status_changed") == 3 and count(app, "concern_referred") == 1
    assert count(app, "concern_closed") == 1
    assert ACTION_MARKER not in all_details(app)


def test_child_can_be_linked_once_while_null(app, sms):
    raise_concern(app, sign_in(app, "teacher"), child_key=None)
    concern = only_concern(app)
    lead = sign_in(app, "lead")
    url = f"/safeguarding/concerns/{concern.id}/link"
    lead.post(url, data={"child_record_id": str(app.config["K"]["home"])})      # wrong mode: refused
    lead.post(url, data={"child_record_id": str(app.config["K"]["archived"])})  # archived: refused
    with app.app_context():
        assert db.session.get(SafeguardingConcern, concern.id).child_record_id is None
    lead.post(url, data={"child_record_id": str(app.config["K"]["out"])})       # any live school child
    lead.post(url, data={"child_record_id": str(app.config["K"]["in"])})        # re-link: refused
    with app.app_context():
        assert db.session.get(SafeguardingConcern, concern.id).child_record_id == app.config["K"]["out"]
    assert count(app, "concern_child_linked") == 1 and count(app, "concern_relink_refused") == 1


def test_a_tampered_narrative_is_shown_as_unreadable_not_a_500(app, sms):
    raise_concern(app, sign_in(app, "teacher"))
    concern = only_concern(app)
    with app.app_context():
        db.session.execute(text("UPDATE safeguarding_concerns SET narrative = :v WHERE id = :id"),
                           {"v": b"not-a-valid-ciphertext-value-at-all", "id": concern.id})
        db.session.commit()
    page = sign_in(app, "lead").get(f"/safeguarding/concerns/{concern.id}")
    assert page.status_code == 200 and "This entry could not be read" in page.get_data(as_text=True)
    assert count(app, "concern_integrity_failed") == 1


# --- Data at rest ------------------------------------------------------------------------------------


def test_narrative_and_action_notes_are_ciphertext_at_rest(app, sms):
    raise_concern(app, sign_in(app, "teacher"))
    concern = only_concern(app)
    sign_in(app, "lead").post(f"/safeguarding/concerns/{concern.id}/actions",
                              data={"action_type": "note", "body": ACTION_MARKER})
    with app.app_context():
        raw = db.session.execute(text("SELECT narrative FROM safeguarding_concerns")).scalar()
        raw_note = db.session.execute(text("SELECT body FROM safeguarding_concern_actions")).scalar()
    for value, marker in ((raw, MARKER), (raw_note, ACTION_MARKER)):
        stored = value if isinstance(value, (bytes, bytearray)) else str(value).encode()
        assert marker.encode() not in stored and marker not in str(value)


# --- Parents -----------------------------------------------------------------------------------------


def test_parents_reach_nothing(app, sms):
    raise_concern(app, sign_in(app, "teacher"))
    client = app.test_client()
    with client.session_transaction() as session:
        session["_user_id"], session["_fresh"] = str(app.config["U"]["parent"]), True
    for url in ("/concerns/new", "/concerns/mine", "/safeguarding/concerns", "/safeguarding/concerns/1",
                "/admin/concerns"):
        response = client.get(url, headers={"Accept": "application/json"})
        assert response.status_code == 403 and MARKER not in response.get_data(as_text=True)
    assert client.post("/concerns/new", data={"urgency": "high", "narrative": "x"}).status_code == 403
    with app.app_context():
        assert SafeguardingConcern.query.count() == 1


# --- Notifications -----------------------------------------------------------------------------------


def test_leads_in_the_mode_get_a_generic_sms_for_high_and_immediate(app, sms):
    raise_concern(app, sign_in(app, "teacher"), urgency="immediate")
    phones = {phone for phone, _ in sms}
    assert phones == {app.config["PHONES"]["lead"], app.config["PHONES"]["lead2"]}
    for _, message in sms:
        assert message == LEAD_SMS and CHILD_NAME not in message and MARKER not in message
    assert count(app, "concern_notified") == 1


def test_low_urgency_waits_in_the_queue_without_sms_when_a_lead_exists(app, sms):
    raise_concern(app, sign_in(app, "teacher"), urgency="low")
    assert sms == []
    assert count(app, "concern_notified") == 1  # recorded: leads exist, no SMS for low (D62.4)


@pytest.mark.parametrize("urgency", ["low", "immediate"])
def test_with_no_lead_in_the_mode_administrators_are_told_and_the_page_says_so(app, sms, urgency):
    with app.app_context():  # no active lead in children's-home mode
        User.query.filter_by(email="home_lead@example.com").one().is_safeguarding_lead = False
        db.session.commit()
    client = sign_in(app, "worker")
    response = raise_concern(app, client, child_key=None, urgency=urgency)
    assert response.status_code == 302
    admin_phones = {app.config["PHONES"]["admin"], app.config["PHONES"]["admin_lead"]}
    assert {phone for phone, _ in sms} == admin_phones
    assert all(message == NO_LEAD_SMS for _, message in sms)
    page = client.get("/concerns/mine").get_data(as_text=True)
    assert "no safeguarding lead is set yet" in page
    assert "No safeguarding lead is set" in client.get("/concerns/new").get_data(as_text=True)
    assert "No safeguarding lead is set" in sign_in(app, "admin").get("/admin/concerns").get_data(as_text=True)


def test_an_sms_failure_keeps_the_concern_and_is_audited(app, monkeypatch):
    def broken(phone, message):
        raise RuntimeError("provider down")

    monkeypatch.setattr("app.services.sms_service.send_sms", broken)
    response = raise_concern(app, sign_in(app, "teacher"), urgency="high")
    assert response.status_code == 302
    with app.app_context():
        assert SafeguardingConcern.query.count() == 1
    assert count(app, "concern_notification_failed") == 1


# --- CSRF --------------------------------------------------------------------------------------------


def test_csrf_is_enforced_on_raising(app, sms):
    client = sign_in(app, "teacher")
    app.config["WTF_CSRF_ENABLED"] = True
    try:
        response = raise_concern(app, client)
    finally:
        app.config["WTF_CSRF_ENABLED"] = False
    assert response.status_code in (302, 400)
    with app.app_context():
        assert SafeguardingConcern.query.count() == 0
