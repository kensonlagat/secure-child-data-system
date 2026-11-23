"""#139: the form that starts a legal-status change. It only reaches the existing endpoint and the
existing requester-code step; the workflow rules (hard rule 3) are unchanged."""

import re
from datetime import date

import pytest
from cryptography.fernet import Fernet
from werkzeug.security import generate_password_hash

from app import create_app, db
from app.config import BaseConfig
from app.models.child_record import ChildRecord
from app.models.legal_status_change_request import LegalStatusChangeRequest, VALID_LEGAL_STATUSES
from app.models.user import Role, User

PASSWORD = "Password#2026"
FORM = 'id="start-request-form"'
TOKEN_INPUT = re.compile(r'name="csrf_token" value="([^"]+)"')
TOKEN_META = re.compile(r'name="csrf-token" content="([^"]+)"')
USERS = {
    "legal": ("legal_officer", "childrens_home"),
    "admin": ("administrator", "both"),
    "worker": ("social_worker", "childrens_home"),
    "manager": ("home_manager", "childrens_home"),
    "teacher": ("teacher", "school"),
}


@pytest.fixture()
def sms(monkeypatch):
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
        roles, ids = {}, {}
        for key, (role_name, mode) in USERS.items():
            if role_name not in roles:
                roles[role_name] = Role(name=role_name, institution_mode=mode)
                db.session.add(roles[role_name])
                db.session.flush()
            user = User(email=f"{key}@example.com", full_name=key, phone_number=f"+2547000001{len(ids):02d}",
                        password_hash=generate_password_hash(PASSWORD), role_id=roles[role_name].id, is_active=True)
            db.session.add(user)
            db.session.flush()
            ids[key] = user.id
        records = {
            "home": ChildRecord(full_name="Home Child", date_of_birth=date(2012, 1, 1),
                                institution_mode="childrens_home", legal_status="in_state_care",
                                caseload_worker_id=ids["worker"]),
            "school": ChildRecord(full_name="School Child", date_of_birth=date(2014, 1, 1),
                                  institution_mode="school"),
            "deleted": ChildRecord(full_name="Deleted Child", date_of_birth=date(2011, 1, 1),
                                   institution_mode="childrens_home", is_deleted=True),
            "archived": ChildRecord(full_name="Archived Child", date_of_birth=date(2010, 1, 1),
                                    institution_mode="childrens_home", is_archived=True),
        }
        db.session.add_all(records.values())
        db.session.commit()
        application.config.update(RECORDS={key: record.id for key, record in records.items()},
                                  PHONES={key: f"+2547000001{index:02d}" for index, key in enumerate(USERS)})
    yield application
    with application.app_context():
        db.session.remove()
        db.drop_all()


def sign_in(app, key, csrf=False):
    client = app.test_client()
    data = {"email": f"{key}@example.com", "password": PASSWORD,
            "portal": "school" if key == "teacher" else "childrens_home"}
    if csrf:
        data["csrf_token"] = TOKEN_INPUT.search(client.get("/login").get_data(as_text=True)).group(1)
    response = client.post("/login", data=data)
    assert response.status_code == 302 and "/login" not in response.headers["Location"]
    return client


def requests_page(client, query=""):
    return client.get(f"/home-mode/legal-status/requests{query}", headers={"Accept": "text/html"})


def options(html):
    """Record ids offered in the child dropdown."""
    block = html.split('id="start-record"')[1].split("</select>")[0]
    return {int(value) for value in re.findall(r'<option value="(\d+)"', block)}


def request_rows(app):
    with app.app_context():
        return [(row.child_record_id, row.requested_status, row.status, row.requested_by_user_id)
                for row in LegalStatusChangeRequest.query.order_by(LegalStatusChangeRequest.id)]


@pytest.mark.parametrize("key", ["legal", "admin"])
def test_form_offers_only_in_scope_childrens_home_records(app, key):
    response = requests_page(sign_in(app, key))

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert FORM in html and 'name="csrf_token"' in html
    records = app.config["RECORDS"]
    # School, deleted and archived children are never offered, even to an administrator.
    assert options(html) == {records["home"]}
    status_block = html.split('id="start-status"')[1].split("</select>")[0]
    assert set(re.findall(r'<option value="([a-z_]+)"', status_block)) == VALID_LEGAL_STATUSES


def test_record_id_preselects_only_an_in_scope_child(app):
    legal = sign_in(app, "legal")
    records = app.config["RECORDS"]

    chosen = requests_page(legal, f"?record_id={records['home']}").get_data(as_text=True)
    assert re.search(rf'<option value="{records["home"]}"[^>]*selected', chosen)

    for other in ("school", "deleted", "archived"):
        html = requests_page(legal, f"?record_id={records[other]}").get_data(as_text=True)
        assert "selected>" not in html.split('id="start-record"')[1].split("</select>")[0]
        assert "Deleted Child" not in html and "Archived Child" not in html and "School Child" not in html


@pytest.mark.parametrize("key", ["worker", "manager", "teacher"])
def test_other_roles_do_not_see_the_form(app, key):
    response = requests_page(sign_in(app, key))
    assert response.status_code == 403
    assert FORM not in response.get_data(as_text=True)


def test_record_list_links_to_the_form_for_legal_officer_and_admin_only(app):
    link = "/home-mode/legal-status/requests?record_id="
    for key in ("legal", "admin"):
        html = sign_in(app, key).get("/home-mode/records", headers={"Accept": "text/html"}).get_data(as_text=True)
        assert f"{link}{app.config['RECORDS']['home']}" in html
    for key in ("worker", "manager"):
        html = sign_in(app, key).get("/home-mode/records", headers={"Accept": "text/html"}).get_data(as_text=True)
        assert link not in html


def test_submitting_the_form_starts_a_pending_otp_request_then_the_code_step(app, sms):
    """Same requests the page's script sends, with CSRF protection switched on."""
    app.config["WTF_CSRF_ENABLED"] = True
    legal = sign_in(app, "legal", csrf=True)
    html = requests_page(legal).get_data(as_text=True)
    token = TOKEN_META.search(html).group(1)
    record_id = app.config["RECORDS"]["home"]
    url = f"/home-mode/legal-status/{record_id}/request-change"

    # Without the token the request is refused and nothing is created.
    assert legal.post(url, json={"requested_status": "placed"}).status_code == 400
    assert request_rows(app) == []

    created = legal.post(url, json={"requested_status": "placed"}, headers={"X-CSRFToken": token})
    assert created.status_code == 201
    with app.app_context():
        legal_id = User.query.filter_by(email="legal@example.com").one().id
    assert request_rows(app) == [(record_id, "placed", "pending_otp", legal_id)]
    code = [c for phone, c in sms if phone == app.config["PHONES"]["legal"]][-1]

    confirmed = legal.post(f"/home-mode/legal-status/confirm-request/{created.get_json()['change_request_id']}",
                           json={"otp_code": code}, headers={"X-CSRFToken": token})
    assert confirmed.status_code == 200 and confirmed.get_json()["status"] == "pending_approval"
    with app.app_context():
        assert db.session.get(ChildRecord, record_id).legal_status == "in_state_care"


@pytest.mark.parametrize("key", ["worker", "manager", "teacher"])
def test_other_roles_posting_get_the_existing_refusal(app, sms, key):
    client = sign_in(app, key)
    response = client.post(f"/home-mode/legal-status/{app.config['RECORDS']['home']}/request-change",
                           json={"requested_status": "placed"})
    assert response.status_code == 403
    assert request_rows(app) == []
    assert sms == []


def audit_rows(app, user_key):
    from app.models.audit_log import AuditLogEntry

    with app.app_context():
        user_id = User.query.filter_by(email=f"{user_key}@example.com").one().id
        return [(row.action, row.target_record_id, row.details)
                for row in AuditLogEntry.query.filter_by(user_id=user_id).order_by(AuditLogEntry.id)]


def test_administrator_on_a_school_record_is_treated_as_out_of_scope(app, sms):
    """Server-side guard: legal status is children's-home only, whatever the role can read."""
    school_id = app.config["RECORDS"]["school"]
    url = f"/home-mode/legal-status/{school_id}/request-change"

    response = sign_in(app, "admin").post(url, json={"requested_status": "placed"})

    assert response.status_code == 404
    assert request_rows(app) == [] and sms == []
    # Same audit row as any other out-of-scope record (the legal officer cannot read school records).
    assert sign_in(app, "legal").post(url, json={"requested_status": "placed"}).status_code == 404
    admin_rows, legal_rows = audit_rows(app, "admin"), audit_rows(app, "legal")
    assert admin_rows[-1] == legal_rows[-1]
    assert admin_rows[-1][0] == "access_denied" and admin_rows[-1][1] == school_id
    assert request_rows(app) == [] and sms == []


def test_requesting_the_current_status_is_refused(app, sms):
    record_id = app.config["RECORDS"]["home"]
    response = sign_in(app, "legal").post(f"/home-mode/legal-status/{record_id}/request-change",
                                          json={"requested_status": "in_state_care"})

    assert response.status_code == 400
    assert response.get_json() == {"error": "The child already has this legal status."}
    assert request_rows(app) == [] and sms == []
    assert audit_rows(app, "legal")[-1][:2] == ("legal_status_change_request_failed", record_id)
