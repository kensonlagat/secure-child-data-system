"""`flask seed-demo`: a realistic, fictional dataset in a SEPARATE demo database.

Safety rails (all checked before anything is touched, see check_guards()):
- the demo database name must end in `_demo`, and it must differ from the live DATABASE_URL's;
- the configuration must not be production;
- AFRICASTALKING_USERNAME must be "sandbox" (so no real SMS can be sent);
- DEMO_PASSWORD must be set (at least 12 characters). It is read from the environment only and is
  never printed, logged or written anywhere; only its salted hash reaches the database.

Reset: the demo database is dropped and recreated, migrated as the owner, setup-db-roles is rerun
on it, then the data is written by a child process connected as the low-privilege app role under
the signed `system` context, so encryption, column grants, append-only rules and row-level
security all apply exactly as in the app. Records go through the app's models (encrypted columns);
documents and photos go through their services (validation, encryption, audit rows).

Deterministic: a fixed random seed. Dates are relative to today, so "this week" stays this week.
All people are fictional: names are combined from built-in lists of common Kenyan names.
"""

import os
import random
import subprocess
import sys
from datetime import date, datetime, time, timedelta
from urllib.parse import urlparse, urlunparse

DEFAULT_DEMO_DATABASE = "child_data_system_demo"
SEED = 20261119
# Accounts Kenson signs in with live: open these numbers in the Africa's Talking simulator.
LIVE_NUMBERS = {
    "admin1": "+254711000101", "admin2": "+254711000102", "principal": "+254711000103",
    "nurse": "+254711000104", "teacher_6a": "+254711000105", "social1": "+254711000106",
    "legal": "+254711000107", "manager": "+254711000108", "parent_live": "+254711000109",
}
FAKE_PREFIX = "+254700000"  # obviously fake range for everyone else; never opened in the simulator
EMAIL_DOMAIN = "demo.cds.test"

FIRST_NAMES = ["Achieng", "Akinyi", "Amani", "Atieno", "Baraka", "Brian", "Chebet", "Cherono", "Daudi", "Esther",
               "Faith", "Gabriel", "Grace", "Hassan", "Imani", "Jabari", "Jepchirchir", "Joy", "Kamau", "Kendi",
               "Kibet", "Kioko", "Lilian", "Makena", "Mercy", "Mwende", "Nafula", "Neema", "Njeri", "Nyokabi",
               "Odhiambo", "Otieno", "Rehema", "Sifa", "Tumaini", "Wafula", "Wambui", "Wanjiru", "Zawadi", "Juma"]
SURNAMES = ["Wanjiku", "Otieno", "Kamau", "Mwangi", "Ochieng", "Kiprop", "Njoroge", "Mutua", "Wekesa", "Chege",
            "Omondi", "Kariuki", "Njeru", "Barasa", "Koech", "Muthoni", "Odera", "Ruto", "Nyambura", "Kilonzo",
            "Ndungu", "Wairimu", "Achola", "Kirui", "Mwende", "Owino", "Gitau", "Langat", "Maina", "Nduta"]
CLASSES = [("Grade 4", "A"), ("Grade 4", "B"), ("Grade 5", "A"), ("Grade 5", "B"), ("Grade 6", "A"),
           ("Grade 6", "B"), ("Grade 7", "A"), ("Grade 8", "A")]
PUPILS_PER_CLASS = 15
HOME_CHILDREN = 25


class DemoSeedError(RuntimeError):
    """A refusal or failure. The message never contains secrets."""


def _with_database(url, name):
    return urlunparse(urlparse(url)._replace(path="/" + name))


def _database_of(url):
    return urlparse(url).path.lstrip("/")


def check_guards(environ, app_config, demo_database, seeding=False):
    """Every refusal happens here, before any database is touched. `seeding`: the child process,
    whose DATABASE_URL has been pointed at the demo database on purpose (seed() checks that)."""
    if not demo_database.endswith("_demo"):
        raise DemoSeedError("The demo database name must end in _demo.")
    if environ.get("FLASK_ENV") == "production" or app_config.get("SESSION_COOKIE_SECURE") is True:
        raise DemoSeedError("Refusing to run with a production configuration.")
    if environ.get("AFRICASTALKING_USERNAME", "sandbox") != "sandbox":
        raise DemoSeedError("AFRICASTALKING_USERNAME must be 'sandbox' for demo data.")
    password = environ.get("DEMO_PASSWORD") or ""
    if len(password) < 12:
        raise DemoSeedError("Set DEMO_PASSWORD (at least 12 characters) in this shell first.")
    for variable in ("DB_SETUP_URL", "MIGRATION_DATABASE_URL", "DATABASE_URL"):
        if not environ.get(variable):
            raise DemoSeedError(f"{variable} must be set.")
    if seeding:
        return
    live = _database_of(environ["DATABASE_URL"])
    if live == demo_database or _database_of(environ["MIGRATION_DATABASE_URL"]) == demo_database:
        raise DemoSeedError("The demo database must not be the database the app normally uses.")


# --- Orchestration (runs in the `flask seed-demo` process) -----------------------------------------


def reset_and_seed(environ, app_config, demo_database, echo):
    import psycopg2

    check_guards(environ, app_config, demo_database)
    owner_url = _with_database(environ["MIGRATION_DATABASE_URL"], demo_database)
    app_url = _with_database(environ["DATABASE_URL"], demo_database)
    setup_url = _with_database(environ["DB_SETUP_URL"], demo_database)
    owner_role = urlparse(environ["MIGRATION_DATABASE_URL"]).username or "cds_owner"
    maintenance = psycopg2.connect(_with_database(environ["DB_SETUP_URL"], "postgres").replace(
        "postgresql+psycopg2://", "postgresql://", 1))
    maintenance.autocommit = True
    with maintenance.cursor() as cursor:
        from psycopg2 import sql

        cursor.execute(sql.SQL("DROP DATABASE IF EXISTS {} WITH (FORCE)").format(sql.Identifier(demo_database)))
        cursor.execute(sql.SQL("CREATE DATABASE {} OWNER {}").format(sql.Identifier(demo_database),
                                                                     sql.Identifier(owner_role)))
    maintenance.close()
    echo(f"demo database {demo_database}: dropped and recreated")

    base = dict(environ, FLASK_APP="run.py")
    steps = [
        ("migrate as owner", ["db", "upgrade"], {"DATABASE_URL": owner_url, "MIGRATION_DATABASE_URL": owner_url}),
        ("setup-db-roles", ["setup-db-roles"], {"DB_SETUP_URL": setup_url, "CDS_OWNER_PASSWORD": "",
                                                "CDS_APP_PASSWORD": "", "DATABASE_URL": app_url}),
        ("seed as the app role", ["seed-demo", "--seed-only", "--demo-database", demo_database],
         {"DATABASE_URL": app_url, "MIGRATION_DATABASE_URL": owner_url}),
    ]
    for label, args, extra in steps:
        result = subprocess.run([sys.executable, "-m", "flask", *args], env={**base, **extra}, capture_output=True,
                                text=True, stdin=subprocess.DEVNULL, cwd=os.getcwd())
        output = [line for line in (result.stdout + result.stderr).splitlines()
                  if line.strip() and "Warning" not in line and "warn(" not in line]
        if result.returncode != 0:
            tail = "; ".join(line.strip() for line in output[-3:])
            raise DemoSeedError(f"{label} failed (exit {result.returncode}): {tail[:400]}")
        echo(f"== {label}: ok")
        if label == "seed as the app role":
            for line in output:
                echo(line)


# --- Seeding (runs in the child process, as the app role, inside system_context) -------------------


def seed(db, demo_database, echo):
    from flask import current_app

    if not _database_of(current_app.config["SQLALCHEMY_DATABASE_URI"]) == demo_database:
        raise DemoSeedError("Seeding refused: DATABASE_URL does not point at the demo database.")
    check_guards(os.environ, current_app.config, demo_database, seeding=True)
    Seeder(db, random.Random(SEED)).run()
    report(db, echo)


class Seeder:
    def __init__(self, db, rng):
        self.db, self.rng = db, rng
        self.today = date.today()
        self.now = datetime.utcnow().replace(microsecond=0)
        self.fake_counter = 0
        self.used_names = set()

    # helpers ---------------------------------------------------------------------------------
    def name(self):
        while True:
            value = f"{self.rng.choice(FIRST_NAMES)} {self.rng.choice(SURNAMES)}"
            if value not in self.used_names:
                self.used_names.add(value)
                return value

    def fake_phone(self):
        self.fake_counter += 1
        return f"{FAKE_PREFIX}{self.fake_counter:03d}"

    def school_days(self, weeks=4):
        days, day = [], self.today - timedelta(days=weeks * 7)
        while day < self.today:
            if day.weekday() < 5:
                days.append(day)
            day += timedelta(days=1)
        return days

    def at(self, day, hour, minute=0):
        return datetime.combine(day, time(hour, minute))

    def add(self, *objects):
        self.db.session.add_all(objects)

    # run ---------------------------------------------------------------------------------------
    def run(self):
        self.roles()
        self.staff()
        self.school()
        self.home()
        self.db.session.commit()
        self.files()
        self.archive()
        self.background_audit()
        self.planted_incident()
        self.db.session.commit()

    def roles(self):
        from app.models.user import Role

        modes = {"administrator": "both", "teacher": "school", "school_nurse": "school", "principal": "school",
                 "social_worker": "childrens_home", "legal_officer": "childrens_home",
                 "home_manager": "childrens_home", "parent_guardian": "school"}
        self.role = {}
        for name, mode in modes.items():
            role = Role.query.filter_by(name=name).first() or Role(name=name, institution_mode=mode)
            self.add(role)
            self.role[name] = role
        self.db.session.flush()

    def user(self, key, role, full_name=None, live=False, lead=False, email=True):
        from werkzeug.security import generate_password_hash

        from app.models.user import User

        phone = LIVE_NUMBERS[key] if live else self.fake_phone()
        user = User(full_name=full_name or self.name(), email=f"{key}@{EMAIL_DOMAIN}" if email else None,
                    phone_number=phone, role_id=self.role[role].id, is_active=True, is_safeguarding_lead=lead,
                    password_hash=generate_password_hash(os.environ["DEMO_PASSWORD"]))
        self.add(user)
        return user

    def staff(self):
        self.admin1 = self.user("admin1", "administrator", live=True)
        self.admin2 = self.user("admin2", "administrator", live=True)
        self.principal = self.user("principal", "principal", live=True)
        self.nurse = self.user("nurse", "school_nurse", live=True)
        self.teachers = []
        for grade, stream in CLASSES:
            key = f"teacher_{grade.split()[1]}{stream.lower()}"
            self.teachers.append(self.user(key, "teacher", live=key == "teacher_6a"))
        self.social = [self.user("social1", "social_worker", live=True, lead=True),
                       self.user("social2", "social_worker"), self.user("social3", "social_worker")]
        self.legal = self.user("legal", "legal_officer", live=True)
        self.manager = self.user("manager", "home_manager", live=True, lead=True)
        self.db.session.flush()

    # school --------------------------------------------------------------------------------------
    def school(self):
        from app.models.child_record import ChildRecord
        from app.models.school_class import ClassTeacherAssignment, Enrolment, SchoolClass

        year = self.today.year
        self.classes, self.class_children = [], {}
        for (grade, stream), teacher in zip(CLASSES, self.teachers):
            school_class = SchoolClass(name=grade, stream=stream, academic_year=year, is_active=True)
            self.add(school_class)
            self.db.session.flush()
            self.add(ClassTeacherAssignment(class_id=school_class.id, user_id=teacher.id))
            age = 10 + int(grade.split()[1]) - 4
            children = []
            for _ in range(PUPILS_PER_CLASS):
                child = ChildRecord(full_name=self.name(), institution_mode="school",
                                    date_of_birth=date(year - age, self.rng.randint(1, 12), self.rng.randint(1, 28)),
                                    gender=self.rng.choice(["female", "male"]),
                                    guardian_contact=self.fake_phone(),
                                    allergies=self.rng.choice([None] * 6 + ["Peanuts", "Penicillin"]),
                                    medical_notes=self.rng.choice([None] * 5 + ["Mild asthma", "Wears glasses"]))
                self.add(child)
                children.append(child)
            self.db.session.flush()
            for child in children:
                self.add(Enrolment(child_record_id=child.id, class_id=school_class.id, started_on=date(year, 1, 6),
                                   reason="enrolled", created_by=self.admin1.id))
            self.classes.append((school_class, teacher))
            self.class_children[school_class.id] = children
        self.db.session.flush()
        self.attendance()
        self.report_cards()
        self.clinic()
        self.consents()
        self.pickup()
        self.parents()

    def attendance(self):
        from app.models.attendance import AbsenceAlert, AttendanceMark, AttendanceRegister

        days = self.school_days()
        chronic = {children[3].id for children in list(self.class_children.values())[:2]}  # two frequent absentees
        for school_class, teacher in self.classes:
            for day in days:
                register = AttendanceRegister(class_id=school_class.id, register_date=day, taken_by=teacher.id,
                                              taken_at=self.at(day, 8, self.rng.randint(0, 25)))
                self.add(register)
                self.db.session.flush()
                for child in self.class_children[school_class.id]:
                    roll = self.rng.random()
                    if child.id in chronic and roll < 0.35:
                        status = "absent"
                    else:
                        status = "absent" if roll < 0.04 else "late" if roll < 0.07 else "excused" if roll < 0.08 \
                            else "present"
                    self.add(AttendanceMark(register_id=register.id, child_record_id=child.id, status=status,
                                            updated_at=register.taken_at))
        for child_id in sorted(chronic):
            self.add(AbsenceAlert(child_record_id=child_id, absences=4, window_days=14, outcome="sent",
                                  created_at=self.now - timedelta(days=self.rng.randint(2, 9))))

    def report_cards(self):
        from app.models.report_card import LEARNING_AREA_KEYS, ReportCard, ReportCardEntry

        year = self.today.year
        levels = ["EE", "ME", "ME", "ME", "AE", "AE", "BE"]
        comments = ["A steady term with good effort.", "Participates well in class.",
                    "Needs more reading practice at home.", "Excellent progress in mathematics.",
                    "Works well with others."]
        for index, (school_class, teacher) in enumerate(self.classes):
            for child in self.class_children[school_class.id]:
                for term in (1, 2):
                    if term == 2 and index % 2:
                        continue  # Term 2 drafts in progress for half the classes
                    stamp = self.now - timedelta(days=60 if term == 1 else 2)
                    card = ReportCard(child_record_id=child.id, class_id=school_class.id, academic_year=year,
                                      term=term, status="draft", teacher_comment=self.rng.choice(comments),
                                      created_by=teacher.id, created_at=stamp, updated_by=teacher.id,
                                      updated_at=stamp)
                    self.add(card)
                    self.db.session.flush()
                    areas = LEARNING_AREA_KEYS if term == 1 else LEARNING_AREA_KEYS[:self.rng.randint(3, 6)]
                    for area in areas:
                        self.add(ReportCardEntry(report_card_id=card.id, learning_area=area,
                                                 level=self.rng.choice(levels), updated_by=teacher.id,
                                                 updated_at=stamp))
                    if term == 1:
                        self.db.session.flush()  # entries first: the trigger locks a published card
                        card.status, card.published_by, card.published_at = "published", teacher.id, stamp
        self.db.session.flush()

    def all_school_children(self):
        return [child for children in self.class_children.values() for child in children]

    def clinic(self):
        from app.models.clinic import ClinicVisit

        complaints = [("Headache", "Rest and water", "Paracetamol 250mg"), ("Stomach ache", "Rest", None),
                      ("Grazed knee", "Cleaned and dressed", None), ("Fever", "Sent home with guardian", "Paracetamol"),
                      ("Asthma symptoms", "Inhaler, observed 30 minutes", "Salbutamol inhaler")]
        children = self.all_school_children()
        for day in self.rng.sample(self.school_days(), 15):
            for _ in range(2):
                complaint, treatment, medicine = self.rng.choice(complaints)
                visited = self.at(day, self.rng.randint(9, 15), self.rng.randint(0, 59))
                self.add(ClinicVisit(child_record_id=self.rng.choice(children).id, visited_at=visited,
                                     complaint=complaint, treatment=treatment, medicines_given=medicine,
                                     follow_up=self.rng.choice([None, "Check tomorrow"]), recorded_by=self.nurse.id,
                                     recorded_at=visited))

    def consents(self):
        from app.models.consent import ConsentRecord

        self.photo_ok = []
        start = date(self.today.year, 1, 10)
        for child in self.all_school_children():
            guardian = self.name()
            photo = self.rng.random() < 0.7
            for consent_type, given in (("photo", photo), ("medical_treatment", self.rng.random() < 0.92)):
                if not given:
                    continue
                self.add(ConsentRecord(child_record_id=child.id, consent_type=consent_type, status="given",
                                       effective_date=start, guardian_name=guardian, recorded_by=self.admin1.id,
                                       recorded_at=self.at(start, 10)))
            withdrawn = photo and self.rng.random() < 0.08
            if withdrawn:
                when = self.today - timedelta(days=self.rng.randint(3, 20))
                self.add(ConsentRecord(child_record_id=child.id, consent_type="photo", status="withdrawn",
                                       effective_date=when, guardian_name=guardian, recorded_by=self.admin2.id,
                                       recorded_at=self.at(when, 11)))
            elif photo:
                self.photo_ok.append(child)

    def pickup(self):
        from app.models.pickup import AuthorisedCollector

        children = self.all_school_children()
        teacher_of = {child.id: teacher for school_class, teacher in self.classes
                      for child in self.class_children[school_class.id]}
        for index, child in enumerate(self.rng.sample(children, 46)):
            pending = index < 6
            added = self.now - timedelta(days=self.rng.randint(1, 25))
            self.add(AuthorisedCollector(
                child_record_id=child.id, full_name=self.name(),
                relationship=self.rng.choice(["mother", "father", "grandparent", "relative", "driver"]),
                phone_number=self.fake_phone(), national_id_number=str(self.rng.randint(20000000, 39999999)),
                added_by=(teacher_of[child.id] if pending else self.admin1).id, added_at=added,
                status="pending" if pending else "active", is_active=not pending,
                decided_by=None if pending else self.admin2.id, decided_at=None if pending else added))

    def parents(self):
        from app.models.guardian_link import GuardianLink

        children = self.rng.sample(self.all_school_children(), 20)
        self.parent_accounts = []
        for index, child in enumerate(children):
            live = index == 0
            phone = LIVE_NUMBERS["parent_live"] if live else self.fake_phone()
            parent = self.user("parent_live" if live else f"parent{index}", "parent_guardian", live=live,
                               email=False)
            parent.phone_number, parent.login_phone = phone, phone
            self.db.session.flush()
            created = self.now - timedelta(days=self.rng.randint(5, 40))
            self.add(GuardianLink(child_record_id=child.id, guardian_user_id=parent.id,
                                  relationship=self.rng.choice(["mother", "father", "guardian"]),
                                  identity_document_type=self.rng.choice(["national_id", "passport"]),
                                  status="active", created_by=self.admin1.id, created_at=created,
                                  verified_by=self.admin2.id, verified_at=created + timedelta(hours=2)))
            self.parent_accounts.append(parent)

    # children's home ---------------------------------------------------------------------------
    def home(self):
        from app.models.child_record import ChildRecord

        self.home_children = []
        for index in range(HOME_CHILDREN):
            worker = self.social[index % 3] if index < 23 else None
            child = ChildRecord(full_name=self.name(), institution_mode="childrens_home",
                                date_of_birth=date(self.today.year - self.rng.randint(4, 16), self.rng.randint(1, 12),
                                                   self.rng.randint(1, 28)),
                                gender=self.rng.choice(["female", "male"]),
                                legal_status=self.rng.choice(["in_state_care"] * 4 + ["eligible_for_adoption", "placed"]),
                                caseload_worker_id=worker.id if worker else None,
                                medical_notes=self.rng.choice([None, "Under review", "Malnutrition, improving"]))
            self.add(child)
            self.home_children.append(child)
        self.db.session.flush()
        self.intake_and_care()
        self.court()
        self.health()
        self.family()
        self.placements()
        self.missing_and_legal()

    def worker_of(self, child):
        return next((w for w in self.social if w.id == child.caseload_worker_id), self.social[0])

    def intake_and_care(self):
        from app.models.care_plan import CarePlanGoal, CaseNote
        from app.models.intake import IntakeRecord

        reasons = ["Abandoned at a market", "Found alone at a bus station", "Referred after neglect at home",
                   "Orphaned, no relatives traced yet", "Removed by court order for safety"]
        goals = ["Re-enrol in school", "Weekly counselling sessions", "Trace extended family",
                 "Complete immunisations", "Prepare for family reunification"]
        notes = ["Settling in well, eating and sleeping normally.", "Attended school all week.",
                 "Visited by an aunt; the visit went well.", "Some nightmares this week; counsellor informed.",
                 "Health check completed, weight improving."]
        for child in self.home_children:
            worker = self.worker_of(child)
            admitted = self.today - timedelta(days=self.rng.randint(40, 700))
            self.add(IntakeRecord(child_record_id=child.id, referral_source=self.rng.choice(
                ["childrens_officer", "police", "court", "hospital", "community"]), admission_date=admitted,
                placement_reason=self.rng.choice(reasons), committal_order_reference=f"CO/{self.rng.randint(10, 999)}/"
                f"{admitted.year}", childrens_officer=f"Officer {self.rng.choice(SURNAMES)}", created_by=worker.id,
                created_at=self.at(admitted, 10)))
            for goal in self.rng.sample(goals, self.rng.randint(1, 3)):
                self.add(CarePlanGoal(child_record_id=child.id, goal=goal,
                                      review_date=self.today + timedelta(days=self.rng.randint(5, 60)),
                                      status=self.rng.choice(["open", "open", "achieved"]), created_by=worker.id,
                                      created_at=self.now - timedelta(days=self.rng.randint(5, 60))))
            for _ in range(self.rng.randint(2, 4)):
                day = self.today - timedelta(days=self.rng.randint(1, 30))
                self.add(CaseNote(child_record_id=child.id, note_date=day, category=self.rng.choice(
                    ["welfare", "education", "health", "family"]), body=self.rng.choice(notes), author_id=worker.id,
                    created_at=self.at(day, 15)))

    def court(self):
        from app.models.court import CourtHearing

        courts = ["Milimani Children's Court", "Kibera Law Courts", "Makadara Law Courts"]
        for index, child in enumerate(self.rng.sample(self.home_children, 12)):
            if index < 3:
                when = self.at(self.today + timedelta(days=index + 1), 9 + index)  # this week
                outcome, next_date = None, None
            else:
                when = self.at(self.today - timedelta(days=self.rng.randint(7, 120)), 10)
                outcome, next_date = self.rng.choice([("Adjourned", self.today + timedelta(days=30)),
                                                      ("Care order extended", None), ("Mention", None)])
            self.add(CourtHearing(child_record_id=child.id, hearing_at=when, court=self.rng.choice(courts),
                                  case_reference=f"CR/{self.rng.randint(10, 300)}/{when.year}", outcome=outcome,
                                  next_date=next_date, created_by=self.legal.id, created_at=self.now -
                                  timedelta(days=self.rng.randint(1, 150))))

    def health(self):
        from app.models.health import HealthEntry, MedicationAdministration, MedicationSchedule

        for child in self.home_children:
            worker = self.worker_of(child)
            for _ in range(self.rng.randint(1, 2)):
                when = self.now - timedelta(days=self.rng.randint(1, 90))
                kind = self.rng.choice(["immunisation", "appointment"])
                self.add(HealthEntry(child_record_id=child.id, entry_type=kind, entry_at=when,
                                     details="Measles booster" if kind == "immunisation" else "Dental check-up",
                                     recorded_by=worker.id, recorded_at=when))
        for child in self.rng.sample(self.home_children, 6):
            worker = self.worker_of(child)
            start = self.today - timedelta(days=10)
            schedule = MedicationSchedule(child_record_id=child.id, medicine=self.rng.choice(
                ["Amoxicillin", "Iron supplement", "Multivitamin", "Salbutamol inhaler"]), dose="As prescribed",
                daily_times="08:00,20:00", start_date=start, is_active=True, created_by=worker.id,
                created_at=self.at(start, 8))
            self.add(schedule)
            self.db.session.flush()
            for offset in range(9, 0, -1):
                day = self.today - timedelta(days=offset)
                for hour in (8, 20):
                    outcome = self.rng.choice(["given"] * 12 + ["refused", "missed"])
                    when = self.at(day, hour)
                    self.add(MedicationAdministration(schedule_id=schedule.id, scheduled_for=when, outcome=outcome,
                                                      given_at=when + timedelta(minutes=10) if outcome == "given"
                                                      else None, recorded_by=worker.id,
                                                      recorded_at=when + timedelta(minutes=15)))

    def family(self):
        from app.models.family import FamilyTracing, FamilyVisit

        for child in self.home_children:
            worker = self.worker_of(child)
            self.add(FamilyTracing(child_record_id=child.id, status=self.rng.choice(
                ["not_started", "in_progress", "in_progress", "family_found", "no_family_traced"]),
                updated_by=worker.id, updated_at=self.now - timedelta(days=self.rng.randint(1, 60))))
        for child in self.rng.sample(self.home_children, 14):
            when = self.now - timedelta(days=self.rng.randint(1, 28))
            self.add(FamilyVisit(child_record_id=child.id, visit_at=when, visitor_name=self.name(),
                                 relationship=self.rng.choice(["mother", "aunt_uncle", "grandparent", "sibling"]),
                                 supervised=self.rng.random() < 0.6, notes="Visit went well.",
                                 recorded_by=self.worker_of(child).id, recorded_at=when))

    def placements(self):
        from app.models.placement import AftercareFollowUp, Placement

        for index, child in enumerate(self.home_children[-5:-1]):
            worker = self.worker_of(child)
            exit_day = self.today - timedelta(days=30 + index * 20)
            placement = Placement(child_record_id=child.id, outcome=self.rng.choice(
                ["family_reunification", "kinship_care", "foster_care"]), exit_date=exit_day,
                destination_notes="Living with relatives nearby.", recorded_by=worker.id,
                recorded_at=self.at(exit_day, 12))
            self.add(placement)
            self.db.session.flush()
            for weeks, done in ((2, True), (6, index % 2 == 0)):
                due = exit_day + timedelta(weeks=weeks)
                self.add(AftercareFollowUp(placement_id=placement.id, due_date=due,
                                           completed_at=self.at(due, 14) if done and due < self.today else None,
                                           completed_by=worker.id if done and due < self.today else None,
                                           created_by=worker.id, created_at=self.at(exit_day, 12)))

    def missing_and_legal(self):
        from app.models.legal_status_change_request import LegalStatusChangeRequest
        from app.models.missing import MissingChildAlert

        child = self.home_children[2]
        raised = self.now - timedelta(days=12, hours=5)
        self.add(MissingChildAlert(child_record_id=child.id, status="resolved", last_seen_at=raised - timedelta(hours=2),
                                   circumstances="Did not return from school.", actions_taken="Searched the area, "
                                   "informed police.", raised_by=self.worker_of(child).id, raised_at=raised,
                                   found_at=raised + timedelta(hours=6), resolution_notes="Found safe at a friend's "
                                   "home.", resolved_by=self.manager.id, resolved_at=raised + timedelta(hours=7)))
        for index, (status, target) in enumerate((("pending_approval", "eligible_for_adoption"),
                                                  ("approved", "placed"), ("approved", "eligible_for_adoption"))):
            child = self.home_children[5 + index]
            created = self.now - timedelta(days=3 + index * 10)
            self.add(LegalStatusChangeRequest(
                child_record_id=child.id, requested_by_user_id=self.legal.id, current_status=child.legal_status,
                requested_status=target, status=status, approved_by_user_id=self.admin2.id if status == "approved"
                else None, created_at=created, resolved_at=created + timedelta(days=1) if status == "approved"
                else None))
            if status == "approved":
                child.legal_status = target

    # files, archive ------------------------------------------------------------------------------
    def files(self):
        import io

        from PIL import Image

        from app.services import document_service, photo_service

        pdf = b"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\ntrailer <<>>\n%%EOF"
        for child, kind in ((self.home_children[0], "birth_certificate"), (self.home_children[1], "court_order"),
                            (self.home_children[3], "medical_report"), (self.all_school_children()[0],
                                                                        "medical_report")):
            actor = self.legal if kind == "court_order" else self.admin1
            document_service.store(actor, child, kind, f"{kind}.pdf", pdf)
        for index, child in enumerate(self.photo_ok[:8]):
            buffer = io.BytesIO()
            colour = (60 + index * 20, 120, 180 - index * 10)
            Image.new("RGB", (96, 96), colour).save(buffer, "PNG")
            photo_service.store(self.admin1, child, buffer.getvalue())

    def archive(self):
        school_child = self.class_children[self.classes[-1][0].id][-1]
        home_child = self.home_children[-1]
        for child, reason in ((school_child, "transferred"), (home_child, "reunified")):
            child.is_archived, child.archived_at, child.archived_by = True, self.now - timedelta(days=4), self.admin1.id
            child.leave_reason, child.leave_date = reason, self.today - timedelta(days=5)
        self.db.session.commit()

    # audit ---------------------------------------------------------------------------------------
    def background_audit(self):
        """Normal working-hours activity for every staff member over the last 4 weeks, built with
        the same role patterns the anomaly models were trained on. Marked is_synthetic."""
        from app.models.user import User
        from app.services.synthetic_audit_data import _role_normal_actions

        pattern = {"administrator": "administrator", "teacher": "teacher", "school_nurse": "school_nurse",
                   "principal": "school_nurse", "social_worker": "social_worker", "legal_officer": "legal_officer",
                   "home_manager": "social_worker"}
        school_ids = [c.id for c in self.all_school_children()]
        home_ids = [c.id for c in self.home_children]
        class_of = {teacher.id: [c.id for c in self.class_children[sc.id]] for sc, teacher in self.classes}
        staff = User.query.filter(User.email.isnot(None)).order_by(User.id).all()
        entries = []
        base = self.now.replace(minute=0, second=0)
        for user in staff:
            role = user.role.name
            if role == "teacher":
                ids = class_of.get(user.id, [])
            elif role == "social_worker":
                ids = [c.id for c in self.home_children if c.caseload_worker_id == user.id]
            elif role in ("legal_officer", "home_manager"):
                ids = home_ids
            elif role in ("school_nurse", "principal"):
                ids = school_ids
            else:
                ids = school_ids + home_ids
            for offset in range(28, 0, -1):
                entries.extend(_role_normal_actions(pattern[role], self.rng, base - timedelta(days=offset), user, ids))
        entries.sort(key=lambda e: (e.timestamp, e.user_id))
        self.db.session.add_all(entries)
        self.db.session.flush()
        self.background_rows = len(entries)

    def planted_incident(self):
        """One teacher at about 02:00 two nights ago: 2 failed sign-ins, a sign-in, then many
        out-of-class records within minutes (refused, so audited as access_denied). is_synthetic."""
        from app.models.audit_log import AuditLogEntry

        teacher = self.teachers[3]  # Grade 5 B
        own = {c.id for c in self.class_children[self.classes[3][0].id]}
        targets = [c.id for c in self.all_school_children() if c.id not in own][:26]
        start = datetime.combine(self.today - timedelta(days=2), time(2, 1))
        rows = [AuditLogEntry(user_id=teacher.id, action="login_failed", target_record_type="user",
                              target_record_id=teacher.id, details="Synthetic planted incident: failed sign-in",
                              timestamp=start + timedelta(seconds=40 * i), is_synthetic=True) for i in range(2)]
        rows.append(AuditLogEntry(user_id=teacher.id, action="login", target_record_type="user",
                                  target_record_id=teacher.id, details="Synthetic planted incident: sign-in",
                                  timestamp=start + timedelta(minutes=2), is_synthetic=True))
        for index, record_id in enumerate(targets):
            rows.append(AuditLogEntry(user_id=teacher.id, action="access_denied", target_record_type="child_record",
                                      target_record_id=record_id,
                                      details="Synthetic planted incident: out-of-class record (404)",
                                      timestamp=start + timedelta(minutes=2, seconds=10 + 9 * index),
                                      is_synthetic=True))
        self.db.session.add_all(rows)
        self.planted_teacher = teacher
        self.planted_rows = len(rows)


def report(db, echo):
    from sqlalchemy import text

    from app.models.user import Role, User

    tables = [row[0] for row in db.session.execute(text(
        "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename NOT IN "
        "('alembic_version', 'rls_context_key') ORDER BY tablename")).all()]
    echo("rows per table:")
    for table in tables:
        count = db.session.execute(text(f'SELECT count(*) FROM public."{table}"')).scalar()
        echo(f"  {table}: {count}")
    echo("accounts by role (password: the DEMO_PASSWORD you set; parents sign in by phone code):")
    live = {phone: key for key, phone in LIVE_NUMBERS.items()}
    for role in Role.query.order_by(Role.name).all():
        users = User.query.filter_by(role_id=role.id).order_by(User.id).all()
        shown = [u for u in users if u.phone_number in live] if role.name == "parent_guardian" else users
        echo(f"  {role.name} ({len(users)}):")
        for user in shown:
            flag = " [safeguarding lead]" if user.is_safeguarding_lead else ""
            where = "simulator" if user.phone_number in live else "fake number"
            echo(f"    {user.email or 'phone sign-in'}  {user.phone_number} ({where}){flag}")
        if role.name == "parent_guardian" and len(users) > len(shown):
            echo(f"    + {len(users) - len(shown)} more parents on fake numbers")
