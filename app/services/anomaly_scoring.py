"""Score recent audit-log entries with trained role-specific anomaly models."""

from __future__ import annotations

from datetime import datetime, timedelta

import joblib
import pandas as pd

from app.models.anomaly_alert import AnomalyAlert
from app.models.audit_log import AuditLogEntry
from app.models.user import Role, User
from app.services.anomaly_features import FEATURE_COLUMNS, extract_features_for_entry
from app.services.anomaly_training import TRAINED_MODELS_DIR


def score_recent_entries(session, since=None, since_hours=24):
    """Return new anomaly alerts for recent entries without committing them."""
    if since is None:
        since = datetime.utcnow() - timedelta(hours=since_hours)

    new_alerts = []
    pending_entry_ids = set()

    for model_path in sorted(TRAINED_MODELS_DIR.glob("*_isolation_forest.joblib")):
        role_name = model_path.name.removesuffix("_isolation_forest.joblib")
        model = joblib.load(model_path)

        entries = (
            session.query(AuditLogEntry)
            .join(User, AuditLogEntry.user_id == User.id)
            .join(Role, User.role_id == Role.id)
            .filter(Role.name == role_name, AuditLogEntry.timestamp >= since)
            .order_by(AuditLogEntry.timestamp.asc(), AuditLogEntry.id.asc())
            .all()
        )
        if not entries:
            continue

        entry_ids = [entry.id for entry in entries]
        existing_alert_entry_ids = {
            entry_id
            for (entry_id,) in session.query(AnomalyAlert.audit_log_entry_id)
            .filter(AnomalyAlert.audit_log_entry_id.in_(entry_ids))
            .all()
        }

        for entry in entries:
            feature_row = extract_features_for_entry(entry, session)
            feature_frame = pd.DataFrame([feature_row], columns=FEATURE_COLUMNS)
            prediction = int(model.predict(feature_frame)[0])
            anomaly_score = float(model.decision_function(feature_frame)[0])

            if prediction != -1:
                continue
            if entry.id in existing_alert_entry_ids or entry.id in pending_entry_ids:
                continue

            new_alerts.append(
                AnomalyAlert(
                    audit_log_entry_id=entry.id,
                    role_name=role_name,
                    anomaly_score=anomaly_score,
                    status="new",
                )
            )
            pending_entry_ids.add(entry.id)

    return new_alerts