"""Train role-specific anomaly detection models from audit-log features."""

from __future__ import annotations

import logging
from pathlib import Path

import joblib
from sklearn.ensemble import IsolationForest

from app.services.anomaly_features import FEATURE_COLUMNS, extract_training_dataset

LOGGER = logging.getLogger(__name__)
TRAINED_MODELS_DIR = Path(__file__).resolve().parents[2] / "trained_models"


def train_models_for_all_roles(session, roles=("administrator", "teacher", "legal_officer")):
    """Train and persist one Isolation Forest model per requested role."""
    TRAINED_MODELS_DIR.mkdir(parents=True, exist_ok=True)

    summary = {}
    for role_name in roles:
        # Training stays synthetic-only for now because the real audit volume is
        # still too small to be statistically meaningful. Revisit this once the
        # system has accumulated enough genuine activity history.
        dataset = extract_training_dataset(role_name, session, include_real_data=False)
        training_rows = len(dataset.index)
        if training_rows < 20:
            reason = "Fewer than 20 audit rows available for training."
            LOGGER.info("Skipping anomaly model training for %s: %s", role_name, reason)
            summary[role_name] = {
                "trained": False,
                "training_rows": training_rows,
                "reason_skipped": reason,
            }
            continue

        model = IsolationForest(contamination=0.025, random_state=42)
        model.fit(dataset[FEATURE_COLUMNS])

        model_path = TRAINED_MODELS_DIR / f"{role_name}_isolation_forest.joblib"
        joblib.dump(model, model_path)

        summary[role_name] = {
            "trained": True,
            "training_rows": training_rows,
            "reason_skipped": None,
        }

    return summary