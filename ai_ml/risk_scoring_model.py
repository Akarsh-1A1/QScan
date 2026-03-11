"""
QScan — AI Risk Scoring Model

Uses XGBoost to predict quantum risk scores based on cryptographic features.
Trained on labeled scan data (synthetic + real) to improve accuracy over
the rule-based scoring in pqc_classifier.py.

Falls back to rule-based scoring when the model is not yet trained.
"""

import os
import joblib
import numpy as np
from typing import Optional, Tuple

from ai_ml.feature_engineering import FeatureExtractor
from utils.logger import get_logger

logger = get_logger(__name__)

DEFAULT_MODEL_DIR = os.path.join(os.path.dirname(__file__), "models")


class RiskScoringModel:
    """ML-based quantum risk scoring model using XGBoost."""

    def __init__(self, model_path: str = None):
        self.model = None
        self.model_path = model_path or os.path.join(DEFAULT_MODEL_DIR, "risk_model.joblib")
        self.is_trained = False
        self.feature_extractor = FeatureExtractor()
        self.metrics: dict = {}

        # Try to load a pre-trained model
        if os.path.exists(self.model_path):
            self.load_model(self.model_path)
        else:
            logger.info("RiskScoringModel initialized (no pre-trained model found)")

    def train(self, X: np.ndarray, y: np.ndarray, test_size: float = 0.2):
        """
        Train the XGBoost risk scoring model.

        Args:
            X: Feature matrix (n_samples, n_features)
            y: Risk score labels (0–100)
            test_size: Fraction of data reserved for validation
        """
        from xgboost import XGBRegressor
        from sklearn.model_selection import train_test_split
        from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score

        logger.info(f"Training risk model on {X.shape[0]} samples, {X.shape[1]} features")

        X_train, X_val, y_train, y_val = train_test_split(
            X, y, test_size=test_size, random_state=42
        )

        self.model = XGBRegressor(
            n_estimators=200,
            max_depth=6,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            reg_alpha=0.1,
            reg_lambda=1.0,
            random_state=42,
            objective="reg:squarederror",
        )

        self.model.fit(
            X_train, y_train,
            eval_set=[(X_val, y_val)],
            verbose=False,
        )

        # Evaluate
        y_pred = self.model.predict(X_val)
        y_pred = np.clip(y_pred, 0, 100)

        rmse = float(np.sqrt(mean_squared_error(y_val, y_pred)))
        mae = float(mean_absolute_error(y_val, y_pred))
        r2 = float(r2_score(y_val, y_pred))

        self.metrics = {"rmse": round(rmse, 3), "mae": round(mae, 3), "r2": round(r2, 4)}
        self.is_trained = True

        logger.info(f"Model trained — RMSE: {rmse:.3f}, MAE: {mae:.3f}, R²: {r2:.4f}")
        return self.metrics

    def predict(self, scan_result: dict) -> float:
        """
        Predict quantum risk score for a scan result.

        Returns ML-predicted risk score (0–100).
        Falls back to the rule-based score if the model is not trained.
        """
        if not self.is_trained or self.model is None:
            # Fallback to the existing rule-based score
            existing = scan_result.get("quantum_risk_score")
            if existing is not None:
                logger.debug("ML model not trained — using rule-based score")
                return float(existing)
            return 50.0

        features = self.feature_extractor.extract(scan_result)
        X = self.feature_extractor.to_numpy([features])
        prediction = float(self.model.predict(X)[0])
        return round(np.clip(prediction, 0, 100), 1)

    def predict_batch(self, scan_results: list) -> list:
        """Predict risk scores for multiple scan results."""
        if not self.is_trained or self.model is None:
            return [self.predict(r) for r in scan_results]

        feature_dicts = self.feature_extractor.extract_batch(scan_results)
        X = self.feature_extractor.to_numpy(feature_dicts)
        predictions = self.model.predict(X)
        return [round(float(np.clip(p, 0, 100)), 1) for p in predictions]

    def get_feature_importance(self) -> dict:
        """Return feature importance scores from the trained model."""
        if not self.is_trained or self.model is None:
            return {}

        importances = self.model.feature_importances_
        names = self.feature_extractor.get_feature_names()
        importance_dict = {
            name: round(float(imp), 4)
            for name, imp in sorted(zip(names, importances), key=lambda x: -x[1])
        }
        return importance_dict

    def save_model(self, path: str = None):
        """Save trained model to disk using joblib."""
        save_path = path or self.model_path
        os.makedirs(os.path.dirname(save_path), exist_ok=True)

        payload = {
            "model": self.model,
            "metrics": self.metrics,
            "feature_names": self.feature_extractor.get_feature_names(),
        }
        joblib.dump(payload, save_path)
        logger.info(f"Model saved to {save_path}")

    def load_model(self, path: str = None):
        """Load a pre-trained model from disk."""
        load_path = path or self.model_path
        if not os.path.exists(load_path):
            logger.warning(f"Model file not found: {load_path}")
            return

        try:
            payload = joblib.load(load_path)
            self.model = payload["model"]
            self.metrics = payload.get("metrics", {})
            self.is_trained = True
            logger.info(f"Loaded pre-trained model from {load_path} (metrics: {self.metrics})")
        except Exception as e:
            logger.error(f"Failed to load model: {e}")
            self.is_trained = False
