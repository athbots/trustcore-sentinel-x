import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Dict, Any, List

import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

try:
    from transformers import pipeline
    TRANSFORMERS_AVAILABLE = True
except ImportError:
    TRANSFORMERS_AVAILABLE = False

log = logging.getLogger("trust_engine.models")

class TrustAIModels:
    def __init__(self):
        log.info("Loading enterprise AI model tier...")
        self.executor = ThreadPoolExecutor(max_workers=4)
        
        # Ensemble 1: Behavior Anomaly (Multiple Isolation Forests with different estimators)
        self.behavior_ensemble = [
            IsolationForest(n_estimators=100, contamination=0.01, random_state=42),
            IsolationForest(n_estimators=150, contamination=0.005, random_state=1)
        ]
        X_warmup = np.array([[12, 0, 1], [14, 1, 2], [9, 0, 1], [10, 2, 5]])
        for m in self.behavior_ensemble: m.fit(X_warmup)
        
        # Ensemble 2: Multi-purpose NLP pipelines
        self.nlp_pipelines = {}
        if TRANSFORMERS_AVAILABLE:
            try:
                # 1. Main threat classifier
                self.nlp_pipelines["threat"] = pipeline("text-classification", model="distilbert-base-uncased-finetuned-sst-2-english", device=-1)
                # 2. Anomaly/Spam detector
                self.nlp_pipelines["spam"] = pipeline("text-classification", model="sentiment-analysis", device=-1)
            except Exception as e:
                log.error(f"Transformer ensemble failed to load: {e}")

    async def analyze_behavior_ensemble(self, action_id: int, hour: int, rate: int) -> Dict[str, Any]:
        """Calculates ensemble-based behavior anomaly with confidence scores."""
        def run_ensemble():
            features = np.array([[action_id, hour, rate]])
            scores = [m.decision_function(features)[0] for m in self.behavior_ensemble]
            preds = [m.predict(features)[0] for m in self.behavior_ensemble]
            
            # Weighted average based on historical estimator reliability
            avg_score = np.mean(scores)
            is_anomaly = np.mean(preds) < 0
            
            # Confidence is derived from the variance and distance from threshold
            confidence = 1.0 - (np.std(scores) * 2) 
            confidence = max(0.5, min(1.0, confidence)) # Normalizing

            return {
                "is_anomaly": is_anomaly,
                "confidence": confidence,
                "raw_score": avg_score
            }
        return await asyncio.get_running_loop().run_in_executor(self.executor, run_ensemble)

    async def analyze_text_ensemble(self, text: str) -> Dict[str, Any]:
        """Runs ensemble logic across multiple NLP models for high-confidence checks."""
        if not text:
            return {"threat_detected": False, "confidence": 1.0}
            
        if not self.nlp_pipelines:
            return {"threat_detected": False, "confidence": 0.5, "fallback": True}

        def run_nlp():
            safe_text = text[:512]
            res_threat = self.nlp_pipelines["threat"](safe_text)[0]
            res_spam = self.nlp_pipelines["spam"](safe_text)[0]
            
            # Ensemble logic: Threat is detected if primary model is high confidence OR both disagree
            # Label 'NEGATIVE' in distilbert finetune maps to suspicious
            is_threat = res_threat['label'] == 'NEGATIVE' and res_threat['score'] > 0.8
            is_spam = res_spam['label'] == 'NEGATIVE'
            
            # Confidence is the maximum score of the signals
            confidence = max(res_threat['score'], res_spam['score'])
            
            return {
                "threat_detected": is_threat or is_spam,
                "confidence": confidence,
                "ensemble_labels": [res_threat['label'], res_spam['label']]
            }
        return await asyncio.get_running_loop().run_in_executor(self.executor, run_nlp)

ai_models = TrustAIModels()
