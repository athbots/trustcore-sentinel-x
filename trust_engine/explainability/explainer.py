from typing import Dict, Any
from trust_engine.models.schemas import EngineResponse

class TrustExplainer:
    def __init__(self):
        pass

    def generate_ui_breakdown(self, response: EngineResponse, raw_scores: Dict[str, float], correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Generates a structured, UI-consumable explanation of the trust score calculation.
        """
        
        # Engine Contribution Matrix
        engine_contributions = [
            {"engine": "Identity Verification", "score": raw_scores.get("identity", 0), "weight": "25%"},
            {"engine": "Behavioral ML IsolationForest", "score": raw_scores.get("behavior", 0), "weight": "30%"},
            {"engine": "Neo4j Graph Relationship", "score": raw_scores.get("graph", 0), "weight": "25%"},
            {"engine": "Transformer NLP Threat", "score": raw_scores.get("ai", 0), "weight": "20%"},
        ]

        # Risk Vector Breakdown
        risk_vectors = []
        for reason in response.explanation:
            category = "General"
            if "IsolationForest" in reason or "velocity" in reason:
                category = "Behavioral"
            elif "Transformer" in reason or "payload" in reason.lower() or "injection" in reason.lower():
                category = "Adversarial AI"
            elif "Neo4j" in reason or "connected" in reason:
                category = "Graph Relationship"
            elif "Hardware" in reason or "Device" in reason:
                category = "Hardware/Identity"
                
            risk_vectors.append({
                "category": category,
                "detail": reason
            })

        # Correlation Analysis
        correlation_insights = []
        if correlation_data:
            indicators = correlation_data.get("indicators", [])
            if "STEALTH_ATTACK" in indicators:
                correlation_insights.append("Identified Stealth Attack: Contradictory normal behavior hiding in fraudulent graph networks.")
            if "COORDINATED_THREAT" in indicators:
                correlation_insights.append("Identified Coordinated Threat: Simultaneous trust drops occurring across entirely distinct vectors.")
            if "CONFLICTING_SIGNALS" in indicators:
                correlation_insights.append("Identified Conflicting Signals: Strong identity signature carrying highly malicious payload vectors.")
            if not correlation_insights:
                correlation_insights.append("Signals align perfectly. No contradiction detected.")

        return {
            "final_trust_score": response.trust_score,
            "risk_level_assigned": response.risk_level.value,
            "autonomous_decision": response.decision.value,
            "ml_confidence_interval": response.confidence,
            "engine_contributions": engine_contributions,
            "risk_vectors": risk_vectors,
            "correlation_analysis": correlation_insights
        }

trust_explainer = TrustExplainer()
