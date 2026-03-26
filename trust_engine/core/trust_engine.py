import asyncio
import time
import logging
from typing import Dict, Any, List

from trust_engine.models.schemas import EngineRequest, EngineResponse, RiskLevel, Decision
from trust_engine.services.scoring import analyze_identity, analyze_behavior, analyze_graph, analyze_ai_threat
from trust_engine.services.defenses import SecurityDefenses
from trust_engine.core.correlation_engine import CorrelationEngine
from trust_engine.trust_memory.memory import TrustMemory
from trust_engine.hardware.trust_device import HardwareTrust
from trust_engine.learning.feedback_loop import AdaptiveFeedbackLoop
from trust_engine.storage.redis_client import redis_cache
from trust_engine.pipeline.kafka_stream import event_stream
from trust_engine.response_engine.actions import autonomous_defender
from trust_engine.explainability.explainer import trust_explainer

import numpy as np

log = logging.getLogger("trust_engine.core")

class TrustCoreEngine:
    def __init__(self):
        self.defenses = SecurityDefenses()
        self.correlation_engine = CorrelationEngine()
        self.trust_memory = TrustMemory()
        self.hardware_trust = HardwareTrust()
        self.feedback_loop = AdaptiveFeedbackLoop()

    async def evaluate_trust(self, request: EngineRequest, tenant_id: str = "default") -> Dict[str, Any]:
        """
        Enterprise Core Engine using multi-tenant context, correlation, 
        adaptive thresholds, and generating visual explainability matrices.
        """
        eval_start = time.perf_counter()
        
        # 1. Hardware Trust Verification (Immediate Block if Sig Mismatch)
        hw_sig = request.metadata.get("hw_signature")
        challenge = request.metadata.get("hw_challenge")
        if hw_sig and challenge:
            if not self.hardware_trust.verify_device_signature(request.device_id, challenge, hw_sig):
                response = EngineResponse(
                    trust_score=0, risk_level=RiskLevel.HIGH, decision=Decision.BLOCK,
                    confidence=1.0, explanation=["CRITICAL: Hardware signature mismatch. Potential device spoofing detected."]
                )
                await autonomous_defender.execute_response(request, response, tenant_id)
                return {
                    "evaluation": response,
                    "explainer_matrix": trust_explainer.generate_ui_breakdown(response, {}, {})
                }

        # 2. Defenses & Trust Memory Context
        request.content = self.defenses.sanitize_input(request.content)
        current_time = time.time()
        
        weights = await self.feedback_loop.get_adaptive_weights()
        user_history = await self.trust_memory.get_user_risk_history(request.user_id)
        device_profile = await self.trust_memory.get_device_trust_profile(request.device_id)

        # 3. Parallel Async Scoring with Ensemble ML
        try:
            results = await asyncio.gather(
                analyze_identity(request),
                analyze_behavior(request, time_penalty=0.0), 
                analyze_graph(request),
                analyze_ai_threat(request),
                return_exceptions=True
            )
            
            id_res = results[0] if not isinstance(results[0], Exception) else {"score": 50, "confidence": 0.5}
            bh_res = results[1] if not isinstance(results[1], Exception) else {"score": 50, "confidence": 0.5}
            gr_res = results[2] if not isinstance(results[2], Exception) else {"score": 50, "confidence": 0.5}
            ai_res = results[3] if not isinstance(results[3], Exception) else {"score": 50, "confidence": 0.5}

        except Exception as e:
            log.critical(f"Engine parallel execution failed: {e}")
            response = EngineResponse(
                trust_score=0, risk_level=RiskLevel.HIGH, decision=Decision.BLOCK,
                confidence=1.0, explanation=["Fail-Secure: Engine internal error."]
            )
            await autonomous_defender.execute_response(request, response, tenant_id)
            return {"evaluation": response, "explainer_matrix": trust_explainer.generate_ui_breakdown(response, {}, {})}

        # 4. Cross-Signal Correlation Integration
        correlation = self.correlation_engine.correlate_signals(id_res, bh_res, gr_res, ai_res)
        
        # 5. Final Adaptive Decision Scoring
        final_trust_score = (
            weights["identity"] * id_res["score"] +
            weights["behavior"] * bh_res["score"] +
            weights["graph"] * gr_res["score"] +
            weights["ai"] * ai_res["score"]
        ) / correlation["escalation_factor"]
        
        if user_history.get("risk_trend") == "DEGRADING":
            final_trust_score -= 10
            
        explanations = id_res.get("reasons", []) + bh_res.get("reasons", []) + gr_res.get("reasons", []) + ai_res.get("reasons", []) + correlation["reasons"]
        decision = Decision.ALLOW

        # Coordinated attack detection triggers BLOCK immediately
        if "COORDINATED_THREAT" in correlation["indicators"] or final_trust_score < 30:
            decision = Decision.BLOCK
        elif final_trust_score < 70 or gr_res["score"] < 40 or ai_res["score"] < 40:
            decision = Decision.CHALLENGE
            
        # 6. Final Event Emission and Memory Update
        is_anomaly = final_trust_score < 60
        asyncio.create_task(self.trust_memory.update_user_risk_history(request.user_id, int(final_trust_score), is_anomaly))
        if is_anomaly:
            asyncio.create_task(self.trust_memory.record_anomaly(request.user_id, request.device_id))

        response = EngineResponse(
            trust_score=max(0, int(final_trust_score)),
            risk_level=RiskLevel.HIGH if final_trust_score < 40 else RiskLevel.MEDIUM if final_trust_score < 75 else RiskLevel.LOW,
            decision=decision,
            confidence=round(np.mean([id_res["confidence"], bh_res["confidence"], gr_res["confidence"], ai_res["confidence"]]), 2),
            explanation=explanations if explanations else ["Intelligence: Normal operational signals."]
        )
        
        # 7. Execute Autobots (Autonomous Defense Response)
        await autonomous_defender.execute_response(request, response, tenant_id)

        # 8. Generate Explainability UI Matrices
        explainer_matrix = trust_explainer.generate_ui_breakdown(
            response, 
            {"identity": id_res["score"], "behavior": bh_res["score"], "graph": gr_res["score"], "ai": ai_res["score"]},
            correlation
        )

        return {
            "evaluation": response,
            "explainer_matrix": explainer_matrix
        }
