from typing import Dict, Any

class SeverityEngine:
    """
    Evaluates raw indicator stats to assign dynamic threat severity levels: LOW, MEDIUM, HIGH, CRITICAL.
    """
    @staticmethod
    def calculate_score(anomaly_score: float, faiss_distance: float, 
                        recurring_threat_score: float, asset_tier: str = "TIER_2") -> Dict[str, Any]:
        base = (anomaly_score * 5.0) + (min(faiss_distance, 100.0) / 20.0)
        recur_boost = recurring_threat_score * 2.5
        
        asset_mult = 1.0
        if asset_tier == "TIER_1":
            asset_mult = 1.3
        elif asset_tier == "TIER_3":
            asset_mult = 0.8
            
        final_score = min((base + recur_boost) * asset_mult, 10.0)
        
        if final_score >= 8.5:
            severity = "CRITICAL"
        elif final_score >= 6.5:
            severity = "HIGH"
        elif final_score >= 4.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"
            
        return {
            "score": round(final_score, 2),
            "severity": severity,
            "components": {
                "base_score": round(base, 2),
                "recur_boost": round(recur_boost, 2),
                "asset_multiplier": asset_mult
            }
        }
