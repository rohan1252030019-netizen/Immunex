from typing import Dict, Any

class MetricsDashboard:
    """
    Compiles detailed drift metrics, precision rates, and retraining performance matrices.
    """
    @staticmethod
    def get_drift_widget(drift_score: float, threshold: float) -> Dict[str, Any]:
        status = "CRITICAL_DRIFT" if drift_score >= threshold else "STABLE"
        return {
            "drift_score": round(drift_score, 4),
            "threshold": threshold,
            "status": status,
            "gauge_percentage": min(round((drift_score / threshold) * 100, 1), 100.0)
        }

    @staticmethod
    def get_retraining_widget(pre_score: float, post_score: float) -> Dict[str, Any]:
        improvement = pre_score - post_score
        return {
            "pre_retrain_score": round(pre_score, 4),
            "post_retrain_score": round(post_score, 4),
            "improvement": round(improvement, 4),
            "efficiency_gain_percentage": max(0.0, round((improvement / pre_score) * 100.0, 1)) if pre_score > 0 else 0.0
        }
