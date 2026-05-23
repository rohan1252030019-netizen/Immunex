from typing import List, Dict, Any

class VisualizationEngine:
    """
    Assembles charting arrays (trend lines, distributions, throughput timelines).
    """
    @staticmethod
    def get_bar_chart_data(distribution: Dict[str, int]) -> Dict[str, Any]:
        return {
            "labels": list(distribution.keys()),
            "datasets": [
                {
                    "label": "Occurrences",
                    "data": list(distribution.values()),
                    "backgroundColor": ["#ef4444", "#f97316", "#eab308", "#3b82f6"]
                }
            ]
        }

    @staticmethod
    def get_trend_chart_data(data_points: List[float], label: str = "Metric") -> Dict[str, Any]:
        return {
            "labels": [f"t-{i}" for i in range(len(data_points), 0, -1)],
            "datasets": [
                {
                    "label": label,
                    "data": data_points,
                    "borderColor": "#10b981",
                    "fill": False
                }
            ]
        }
