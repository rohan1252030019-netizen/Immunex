import pytest
from dashboard.realtime_dashboard import RealtimeDashboard
from dashboard.heatmap_engine import HeatmapEngine
from dashboard.visualization_engine import VisualizationEngine
from dashboard.metrics_dashboard import MetricsDashboard
from dashboard.executive_summary_engine import ExecutiveSummaryEngine

def test_realtime_dashboard():
    dash = RealtimeDashboard()
    metrics = dash.get_realtime_metrics()
    assert metrics["uptime_seconds"] >= 0.0
    assert metrics["total_alerts"] == 0
    
    dash.log_alert({"severity": "CRITICAL", "source": "WS-99"})
    metrics = dash.get_realtime_metrics()
    assert metrics["total_alerts"] == 1
    assert len(metrics["recent_severity"]) == 1
    assert metrics["recent_severity"][0] == "CRITICAL"

def test_heatmap_engine():
    engine = HeatmapEngine()
    # Check mapping logic
    heatmap = engine.generate_mitre_heatmap(["T1053.005", "T1218.010", "T1033"])
    assert heatmap["tactic_heat"]["Persistence"] == 1
    assert heatmap["tactic_heat"]["Defense Evasion"] == 1
    assert heatmap["tactic_heat"]["Discovery"] == 1
    assert heatmap["total_techniques_mapped"] == 3

def test_visualization_engine():
    data = VisualizationEngine.get_bar_chart_data({"CRITICAL": 5, "HIGH": 2})
    assert data["labels"] == ["CRITICAL", "HIGH"]
    assert data["datasets"][0]["data"] == [5, 2]
    
    trend = VisualizationEngine.get_trend_chart_data([10.0, 15.0, 20.0])
    assert len(trend["datasets"][0]["data"]) == 3

def test_metrics_dashboard():
    drift = MetricsDashboard.get_drift_widget(drift_score=0.45, threshold=0.30)
    assert drift["status"] == "CRITICAL_DRIFT"
    assert drift["gauge_percentage"] == 100.0
    
    retrain = MetricsDashboard.get_retraining_widget(pre_score=0.8, post_score=0.2)
    assert retrain["improvement"] == 0.6
    assert retrain["efficiency_gain_percentage"] == 75.0

def test_executive_summary_engine():
    summary = ExecutiveSummaryEngine.generate_summary(
        metrics={"active_alerts_count": 10, "critical_incidents": 2},
        incidents=[]
    )
    assert "Defensive Perimeter: STABLE" in summary["headline"]
    assert summary["security_index_percentage"] > 0.0
