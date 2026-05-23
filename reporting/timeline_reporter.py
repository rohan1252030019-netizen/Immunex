import time
from typing import List, Dict, Any

class TimelineReporter:
    """
    Renders incident timeline logs, sorting chronologically,
    and reconstructing forensic analysis chains.
    """
    def build_chronological_chain(self, timeline_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        Sorts logs by timestamp, standardizes format, and validates the chronological flow.
        """
        def get_timestamp(ev: Dict[str, Any]) -> float:
            ts = ev.get("timestamp", 0.0)
            if isinstance(ts, (int, float)):
                return float(ts)
            # Try to parse string timestamp
            try:
                # Expecting format "YYYY-MM-DD HH:MM:SS" or similar
                return time.mktime(time.strptime(str(ts)[:19], "%Y-%m-%d %H:%M:%S"))
            except Exception:
                return 0.0

        sorted_events = sorted(timeline_events, key=get_timestamp)
        
        chain = []
        for index, ev in enumerate(sorted_events):
            ts = get_timestamp(ev)
            ts_str = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) if ts > 0 else "N/A"
            
            chain.append({
                "sequence_index": index + 1,
                "timestamp": ts,
                "timestamp_str": ts_str,
                "action": ev.get("action", ev.get("details", "Observed anomalous activity")),
                "tactic": ev.get("tactic", ev.get("metadata", "Execution")),
                "details": ev.get("details", "")
            })
            
        return chain

    def render_text_timeline(self, chronological_chain: List[Dict[str, Any]]) -> str:
        """
        Generates a clean text graph representation of the intrusion campaign timeline.
        """
        lines = []
        lines.append("IMMUNEX ATTACK FORENSIC RECONSTRUCTION CHAIN")
        lines.append("=" * 60)
        
        if not chronological_chain:
            lines.append("[-] No timeline logs recorded.")
            return "\n".join(lines)
            
        for ev in chronological_chain:
            idx = ev["sequence_index"]
            ts = ev["timestamp_str"]
            action = ev["action"]
            tactic = ev["tactic"]
            
            lines.append(f"[{idx:02d}] {ts} - TACTIC: {tactic}")
            lines.append(f"     EVENT: {action}")
            if ev["details"]:
                lines.append(f"     DETAILS: {ev['details']}")
            lines.append("-" * 60)
            
        return "\n".join(lines)
