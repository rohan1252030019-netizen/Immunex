import json
import time
from pathlib import Path
from typing import Dict, Any, List

class ForensicRecorder:
    """
    Saves forensic snapshots and evidence captures of malicious episodes to file.
    """
    def __init__(self, output_dir: Path = Path("data/logs/forensics/")) -> None:
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def record_evidence(self, campaign_id: str, context: Dict[str, Any]) -> Path:
        evidence = {
            "campaign_id": campaign_id,
            "recorded_at": time.time(),
            "context": context
        }
        file_path = self.output_dir / f"forensic_{campaign_id}_{int(time.time())}.json"
        file_path.write_text(json.dumps(evidence, indent=2))
        return file_path

    def capture_snapshot(self, host_id: str, trigger_reason: str, active_processes: List[str]) -> Dict[str, Any]:
        """Captures host snapshot and records it as evidence."""
        snapshot = {
            "host_id": host_id,
            "trigger_reason": trigger_reason,
            "context_captured": {
                "active_processes": active_processes,
                "timestamp": time.time()
            }
        }
        self.record_evidence(f"snapshot_{host_id}", snapshot)
        return snapshot
