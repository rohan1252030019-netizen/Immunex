import json
from pathlib import Path
from typing import List, Dict, Any

class ThreatFeedEngine:
    """
    Handles air-gapped threat intelligence feed ingestion in JSON and STIX-like envelopes.
    """
    def __init__(self, feed_dir: Path = Path("data/threat_feeds/")) -> None:
        self.feed_dir = feed_dir
        self.feed_dir.mkdir(parents=True, exist_ok=True)
        self._indicators: List[Dict[str, Any]] = []
        self.load_local_feeds()

    def load_local_feeds(self) -> None:
        self._indicators = []
        for file_path in self.feed_dir.glob("*.json"):
            try:
                data = json.loads(file_path.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    self._indicators.extend(data)
                elif isinstance(data, dict):
                    if data.get("type") == "bundle":
                        for obj in data.get("objects", []):
                            if obj.get("type") == "indicator":
                                self._indicators.append({
                                    "value": obj.get("pattern"),
                                    "type": "STIX_PATTERN",
                                    "actor": obj.get("name"),
                                    "confidence": 0.8
                                })
                    else:
                        self._indicators.append(data)
            except Exception:
                pass

    def add_custom_feed_entry(self, value: str, type_name: str, metadata: Dict[str, Any]) -> None:
        entry = {
            "value": value,
            "type": type_name,
            "metadata": metadata
        }
        self._indicators.append(entry)
        feed_file = self.feed_dir / "custom_feed.json"
        try:
            feed_file.write_text(json.dumps(self._indicators, indent=2))
        except Exception:
            pass

    def query(self, value: str) -> List[Dict[str, Any]]:
        matches = []
        for ind in self._indicators:
            val = ind.get("value")
            if val == value or (isinstance(val, str) and value in val):
                matches.append(ind)
        return matches

    def ingest_stix_feed(self, bundle: Dict[str, Any]) -> None:
        """
        Dynamically ingests a STIX 2.1 bundle structure into the threat intelligence store.
        """
        if bundle.get("type") == "bundle":
            for obj in bundle.get("objects", []):
                if obj.get("type") == "indicator":
                    pattern = obj.get("pattern", "")
                    # Extract raw value from STIX pattern like: [ipv4-addr:value = '198.51.100.42']
                    value = pattern
                    if "'" in pattern:
                        parts = pattern.split("'")
                        if len(parts) >= 2:
                            value = parts[1]
                    
                    self._indicators.append({
                        "value": value,
                        "type": "STIX_PATTERN",
                        "actor": obj.get("name"),
                        "confidence": 0.8
                    })

    def check_indicator(self, value: str) -> bool:
        """
        Quick check if an indicator exists in the threat feed cache.
        """
        for ind in self._indicators:
            val = ind.get("value")
            if val == value or (isinstance(val, str) and value in val):
                return True
        return False
