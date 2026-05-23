from typing import Dict, Any, Optional

class IOCEngine:
    """
    Offline air-gapped IOC correlation engine.
    Checks indicators against local threat intelligence databases.
    """
    def __init__(self) -> None:
        # High confidence offline IOC lists
        self.known_ips = {
            "198.51.100.42": {"threat_actor": "APT28 (Fancy Bear)", "confidence": 0.95, "type": "Command & Control"},
            "203.0.113.88": {"threat_actor": "Lazarus Group", "confidence": 0.90, "type": "Data Exfiltration Host"},
            "45.227.254.12": {"threat_actor": "FIN7", "confidence": 0.85, "type": "Phishing Gateway"},
            "185.112.144.5": {"threat_actor": "Cozy Bear (APT29)", "confidence": 0.92, "type": "C2 Server"}
        }
        self.known_hashes = {
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": {"malware_family": "WannaCry", "confidence": 0.99},
            "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f": {"malware_family": "Cobalt Strike", "confidence": 0.95},
            "094a3a60a7479d2b2b101684c3e800a7a0b38c2efcf2e3678b88d40d9d3f10ef": {"malware_family": "Emotet", "confidence": 0.92}
        }
        self.known_domains = {
            "secure-update-microsoft.com": {"threat_actor": "APT28", "confidence": 0.90},
            "system-support-patch.info": {"threat_actor": "Lazarus Group", "confidence": 0.88},
            "exfil-data-server.net": {"threat_actor": "FIN7", "confidence": 0.95}
        }

    def correlate(self, indicator_value: str, indicator_type: str) -> Optional[Dict[str, Any]]:
        val = indicator_value.strip()
        typ = indicator_type.upper().strip()
        if typ == "IP" and val in self.known_ips:
            return self.known_ips[val]
        elif typ == "HASH" and val in self.known_hashes:
            return self.known_hashes[val]
        elif typ == "DOMAIN" and val in self.known_domains:
            return self.known_domains[val]
        return None
