import pytest
from threat_intelligence.ioc_engine import IOCEngine
from threat_intelligence.cve_mapper import CVEMapper
from threat_intelligence.mitre_mapper import MITREMapper
from threat_intelligence.malware_profiler import MalwareProfiler
from threat_intelligence.threat_feed_engine import ThreatFeedEngine
from threat_intelligence.attacker_behavior_engine import AttackerBehaviorEngine

def test_ioc_engine():
    engine = IOCEngine()
    
    # Core matching test
    res = engine.correlate("198.51.100.42", "IP")
    assert res is not None
    assert res["threat_actor"] == "APT28 (Fancy Bear)"
    
    res = engine.correlate("exfil-data-server.net", "DOMAIN")
    assert res is not None
    assert res["threat_actor"] == "FIN7"
    
    # Missing indicator returns None
    assert engine.correlate("8.8.8.8", "IP") is None

def test_cve_mapper():
    mapper = CVEMapper()
    matches = mapper.map_by_pattern("System exploited via printnightmare payload")
    assert len(matches) > 0
    assert matches[0]["cve_id"] == "CVE-2021-34527"

def test_mitre_mapper():
    mapper = MITREMapper()
    
    # Test command lines
    matches = mapper.map_command("powershell -nop -w hidden -c Write-Host 'Alert'")
    assert len(matches) > 0
    assert matches[0]["technique_id"] == "T1059.001"
    
    matches = mapper.map_command("schtasks /create /tn 'System'")
    assert len(matches) > 0
    assert matches[0]["technique_id"] == "T1053.005"

def test_malware_profiler():
    profiler = MalwareProfiler()
    profile = profiler.profile_behavior(["powershell", "schtasks", "vssadmin"])
    assert profile["malware_family"] in ["Ransomware (e.g. Ryuk)", "APT Implant Payload"]
    assert profile["confidence"] > 0.0

def test_attacker_behavior_engine():
    engine = AttackerBehaviorEngine()
    profile = engine.attribute_campaign(["Execution", "Persistence", "Discovery"])
    assert profile is not None
    assert "associated_actors" in profile
    assert profile["jaccard_similarity"] >= 0.0

def test_threat_feed_engine():
    feed = ThreatFeedEngine()
    # Check ingestion does not throw exception
    stix_feed = {
        "type": "bundle",
        "objects": [
            {
                "type": "indicator",
                "pattern": "[ipv4-addr:value = '198.51.100.42']",
                "name": "Fancy Bear IP"
            }
        ]
    }
    feed.ingest_stix_feed(stix_feed)
    assert feed.check_indicator("198.51.100.42") is True
