import json
import uuid
import time
from typing import Dict, Any, List

class IncidentExporter:
    """
    Standardizes incident datasets and transforms them into JSON/STIX formats
    compatible with SOAR (Security Orchestration, Automation, and Response) integrations.
    """
    def export_as_json(self, incident_data: Dict[str, Any]) -> str:
        """
        Exports clean JSON serialized incident profile.
        """
        return json.dumps(incident_data, indent=2)

    def export_as_stix(self, incident_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Transforms internal incident logs into a STIX 2.1 Bundle document.
        """
        campaign_id = incident_data.get("campaign_id", str(uuid.uuid4()))
        summary = incident_data.get("summary", {})
        attacker_ip = summary.get("attacker_ip", "0.0.0.0")
        severity = summary.get("severity", "medium").lower()
        risk_score = summary.get("risk_score", 50.0)
        
        bundle_id = f"bundle--{uuid.uuid4()}"
        
        # 1. Incident Core Object
        incident_obj_id = f"incident--{uuid.uuid4()}"
        incident_obj = {
            "type": "incident",
            "spec_version": "2.1",
            "id": incident_obj_id,
            "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(incident_data.get("generated_at", time.time()))),
            "modified": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(incident_data.get("generated_at", time.time()))),
            "name": f"IMMUNEX Mitigated Intrusion Campaign: {campaign_id[:8]}",
            "description": f"Intrusion campaign attributed to source IP {attacker_ip} with a calculated risk score of {risk_score:.1f}.",
            "severity": severity,
            "labels": ["intrusion-set", "autonomous-defense"],
            "custom_properties": {
                "risk_score": risk_score,
                "assigned_analyst": summary.get("assigned_analyst", "Unassigned")
            }
        }
        
        # 2. Indicator Object (Attacker IP address)
        indicator_id = f"indicator--{uuid.uuid4()}"
        indicator_obj = {
            "type": "indicator",
            "spec_version": "2.1",
            "id": indicator_id,
            "created": incident_obj["created"],
            "modified": incident_obj["modified"],
            "name": f"Malicious Attacker IP: {attacker_ip}",
            "description": "Source IP of campaign executing unauthorized commands and lateral movement.",
            "pattern": f"[ipv4-addr:value = '{attacker_ip}']",
            "pattern_type": "stix",
            "valid_from": incident_obj["created"]
        }
        
        # 3. Relationship: Indicator indicates Incident
        rel_id = f"relationship--{uuid.uuid4()}"
        relationship_obj = {
            "type": "relationship",
            "spec_version": "2.1",
            "id": rel_id,
            "created": incident_obj["created"],
            "modified": incident_obj["modified"],
            "relationship_type": "indicates",
            "source_ref": indicator_id,
            "target_ref": incident_obj_id
        }

        # 4. Course of Action Objects (Mitigations)
        objects = [incident_obj, indicator_obj, relationship_obj]
        
        mitigations = incident_data.get("mitigations", [])
        for mit in mitigations:
            coa_id = f"course-of-action--{uuid.uuid4()}"
            coa_obj = {
                "type": "course-of-action",
                "spec_version": "2.1",
                "id": coa_id,
                "created": incident_obj["created"],
                "modified": incident_obj["modified"],
                "name": f"Autonomous Mitigation: {mit.get('action_type', 'Containment')}",
                "description": f"Applied defense on host {mit.get('host_id', 'global')}. Status: {mit.get('status', 'SUCCESS')}."
            }
            objects.append(coa_obj)
            
            # Relationship: Course of Action mitigates Incident
            coa_rel_id = f"relationship--{uuid.uuid4()}"
            coa_rel = {
                "type": "relationship",
                "spec_version": "2.1",
                "id": coa_rel_id,
                "created": incident_obj["created"],
                "modified": incident_obj["modified"],
                "relationship_type": "mitigates",
                "source_ref": coa_id,
                "target_ref": incident_obj_id
            }
            objects.append(coa_rel)

        return {
            "type": "bundle",
            "id": bundle_id,
            "spec_version": "2.1",
            "objects": objects
        }
