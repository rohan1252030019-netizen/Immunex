from typing import List, Dict, Any

class HeatmapEngine:
    """
    Prepares heat matrix indexes representing observed MITRE tactics and techniques.
    """
    def __init__(self) -> None:
        pass

    def generate_mitre_heatmap(self, observed_techniques: List[str]) -> Dict[str, Any]:
        tactic_counts = {
            "Execution": 0,
            "Persistence": 0,
            "Defense Evasion": 0,
            "Discovery": 0,
            "Lateral Movement": 0,
            "Impact": 0
        }
        
        technique_details: Dict[str, int] = {}
        for tech in observed_techniques:
            tactic = "Execution"
            if tech.startswith("T1053"):
                tactic = "Persistence"
            elif tech.startswith("T1218") or tech.startswith("T1490"):
                tactic = "Defense Evasion"
            elif tech.startswith("T1033") or tech.startswith("T1135"):
                tactic = "Discovery"
            elif tech.startswith("T1021"):
                tactic = "Lateral Movement"
                
            tactic_counts[tactic] = tactic_counts.get(tactic, 0) + 1
            technique_details[tech] = technique_details.get(tech, 0) + 1
            
        return {
            "tactic_heat": tactic_counts,
            "technique_heat": technique_details,
            "total_techniques_mapped": len(observed_techniques)
        }
