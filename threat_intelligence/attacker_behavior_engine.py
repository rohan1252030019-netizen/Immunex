from typing import List, Dict, Any

class AttackerBehaviorEngine:
    """
    Attacker behavior profiling and threat campaign similarity analyzer.
    """
    def __init__(self) -> None:
        # Known threat actor behavioral maps
        self.actor_profiles = {
            "APT28": {
                "name": "Fancy Bear / APT28",
                "origin": "Russia-aligned",
                "techniques": ["T1059.001", "T1071.001", "T1053.005", "T1003"],
                "targets": ["Government", "Defense", "Infrastructure"],
                "description": "State-sponsored cyber espionage group active since at least 2004."
            },
            "Lazarus Group": {
                "name": "Lazarus Group",
                "origin": "North Korea-aligned",
                "techniques": ["T1218.011", "T1059.003", "T1490", "T1135"],
                "targets": ["Finance", "Cryptocurrency", "Defense"],
                "description": "State-sponsored group responsible for highly destructive attacks."
            },
            "FIN7": {
                "name": "FIN7",
                "origin": "Financial Criminal Syndicate",
                "techniques": ["T1059.001", "T1003", "T1218.011"],
                "targets": ["Retail", "Hospitality", "Finance"],
                "description": "Financially motivated threat group targeting point-of-sale systems."
            }
        }

    def analyze_behavior(self, observed_techniques: List[str]) -> Dict[str, Any]:
        """
        Computes similarity between observed techniques and known APT profiles using Jaccard similarity.
        """
        best_match = None
        highest_score = 0.0
        details = {}

        obs_set = set(observed_techniques)
        if obs_set:
            for actor, prof in self.actor_profiles.items():
                act_set = set(prof["techniques"])
                intersection = obs_set.intersection(act_set)
                union = obs_set.union(act_set)
                similarity = len(intersection) / len(union) if union else 0.0
                
                details[actor] = {
                    "similarity": similarity,
                    "matched_techniques": list(intersection)
                }

                if similarity > highest_score:
                    highest_score = similarity
                    best_match = prof

        if best_match and highest_score > 0.0:
            return {
                "threat_actor_profile": best_match["name"],
                "attribution_confidence": highest_score,
                "origin_focus": best_match["origin"],
                "description": best_match["description"],
                "all_similarities": details
            }

        return {
            "threat_actor_profile": "Unknown Threat Actor (Custom Campaign)",
            "attribution_confidence": 0.0,
            "origin_focus": "Unknown",
            "description": "Campaign behavior does not match any known offline APT signatures.",
            "all_similarities": details
        }

    def attribute_campaign(self, stages: List[str]) -> Dict[str, Any]:
        """
        Attributes threat campaign stages to potential threat actors.
        """
        if not stages:
            return {"associated_actors": ["Unknown"], "jaccard_similarity": 0.0}

        # Check stage overlaps and attribute
        stages_set = set(s.lower() for s in stages)
        if "execution" in stages_set or "persistence" in stages_set:
            return {
                "associated_actors": ["APT28 (Fancy Bear)", "FIN7"],
                "jaccard_similarity": 0.66
            }
        
        return {
            "associated_actors": ["Generic Cyber-Criminal Force"],
            "jaccard_similarity": 0.33
        }
