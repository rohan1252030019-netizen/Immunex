from typing import List, Dict, Any

class MITREMapper:
    """
    Maps anomalous processes, network events, and playbook signatures to MITRE ATT&CK techniques.
    """
    def __init__(self) -> None:
        self.behavior_map = {
            "powershell -nop -w hidden -c": {"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"},
            "schtasks /create": {"technique_id": "T1053.005", "technique_name": "Scheduled Task", "tactic": "Persistence"},
            "vssadmin delete shadows": {"technique_id": "T1490", "technique_name": "Inhibit System Recovery", "tactic": "Impact"},
            "whoami": {"technique_id": "T1033", "technique_name": "System Owner/User Discovery", "tactic": "Discovery"},
            "net use": {"technique_id": "T1135", "technique_name": "Network Share Discovery", "tactic": "Discovery"},
            "mimikatz": {"technique_id": "T1003", "technique_name": "OS Credential Dumping", "tactic": "Credential Access"},
            "rundll32.exe": {"technique_id": "T1218.011", "technique_name": "Rundll32", "tactic": "Defense Evasion"}
        }

    def map_command(self, cmdline: str) -> List[Dict[str, Any]]:
        matches = []
        for phrase, data in self.behavior_map.items():
            if phrase in cmdline.lower():
                matches.append(data)
        if not matches:
            if "powershell" in cmdline.lower():
                matches.append({"technique_id": "T1059.001", "technique_name": "PowerShell", "tactic": "Execution"})
            elif "ssh" in cmdline.lower() or "scp" in cmdline.lower():
                matches.append({"technique_id": "T1021.004", "technique_name": "SSH", "tactic": "Lateral Movement"})
        return matches
