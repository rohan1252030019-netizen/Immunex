from typing import List, Dict, Any

class CVEMapper:
    """
    Enriches detected exploits and anomalies with local air-gapped CVE references.
    """
    def __init__(self) -> None:
        self.cve_db = {
            "log4j": {
                "cve_id": "CVE-2021-44228",
                "title": "Log4Shell Apache Log4j RCE",
                "cvss_score": 10.0,
                "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP endpoints."
            },
            "printnightmare": {
                "cve_id": "CVE-2021-34527",
                "title": "Windows Print Spooler RCE",
                "cvss_score": 8.8,
                "description": "Remote code execution vulnerability when the Windows Print Spooler service improperly performs privileged file operations."
            },
            "dirty_cow": {
                "cve_id": "CVE-2016-5195",
                "title": "Linux Kernel Privilege Escalation",
                "cvss_score": 7.8,
                "description": "Race condition in Linux kernel memory subsystem allows local user privilege escalation."
            },
            "eternalblue": {
                "cve_id": "CVE-2017-0144",
                "title": "MS17-010 EternalBlue SMB Remote Code Execution",
                "cvss_score": 8.1,
                "description": "SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets."
            }
        }

    def map_by_pattern(self, pattern: str) -> List[Dict[str, Any]]:
        results = []
        for key, value in self.cve_db.items():
            if key in pattern.lower():
                results.append(value)
        return results
