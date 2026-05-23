"""
IMMUNEX Constants
Immutable domain values shared across all subsystems.
"""

from typing import Final

# ─── Protocol Encoding ────────────────────────────────────────────────────────
PROTOCOL_MAP: Final[dict[str, int]] = {
    "TCP": 0,
    "UDP": 1,
    "ICMP": 2,
    "HTTP": 3,
    "HTTPS": 4,
    "DNS": 5,
    "SMB": 6,
    "RDP": 7,
}

# ─── Event Type Encoding ──────────────────────────────────────────────────────
EVENT_TYPE_MAP: Final[dict[str, int]] = {
    # Normal
    "Normal_Connection": 0,
    "File_Access": 1,
    "Process_Start": 2,
    "Authentication_Success": 3,
    "DNS_Query": 4,
    "HTTP_Request": 5,
    # Reconnaissance
    "Port_Scan": 10,
    "Network_Sweep": 11,
    # Credential Access
    "Brute_Force_Login": 20,
    "Password_Spray": 21,
    # Execution
    "PowerShell_Execution": 30,
    "Suspicious_Process_Spawn": 31,
    # Persistence
    "Registry_Modification": 40,
    "Scheduled_Task": 41,
    # Exfiltration
    "Data_Exfiltration": 50,
    "DNS_Tunneling": 51,
}

MALICIOUS_EVENT_TYPES: Final[set[str]] = {
    "Port_Scan", "Network_Sweep",
    "Brute_Force_Login", "Password_Spray",
    "PowerShell_Execution", "Suspicious_Process_Spawn",
    "Registry_Modification", "Scheduled_Task",
    "Data_Exfiltration", "DNS_Tunneling",
}

BENIGN_EVENT_TYPES: Final[set[str]] = {
    "Normal_Connection", "File_Access", "Process_Start",
    "Authentication_Success", "DNS_Query", "HTTP_Request",
}

# ─── Asset Criticality ────────────────────────────────────────────────────────
ASSET_CRITICALITY_LEVELS: Final[list[str]] = [
    "LOW", "MEDIUM", "HIGH", "CRITICAL"
]

ASSET_CRITICALITY_SCORE: Final[dict[str, int]] = {
    "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4
}

# ─── Severity Labels ─────────────────────────────────────────────────────────
SEVERITY_INFO: Final[str] = "INFO"
SEVERITY_LOW: Final[str] = "LOW"
SEVERITY_MEDIUM: Final[str] = "MEDIUM"
SEVERITY_HIGH: Final[str] = "HIGH"
SEVERITY_CRITICAL: Final[str] = "CRITICAL"

SEVERITY_ORDER: Final[list[str]] = [
    SEVERITY_INFO, SEVERITY_LOW, SEVERITY_MEDIUM, SEVERITY_HIGH, SEVERITY_CRITICAL
]

# ─── Detection Reasons ────────────────────────────────────────────────────────
REASON_ISOLATION_FOREST: Final[str] = "IsolationForest_Score_Exceeded"
REASON_FAISS_DISTANCE: Final[str] = "FAISS_Distance_Exceeded"
REASON_COMBINED: Final[str] = "IsolationForest+FAISS_Combined"
REASON_NORMAL: Final[str] = "Normal_Baseline"

# ─── Feature Vector Indices ───────────────────────────────────────────────────
FEATURE_NAMES: Final[list[str]] = [
    "src_bytes",
    "dst_bytes",
    "duration",
    "packet_rate",
    "connection_count",
    "failed_logins",
    "event_frequency",
    "event_interval",
    "protocol_encoding",
    "event_type_encoding",
]

FEATURE_DIM: Final[int] = len(FEATURE_NAMES)  # 10

# ─── GeoLocations Pool ────────────────────────────────────────────────────────
GEO_LOCATIONS: Final[list[str]] = [
    "US-NY", "US-CA", "US-TX", "GB-LDN", "DE-BER", "FR-PAR",
    "IN-MUM", "CN-SHA", "RU-MOW", "BR-SAO", "AU-SYD", "JP-TYO",
    "NG-LAG", "ZA-JNB", "KR-SEO", "SG-SIN", "CA-TOR", "MX-MEX",
]

# ─── Process Name Pools ───────────────────────────────────────────────────────
BENIGN_PROCESSES: Final[list[str]] = [
    "chrome.exe", "explorer.exe", "svchost.exe", "lsass.exe",
    "notepad.exe", "outlook.exe", "teams.exe", "python3",
    "bash", "nginx", "postgres", "java",
]

MALICIOUS_PROCESSES: Final[list[str]] = [
    "powershell.exe", "cmd.exe", "wscript.exe", "mshta.exe",
    "rundll32.exe", "regsvr32.exe", "certutil.exe", "bitsadmin.exe",
    "nc.exe", "mimikatz.exe", "psexec.exe", "wmic.exe",
]
