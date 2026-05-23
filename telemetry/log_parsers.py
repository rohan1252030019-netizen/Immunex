"""
IMMUNEX Real Telemetry Engine — Log Parsers
=============================================
This module handles high-performance normalization of real-world log sources
into standardized IMMUNEX SecurityEvent models.

Supports 14 enterprise telemetry formats:
1. Windows Event Logs (Security 4624/4625/etc.)
2. Microsoft Sysmon (Process creation ID 1, Network connection ID 3, etc.)
3. Linux auditd (SYSCALL, EXECVE, etc.)
4. ETW (Event Tracing for Windows)
5. DNS Logs (CoreDNS, BIND9, Route53 query logs)
6. NetFlow (V5/V9 standard flow records)
7. Zeek (conn.log, dns.log, http.log)
8. Suricata (EVE JSON format alerts)
9. Packet Metadata (pcap-derived flow statistics)
10. Kubernetes Audit Logs (API request context)
11. Active Directory (Kerberos auth, Directory Service logs)
12. Cloud IAM Telemetry (AWS CloudTrail, GCP Audit, Azure Activity)
13. VPN Logs (OpenVPN, Cisco AnyConnect, IPsec logs)
14. SaaS Telemetry (Okta auth, GSuite audit logs)
"""

from __future__ import annotations

import re
import json
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, Optional, Union
from utils.schemas import SecurityEvent
from utils.logger import log

def generate_deterministic_hash(seed_str: str) -> str:
    """Generate a deterministic 64-character SHA-256 string for system hashes."""
    return hashlib.sha256(seed_str.encode("utf-8")).hexdigest()

def ensure_datetime(ts: Any) -> datetime:
    """Convert variable timestamp representations into timezone-aware datetimes."""
    if isinstance(ts, datetime):
        if ts.tzinfo is None:
            return ts.replace(tzinfo=timezone.utc)
        return ts
    if isinstance(ts, (int, float)):
        return datetime.fromtimestamp(ts, tz=timezone.utc)
    if isinstance(ts, str):
        # Strip trailing Z and offset formats for parsing
        try:
            return datetime.fromisoformat(ts.replace("Z", "+00:00"))
        except ValueError:
            # Fallback for custom formats
            for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%fZ"):
                try:
                    dt = datetime.strptime(ts, fmt)
                    return dt.replace(tzinfo=timezone.utc)
                except ValueError:
                    continue
    return datetime.now(timezone.utc)

class BaseParser:
    """Base structural interface for all IMMUNEX real telemetry parsers."""
    
    def parse(self, raw_log: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Normalize a raw dictionary log into a valid SecurityEvent."""
        try:
            normalized_data = self._normalize(raw_log)
            if not normalized_data:
                return None
            
            # Ensure mandatory defaults to preserve strict SecurityEvent validator conditions
            normalized_data.setdefault("timestamp", datetime.now(timezone.utc))
            normalized_data.setdefault("src_ip", "127.0.0.1")
            normalized_data.setdefault("dst_ip", "127.0.0.1")
            normalized_data.setdefault("src_port", 0)
            normalized_data.setdefault("dst_port", 0)
            normalized_data.setdefault("protocol", "TCP")
            normalized_data.setdefault("user_id", "unknown")
            normalized_data.setdefault("process_name", "unknown")
            normalized_data.setdefault("process_hash", generate_deterministic_hash(normalized_data["process_name"]))
            normalized_data.setdefault("event_type", "Telemetry_Ingest")
            normalized_data.setdefault("src_bytes", 0)
            normalized_data.setdefault("dst_bytes", 0)
            normalized_data.setdefault("duration", 0.0)
            normalized_data.setdefault("failed_logins", 0)
            normalized_data.setdefault("connection_count", 1)
            normalized_data.setdefault("packet_rate", 1.0)
            normalized_data.setdefault("geo_location", "US")
            normalized_data.setdefault("asset_criticality", "MEDIUM")

            # Clean IPs to pass Pydantic schema validation regex
            normalized_data["src_ip"] = self._clean_ip(normalized_data["src_ip"])
            normalized_data["dst_ip"] = self._clean_ip(normalized_data["dst_ip"])

            return SecurityEvent(**normalized_data)
        except Exception as exc:
            log.warning("Parsing failure in modular telemetry engine", parser=self.__class__.__name__, exc_info=exc)
            return None

    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parser-specific normalization logic to be implemented by child classes."""
        raise NotImplementedError

    def _clean_ip(self, ip: str) -> str:
        """Fallback cleaner to force invalid IPs to loopback to prevent validation failures."""
        if not ip or not isinstance(ip, str):
            return "127.0.0.1"
        # Validate IPv4 format
        parts = ip.split(".")
        if len(parts) != 4:
            return "127.0.0.1"
        try:
            if all(0 <= int(part) <= 255 for part in parts):
                return ip
        except ValueError:
            pass
        return "127.0.0.1"


# ─── 1. Windows Event Log Parser ──────────────────────────────────────────────
class WindowsEventParser(BaseParser):
    """Parses standard Windows Event Log structures (Security channel)."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_id = int(raw_log.get("EventID", raw_log.get("event_id", 0)))
        data = raw_log.get("EventData", raw_log)
        
        normalized = {
            "timestamp": ensure_datetime(raw_log.get("TimeCreated", raw_log.get("timestamp"))),
            "event_type": f"Windows_Event_{event_id}",
            "user_id": data.get("TargetUserName", data.get("subject_user", "system")),
            "src_ip": data.get("IpAddress", data.get("src_ip", "127.0.0.1")),
            "dst_ip": data.get("TargetIpAddress", data.get("dst_ip", "127.0.0.1")),
            "process_name": data.get("ProcessName", "lsass.exe").split("\\")[-1],
            "asset_criticality": "MEDIUM"
        }

        # Specialize security events
        if event_id in (4624, 4625):
            normalized["event_type"] = "Authentication_Success" if event_id == 4624 else "Brute_Force_Login"
            normalized["failed_logins"] = 1 if event_id == 4625 else 0
            normalized["src_bytes"] = 450
            normalized["dst_bytes"] = 350
        elif event_id == 4688:
            normalized["event_type"] = "Process_Start"
            normalized["process_name"] = data.get("NewProcessName", "cmd.exe").split("\\")[-1]
            
        return normalized


# ─── 2. Microsoft Sysmon Parser ───────────────────────────────────────────────
class SysmonParser(BaseParser):
    """Parses rich Microsoft Sysmon endpoint telemetry records."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_id = int(raw_log.get("EventID", raw_log.get("event_id", 0)))
        data = raw_log.get("EventData", raw_log)
        
        normalized = {
            "timestamp": ensure_datetime(raw_log.get("UtcTime", raw_log.get("timestamp"))),
            "event_type": f"Sysmon_Event_{event_id}",
            "user_id": data.get("User", "system"),
            "src_ip": data.get("SourceIp", "127.0.0.1"),
            "dst_ip": data.get("DestinationIp", "127.0.0.1"),
            "src_port": int(data.get("SourcePort", 0) or 0),
            "dst_port": int(data.get("DestinationPort", 0) or 0),
            "process_name": (data.get("Image", "unknown.exe")).split("\\")[-1].split("/")[-1],
            "asset_criticality": "HIGH"
        }

        # Specialize Sysmon Event types
        if event_id == 1: # Process Create
            normalized["event_type"] = "Suspicious_Process_Spawn"
            img_hash = data.get("Hashes", "")
            match = re.search(r"SHA256=([A-Fa-f0-9]{64})", img_hash)
            if match:
                normalized["process_hash"] = match.group(1)
        elif event_id == 3: # Network Connect
            normalized["event_type"] = "Normal_Connection"
            normalized["protocol"] = data.get("Protocol", "TCP").upper()
        elif event_id in (12, 13, 14): # Registry Event
            normalized["event_type"] = "Registry_Modification"
            normalized["process_name"] = data.get("Image", "reg.exe").split("\\")[-1]

        return normalized


# ─── 3. Linux auditd Parser ───────────────────────────────────────────────────
class LinuxAuditdParser(BaseParser):
    """Parses Linux auditd daemon log streams (SYSCALL, EXECVE)."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        msg_type = raw_log.get("type", "SYSCALL")
        normalized = {
            "timestamp": ensure_datetime(raw_log.get("timestamp", raw_log.get("epoch"))),
            "event_type": f"Linux_Auditd_{msg_type}",
            "user_id": raw_log.get("uid", raw_log.get("auid", "unknown")),
            "process_name": raw_log.get("exe", "bash").split("/")[-1],
            "asset_criticality": "HIGH"
        }

        if msg_type == "EXECVE":
            normalized["event_type"] = "Suspicious_Process_Spawn"
            normalized["process_name"] = raw_log.get("argc0", "sh").split("/")[-1]
        elif msg_type == "SYSCALL":
            syscall_num = int(raw_log.get("syscall", 0))
            # Map common security sensitive syscalls
            if syscall_num == 59: # execve
                normalized["event_type"] = "Process_Start"
            elif syscall_num in (41, 42, 43): # socket, connect, accept
                normalized["event_type"] = "Normal_Connection"
                normalized["src_ip"] = raw_log.get("saddr", "127.0.0.1")
                
        return normalized


# ─── 4. ETW Parser ────────────────────────────────────────────────────────────
class EtwParser(BaseParser):
    """Parses Event Tracing for Windows (ETW) logs, focused on security providers."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        provider = raw_log.get("ProviderName", "Microsoft-Windows-Threat-Intelligence")
        task_name = raw_log.get("TaskName", "Threat_Trace")
        
        normalized = {
            "timestamp": ensure_datetime(raw_log.get("timestamp")),
            "event_type": f"ETW_{task_name}",
            "user_id": raw_log.get("user", "system"),
            "process_name": raw_log.get("ProcessName", "unknown").split("\\")[-1],
            "asset_criticality": "MEDIUM"
        }
        
        if "process" in task_name.lower() or "inject" in task_name.lower():
            normalized["event_type"] = "Suspicious_Process_Spawn"
            
        return normalized


# ─── 5. DNS Log Parser ────────────────────────────────────────────────────────
class DnsParser(BaseParser):
    """Parses DNS query server logs (BIND9, CoreDNS, Route53 query logs)."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        query = raw_log.get("query", raw_log.get("qname", "google.com"))
        
        # Check for indicators of DNS Tunneling
        event_type = "DNS_Query"
        if len(query) > 100 or query.count(".") > 6:
            event_type = "DNS_Tunneling"

        return {
            "timestamp": ensure_datetime(raw_log.get("timestamp")),
            "event_type": event_type,
            "src_ip": raw_log.get("client_ip", "127.0.0.1"),
            "dst_ip": raw_log.get("server_ip", "8.8.8.8"),
            "src_port": 53,
            "dst_port": 53,
            "protocol": "DNS",
            "process_name": "nslookup.exe",
            "src_bytes": len(query) + 20,
            "dst_bytes": 150,
            "asset_criticality": "MEDIUM"
        }


# ─── 6. NetFlow Parser ────────────────────────────────────────────────────────
class NetflowParser(BaseParser):
    """Parses raw NetFlow V5/V9 flow data summaries."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Map protocol numbers
        proto_num = int(raw_log.get("protocol", raw_log.get("proto", 6)))
        protocol = "TCP" if proto_num == 6 else "UDP" if proto_num == 17 else "ICMP" if proto_num == 1 else "TCP"
        
        duration = float(raw_log.get("duration", raw_log.get("duration_ms", 0.0)))
        if duration > 1000:
            duration /= 1000.0  # normalize ms to seconds

        src_bytes = int(raw_log.get("src_bytes", raw_log.get("bytes_out", 120)))
        packet_count = int(raw_log.get("packets", 2))
        
        # High bytes exfiltration signature check
        event_type = "Normal_Connection"
        if src_bytes > 5_000_000 and raw_log.get("dst_port", 0) in (443, 80):
            event_type = "Data_Exfiltration"

        return {
            "timestamp": ensure_datetime(raw_log.get("timestamp")),
            "event_type": event_type,
            "src_ip": raw_log.get("src_ip", "127.0.0.1"),
            "dst_ip": raw_log.get("dst_ip", "127.0.0.1"),
            "src_port": int(raw_log.get("src_port", 49152)),
            "dst_port": int(raw_log.get("dst_port", 443)),
            "protocol": protocol,
            "src_bytes": src_bytes,
            "dst_bytes": int(raw_log.get("dst_bytes", raw_log.get("bytes_in", 150))),
            "duration": duration,
            "connection_count": int(raw_log.get("flows_count", 1)),
            "packet_rate": round(packet_count / max(duration, 0.001), 2),
            "process_name": "system",
            "asset_criticality": "LOW"
        }


# ─── 7. Zeek Log Parser ───────────────────────────────────────────────────────
class ZeekParser(BaseParser):
    """Parses standard Zeek (formerly Bro) JSON logs (conn, dns, http)."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        # Auto-detect log type or fallback
        log_type = raw_log.get("_path", raw_log.get("log_type", "conn"))
        
        normalized = {
            "timestamp": ensure_datetime(raw_log.get("ts", raw_log.get("timestamp"))),
            "event_type": f"Zeek_{log_type}",
            "src_ip": raw_log.get("id.orig_h", raw_log.get("src_ip", "127.0.0.1")),
            "dst_ip": raw_log.get("id.resp_h", raw_log.get("dst_ip", "127.0.0.1")),
            "src_port": int(raw_log.get("id.orig_p", 0)),
            "dst_port": int(raw_log.get("id.resp_p", 0)),
            "protocol": raw_log.get("proto", "TCP").upper(),
            "process_name": "system",
            "asset_criticality": "MEDIUM"
        }

        if log_type == "conn":
            normalized["event_type"] = "Normal_Connection"
            normalized["src_bytes"] = int(raw_log.get("orig_ip_bytes", raw_log.get("orig_bytes", 150) or 150))
            normalized["dst_bytes"] = int(raw_log.get("resp_ip_bytes", raw_log.get("resp_bytes", 150) or 150))
            normalized["duration"] = float(raw_log.get("duration", 0.0) or 0.0)
        elif log_type == "dns":
            query = raw_log.get("query", "localhost")
            normalized["event_type"] = "DNS_Tunneling" if len(query) > 100 else "DNS_Query"
            normalized["process_name"] = "nslookup.exe"
            normalized["protocol"] = "DNS"
        elif log_type == "http":
            normalized["event_type"] = "HTTP_Request"
            normalized["process_name"] = "chrome.exe"
            
        return normalized


# ─── 8. Suricata Parser ───────────────────────────────────────────────────────
class SuricataParser(BaseParser):
    """Parses Suricata EVE JSON event log records."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        alert = raw_log.get("alert", {})
        alert_msg = alert.get("signature", "Network Alert")
        severity_map = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
        severity = severity_map.get(alert.get("severity", 3), "MEDIUM")
        
        event_type = "Normal_Connection"
        if alert:
            event_type = "Network_Sweep" if "sweep" in alert_msg.lower() else "Brute_Force_Login" if "brute" in alert_msg.lower() else "Data_Exfiltration" if "exfil" in alert_msg.lower() else "Suspicious_Process_Spawn"

        return {
            "timestamp": ensure_datetime(raw_log.get("timestamp")),
            "event_type": event_type,
            "src_ip": raw_log.get("src_ip", "127.0.0.1"),
            "dst_ip": raw_log.get("dest_ip", raw_log.get("dst_ip", "127.0.0.1")),
            "src_port": int(raw_log.get("src_port", 0)),
            "dst_port": int(raw_log.get("dest_port", 0)),
            "protocol": raw_log.get("proto", "TCP").upper(),
            "process_name": "suricata_alert",
            "asset_criticality": severity
        }


# ─── 9. Packet Metadata Parser ────────────────────────────────────────────────
class PacketMetadataParser(BaseParser):
    """Parses packet stream flow metadata statistics."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        return {
            "timestamp": ensure_datetime(raw_log.get("timestamp")),
            "event_type": "Normal_Connection",
            "src_ip": raw_log.get("src_ip", "127.0.0.1"),
            "dst_ip": raw_log.get("dst_ip", "127.0.0.1"),
            "src_port": int(raw_log.get("src_port", 49152)),
            "dst_port": int(raw_log.get("dst_port", 80)),
            "protocol": raw_log.get("protocol", "TCP"),
            "src_bytes": int(raw_log.get("total_bytes_sent", 200)),
            "dst_bytes": int(raw_log.get("total_bytes_recv", 200)),
            "packet_rate": float(raw_log.get("packet_rate", 50.0)),
            "process_name": "packet_analyzer",
            "asset_criticality": "LOW"
        }


# ─── 10. Kubernetes Audit Parser ──────────────────────────────────────────────
class KubernetesAuditParser(BaseParser):
    """Parses Kubernetes REST API audit event streams."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        user = raw_log.get("user", {}).get("username", "system")
        verb = raw_log.get("verb", "get")
        uri = raw_log.get("requestURI", "/api/v1/namespaces")
        
        # High risk action in K8s clusters
        event_type = "Process_Start"
        if verb == "create" and "exec" in uri:
            event_type = "Suspicious_Process_Spawn"

        return {
            "timestamp": ensure_datetime(raw_log.get("stageTimestamp", raw_log.get("timestamp"))),
            "event_type": event_type,
            "user_id": user,
            "process_name": "kubectl" if "kubectl" in raw_log.get("userAgent", "") else "kube-apiserver",
            "src_ip": raw_log.get("sourceIPs", ["127.0.0.1"])[0],
            "dst_ip": "10.96.0.1", # Cluster IP
            "dst_port": 6443,      # API Server default
            "protocol": "HTTPS",
            "asset_criticality": "CRITICAL"
        }


# ─── 11. Active Directory Parser ──────────────────────────────────────────────
class ActiveDirectoryParser(BaseParser):
    """Parses Active Directory domain controller authentication streams."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        action = raw_log.get("action", "login")
        user = raw_log.get("samAccountName", raw_log.get("user", "unknown"))
        
        event_type = "Authentication_Success"
        failed_logins = 0
        if "fail" in action.lower() or raw_log.get("status_code") == "0xC000006A":
            event_type = "Brute_Force_Login"
            failed_logins = 1
            
        return {
            "timestamp": ensure_datetime(raw_log.get("timestamp")),
            "event_type": event_type,
            "user_id": user,
            "src_ip": raw_log.get("client_address", "127.0.0.1"),
            "dst_ip": "10.0.0.1", # DC IP
            "dst_port": 88,       # Kerberos
            "protocol": "TCP",
            "process_name": "lsass.exe",
            "failed_logins": failed_logins,
            "asset_criticality": "CRITICAL"
        }


# ─── 12. Cloud IAM Parser ─────────────────────────────────────────────────────
class CloudIamParser(BaseParser):
    """Parses multi-cloud IAM telemetry logs (AWS CloudTrail, GCP Audit, Azure AD)."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        event_name = raw_log.get("eventName", raw_log.get("event_name", "ConsoleLogin"))
        user = raw_log.get("userIdentity", {}).get("userName", raw_log.get("user", "admin"))
        
        event_type = "Authentication_Success"
        if raw_log.get("errorCode") or raw_log.get("errorMessage"):
            event_type = "Brute_Force_Login"

        return {
            "timestamp": ensure_datetime(raw_log.get("eventTime", raw_log.get("timestamp"))),
            "event_type": event_type,
            "user_id": user,
            "src_ip": raw_log.get("sourceIPAddress", "127.0.0.1"),
            "process_name": "cloud_operator",
            "asset_criticality": "HIGH"
        }


# ─── 13. VPN Log Parser ───────────────────────────────────────────────────────
class VpnParser(BaseParser):
    """Parses corporate VPN portal authentication and connection logs."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        action = raw_log.get("action", "connect")
        user = raw_log.get("user", "remote_worker")
        
        event_type = "Authentication_Success"
        failed_logins = 0
        if "fail" in action.lower():
            event_type = "Brute_Force_Login"
            failed_logins = 1

        return {
            "timestamp": ensure_datetime(raw_log.get("timestamp")),
            "event_type": event_type,
            "user_id": user,
            "src_ip": raw_log.get("client_ip", "127.0.0.1"),
            "dst_ip": raw_log.get("vpn_gateway", "127.0.0.1"),
            "dst_port": 1194, # default OpenVPN
            "protocol": "UDP",
            "process_name": "openvpn",
            "failed_logins": failed_logins,
            "asset_criticality": "HIGH"
        }


# ─── 14. SaaS Telemetry Parser ────────────────────────────────────────────────
class SaaSParser(BaseParser):
    """Parses SaaS platforms activity streams (Okta, GSuite)."""
    
    def _normalize(self, raw_log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        app = raw_log.get("app", "Okta")
        event = raw_log.get("eventType", raw_log.get("event", "user.session.start"))
        user = raw_log.get("actor", {}).get("alternateId", raw_log.get("user", "employee"))
        
        event_type = "Authentication_Success"
        if "deny" in event.lower() or "fail" in event.lower():
            event_type = "Brute_Force_Login"

        return {
            "timestamp": ensure_datetime(raw_log.get("published", raw_log.get("timestamp"))),
            "event_type": event_type,
            "user_id": user,
            "src_ip": raw_log.get("client", {}).get("ipAddress", "127.0.0.1"),
            "process_name": app.lower(),
            "asset_criticality": "HIGH"
        }


# ─── Ingestion Dispatcher Registry ───────────────────────────────────────────
class TelemetryParserRegistry:
    """Enterprise dispatching gateway routing logs to appropriate parsing micro-modules."""
    
    def __init__(self) -> None:
        self._parsers: Dict[str, BaseParser] = {
            "windows": WindowsEventParser(),
            "sysmon": SysmonParser(),
            "auditd": LinuxAuditdParser(),
            "etw": EtwParser(),
            "dns": DnsParser(),
            "netflow": NetflowParser(),
            "zeek": ZeekParser(),
            "suricata": SuricataParser(),
            "packet": PacketMetadataParser(),
            "kubernetes": KubernetesAuditParser(),
            "ad": ActiveDirectoryParser(),
            "cloud": CloudIamParser(),
            "vpn": VpnParser(),
            "saas": SaaSParser()
        }

    def parse_log(self, format_name: str, raw_log: Dict[str, Any]) -> Optional[SecurityEvent]:
        """Dispatch a raw log dictionary to the matching parser type."""
        parser = self._parsers.get(format_name.lower())
        if not parser:
            log.warning("No telemetry parser registered for format", format_name=format_name)
            return None
        return parser.parse(raw_log)
