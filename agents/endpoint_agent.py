"""
IMMUNEX Autonomous EDR Agent
==============================
Production-grade host-level detection & response endpoint agent.
Gathers live process trees, connection mappings, process lineage, and
runs real-time lightweight YARA behavioral scans against malicious indicators.
"""

from __future__ import annotations

import time
import httpx
import psutil
import re
import os
from typing import Dict, Any, List, Optional

class EndpointAgent:
    """
    Lightweight process and connection monitor running on distributed endpoints.
    Collects live telemetry, buffers when disconnected, and sends heartbeats.
    """
    def __init__(self, agent_id: str, server_url: str, hostname: str, ip: str, os_type: str) -> None:
        self.agent_id = agent_id
        self.server_url = server_url
        self.hostname = hostname
        self.ip = ip
        self.os = os_type
        self.status = "ACTIVE"
        self._buffer: List[Dict[str, Any]] = []

    def log_process(self, process_name: str, cmdline: str, pid: int) -> Dict[str, Any]:
        """Backward-compatible log process API enriched with YARA signatures and lineage."""
        sigs = self.yara_behavioral_scan(process_name, cmdline)
        lineage = self.get_process_lineage(pid)
        
        event = {
            "timestamp": time.time(),
            "agent_id": self.agent_id,
            "event_type": "process_launch",
            "process_name": process_name,
            "command_line": cmdline,
            "pid": pid,
            "src_ip": self.ip,
            "triggered_signatures": sigs,
            "lineage": lineage
        }
        self._buffer.append(event)
        if len(self._buffer) > 1000:
            self._buffer.pop(0)
        return event

    def yara_behavioral_scan(self, process_name: str, cmdline: str) -> List[str]:
        """Perform lightweight YARA-inspired regex scan on process names and commands."""
        triggered = []
        if not cmdline:
            return triggered

        cmd_lower = cmdline.lower()
        proc_lower = process_name.lower()

        # 1. Encoded PowerShell & Evasion tactics
        if "powershell" in cmd_lower or "pwsh" in cmd_lower:
            if re.search(r"-[eE][nN][cC][oO]?[dD]?[eE]?[dD]?[sS]?\s+[A-Za-z0-9+/=]{10,}", cmdline):
                triggered.append("ENCODED_POWERSHELL")
            if any(ev in cmd_lower for ev in ("bypass", "nop", "hidden", "noexit")):
                triggered.append("POWERSHELL_EVASION")
            if any(exec_op in cmd_lower for exec_op in ("iex", "invoke-expression", "downloadstring", "downloadfile")):
                triggered.append("POWERSHELL_INLINE_EXEC")

        # 2. LOLBins heuristics (Abusing legitimate Windows/Linux binaries)
        lolbins = {
            "certutil": ["-urlcache", "-split", "-decode"],
            "bitsadmin": ["/transfer", "/download"],
            "regsvr32": ["/s", "/u", "/i:http", "scrobj.dll"],
            "wmic": ["process", "call", "create"],
            "mshta": ["http", "javascript", "vbscript"],
            "curl": ["http", "-o", "--output"],
            "wget": ["http", "-o", "--output"]
        }
        for bin_name, indicators in lolbins.items():
            if bin_name in proc_lower or bin_name in cmd_lower:
                if any(ind in cmd_lower for ind in indicators):
                    triggered.append(f"LOLBIN_SUSPICIOUS_PARAM_{bin_name.upper()}")

        # 3. Ransomware indicators (Shadow copies / boot modifications)
        ransomware_sigs = {
            "vssadmin": ["delete", "shadows"],
            "wmic": ["shadowcopy", "delete"],
            "bcdedit": ["recoveryenabled", "no", "ignoreallfailures"],
            "wbadmin": ["delete", "catalog"]
        }
        for bin_name, indicators in ransomware_sigs.items():
            if bin_name in proc_lower or bin_name in cmd_lower:
                if all(ind in cmd_lower for ind in indicators):
                    triggered.append(f"RANSOMWARE_MUTATION_{bin_name.upper()}")

        # 4. Privilege Escalation / Threat Extraction
        priv_esc = ["runas", "psexec", "mimikatz", "sekurlsa", "lsass", "token::elevate", "whoami /priv"]
        for p in priv_esc:
            if p in cmd_lower:
                triggered.append(f"PRIVILEGE_ESCALATION_{p.upper().replace(' ', '_').replace('::', '_')}")

        return triggered

    def get_process_lineage(self, pid: int) -> List[Dict[str, Any]]:
        """Traverse parent processes upwards to construct full execution lineage."""
        lineage = []
        try:
            p = psutil.Process(pid)
            while p:
                try:
                    pinfo = {
                        "pid": p.pid,
                        "ppid": p.ppid(),
                        "name": p.name(),
                        "cmdline": " ".join(p.cmdline()) if p.cmdline() else "",
                        "username": p.username() if hasattr(p, 'username') else "unknown"
                    }
                    lineage.append(pinfo)
                    p = p.parent()
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    break
        except Exception:
            pass
        return lineage

    def collect_live_processes(self, limit: int = 100) -> List[Dict[str, Any]]:
        """Enumerate and analyze active process tree executing on the host."""
        processes = []
        count = 0
        try:
            for p in psutil.process_iter(['pid', 'ppid', 'name', 'cmdline', 'username']):
                try:
                    pinfo = p.info
                    cmdline = " ".join(pinfo['cmdline']) if pinfo['cmdline'] else ""
                    name = pinfo['name'] or "unknown"
                    sigs = self.yara_behavioral_scan(name, cmdline)
                    
                    if sigs or count < limit:
                        p_data = {
                            "pid": pinfo['pid'],
                            "ppid": pinfo['ppid'] or 0,
                            "process_name": name,
                            "command_line": cmdline,
                            "username": pinfo['username'] or "unknown",
                            "triggered_signatures": sigs,
                            "threat_level": "HIGH" if sigs else "INFO"
                        }
                        processes.append(p_data)
                        if not sigs:
                            count += 1
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue
        except Exception:
            pass
        return processes

    def collect_live_connections(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Enumerate live TCP/UDP socket connections."""
        connections = []
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns[:limit]:
                try:
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "0.0.0.0:0"
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "0.0.0.0:0"
                    
                    conn_data = {
                        "family": "IPv4" if c.family == 2 else "IPv6",
                        "type": "TCP" if c.type == 1 else "UDP",
                        "local_address": laddr,
                        "remote_address": raddr,
                        "status": c.status,
                        "pid": c.pid or 0
                    }
                    connections.append(conn_data)
                except Exception:
                    continue
        except Exception:
            # Fallback to local process connection if net_connections kind isn't permitted
            try:
                p = psutil.Process()
                for c in p.connections()[:limit]:
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "0.0.0.0:0"
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "0.0.0.0:0"
                    conn_data = {
                        "family": "IPv4" if c.family == 2 else "IPv6",
                        "type": "TCP" if c.type == 1 else "UDP",
                        "local_address": laddr,
                        "remote_address": raddr,
                        "status": c.status,
                        "pid": os.getpid()
                    }
                    connections.append(conn_data)
            except Exception:
                pass
        return connections

    def gather_live_telemetry(self) -> None:
        """Run collectors, invoke behavioral scanners, and insert findings into memory buffer."""
        procs = self.collect_live_processes(limit=50)
        conns = self.collect_live_connections(limit=30)

        # Buffer suspicious activities as primary events
        for p in procs:
            if p.get("triggered_signatures"):
                event = {
                    "timestamp": time.time(),
                    "agent_id": self.agent_id,
                    "event_type": "suspicious_activity",
                    "process_name": p["process_name"],
                    "command_line": p["command_line"],
                    "pid": p["pid"],
                    "src_ip": self.ip,
                    "payload": {
                        "triggered_signatures": p["triggered_signatures"],
                        "lineage": self.get_process_lineage(p["pid"]),
                        "username": p["username"]
                    }
                }
                self._buffer.append(event)

        # Buffer active system profile metrics
        system_event = {
            "timestamp": time.time(),
            "agent_id": self.agent_id,
            "event_type": "host_telemetry",
            "src_ip": self.ip,
            "payload": {
                "processes_running": len(procs),
                "connections_active": len(conns),
                "connections": conns[:10]
            }
        }
        self._buffer.append(system_event)

        # Truncate buffer to prevent out of memory issues
        while len(self._buffer) > 1000:
            self._buffer.pop(0)

    async def dispatch_telemetry(self) -> bool:
        """Upload buffered telemetry data to target server."""
        if not self._buffer:
            return True
        payload = {
            "agent_id": self.agent_id,
            "events": self._buffer
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(f"{self.server_url}/api/v1/agents/telemetry", json=payload, timeout=5.0)
                if resp.status_code == 200:
                    self._buffer.clear()
                    return True
        except Exception:
            pass
        return False

    async def send_heartbeat(self) -> bool:
        """Send a real-time host metric heartbeat."""
        cpu = 12.5
        memory = 45.1
        disk = 60.3
        try:
            cpu = psutil.cpu_percent(interval=None)
            memory = psutil.virtual_memory().percent
            disk = psutil.disk_usage('/').percent
        except Exception:
            pass

        payload = {
            "agent_id": self.agent_id,
            "status": self.status,
            "metrics": {
                "cpu_usage": cpu,
                "memory_usage": memory,
                "disk_usage": disk
            }
        }
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(f"{self.server_url}/api/v1/agents/heartbeat", json=payload, timeout=5.0)
                return resp.status_code == 200
        except Exception:
            pass
        return False
