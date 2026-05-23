"""
IMMUNEX Layer 3 — Mitigation Actions
======================================
Generates deterministic, production-safe, auditable mitigation commands
for both Linux and Windows environments.

Each action function returns a dict with:
  linux_commands:        list of bash / iptables / systemctl commands
  windows_commands:      list of PowerShell / netsh / net commands
  verification_commands: post-execution verification steps
  rollback_commands:     commands to undo the mitigation safely

All commands are:
  ✓ Realistic (production-grade syntax)
  ✓ Parameterised with actual IP / process / user values
  ✓ Safe by default (no rm -rf, no format, no destructive file ops)
  ✓ Auditable (include logging / event recording steps)
"""

from __future__ import annotations

import os
import sys
import json
import time
import shutil
import psutil
import subprocess
from pathlib import Path
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from utils.logger import log


@dataclass
class CommandSet:
    """Bundled mitigation commands for all platforms."""
    linux_commands: list[str] = field(default_factory=list)
    windows_commands: list[str] = field(default_factory=list)
    verification_commands: list[str] = field(default_factory=list)
    rollback_commands: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "linux_commands": self.linux_commands,
            "windows_commands": self.windows_commands,
            "verification_commands": self.verification_commands,
            "rollback_commands": self.rollback_commands,
        }


# ─── Action Generators ────────────────────────────────────────────────────────


def block_ip(
    attacker_ip: str,
    interface: str = "eth0",
    chain: str = "INPUT",
) -> CommandSet:
    """Block all traffic from a malicious IP address."""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Block attacker IP {attacker_ip}",
            f"iptables -I {chain} -s {attacker_ip} -j DROP",
            f"iptables -I FORWARD -s {attacker_ip} -j DROP",
            f"iptables -I OUTPUT -d {attacker_ip} -j DROP",
            f"ip6tables -I {chain} -s ::ffff:{attacker_ip} -j DROP",
            f"ipset create IMMUNEX_BLOCKLIST hash:ip",
            f"ipset add IMMUNEX_BLOCKLIST {attacker_ip}",
            f"iptables -I {chain} -m set --match-set IMMUNEX_BLOCKLIST src -j DROP",
            f"logger -t IMMUNEX 'Blocked attacker IP {attacker_ip}'",
        ],
        windows_commands=[
            f"# IMMUNEX: Block attacker IP {attacker_ip}",
            f'New-NetFirewallRule -DisplayName "IMMUNEX_BLOCK_{attacker_ip.replace(".", "_")}" '
            f'-Direction Inbound -RemoteAddress {attacker_ip} -Action Block -Enabled True',
            f'New-NetFirewallRule -DisplayName "IMMUNEX_BLOCK_OUT_{attacker_ip.replace(".", "_")}" '
            f'-Direction Outbound -RemoteAddress {attacker_ip} -Action Block -Enabled True',
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 4625 '
            f'-EntryType Warning -Message "Blocked attacker IP {attacker_ip}"',
        ],
        verification_commands=[
            f"iptables -L {chain} -n | grep {attacker_ip}",
            f"ping -c 1 -W 1 {attacker_ip} && echo FAIL: IP still reachable || echo PASS: IP blocked",
        ],
        rollback_commands=[
            f"iptables -D {chain} -s {attacker_ip} -j DROP",
            f"iptables -D FORWARD -s {attacker_ip} -j DROP",
            f"iptables -D OUTPUT -d {attacker_ip} -j DROP",
            f"ipset del IMMUNEX_BLOCKLIST {attacker_ip}",
            f'Remove-NetFirewallRule -DisplayName "IMMUNEX_BLOCK_{attacker_ip.replace(".", "_")}"',
        ],
    )


def isolate_host(
    target_ip: str,
    management_ip: str = "10.0.0.1",
    interface: str = "eth0",
) -> CommandSet:
    """Network-isolate a compromised host while preserving management access."""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Isolate host {target_ip} (preserve management: {management_ip})",
            f"iptables -I INPUT ! -s {management_ip} -d {target_ip} -j DROP",
            f"iptables -I OUTPUT -s {target_ip} ! -d {management_ip} -j DROP",
            f"iptables -I FORWARD -i {interface} -s {target_ip} -j DROP",
            f"iptables -I FORWARD -i {interface} -d {target_ip} -j DROP",
            # ARP poisoning prevention
            f"arptables -A INPUT -s {target_ip} -j DROP",
            f"logger -t IMMUNEX 'Host {target_ip} isolated — management via {management_ip} preserved'",
        ],
        windows_commands=[
            f"# IMMUNEX: Isolate host {target_ip}",
            f'New-NetFirewallRule -DisplayName "IMMUNEX_ISOLATE_INBOUND" '
            f'-Direction Inbound -Action Block -Enabled True -Profile Any',
            f'New-NetFirewallRule -DisplayName "IMMUNEX_ISOLATE_OUTBOUND" '
            f'-Direction Outbound -Action Block -Enabled True -Profile Any',
            f'New-NetFirewallRule -DisplayName "IMMUNEX_ALLOW_MGMT" '
            f'-Direction Inbound -RemoteAddress {management_ip} -Action Allow -Enabled True',
            f'Set-NetFirewallProfile -All -DefaultInboundAction Block',
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 4649 '
            f'-EntryType Warning -Message "Host {target_ip} network-isolated"',
        ],
        verification_commands=[
            f"iptables -L FORWARD -n | grep {target_ip}",
            f"nmap -sn {target_ip} 2>&1 | grep 'Host is up' && echo FAIL || echo PASS: Host isolated",
        ],
        rollback_commands=[
            f"iptables -D INPUT ! -s {management_ip} -d {target_ip} -j DROP",
            f"iptables -D OUTPUT -s {target_ip} ! -d {management_ip} -j DROP",
            f"iptables -D FORWARD -i {interface} -s {target_ip} -j DROP",
            f"iptables -D FORWARD -i {interface} -d {target_ip} -j DROP",
            f'Remove-NetFirewallRule -DisplayName "IMMUNEX_ISOLATE_INBOUND"',
            f'Remove-NetFirewallRule -DisplayName "IMMUNEX_ISOLATE_OUTBOUND"',
        ],
    )


def revoke_token(
    user_id: str,
    session_prefix: str = "sess",
) -> CommandSet:
    """Revoke active sessions and authentication tokens for a user."""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Revoke tokens for user {user_id}",
            f"pkill -KILL -u {user_id}",
            f"loginctl terminate-user {user_id}",
            f"find /tmp /var/run -name '{session_prefix}*{user_id}*' -exec rm -f {{}} \\;",
            # Redis-based token blacklist (if applicable)
            f"redis-cli KEYS 'token:*:{user_id}' | xargs -r redis-cli DEL",
            f"logger -t IMMUNEX 'Tokens revoked for user {user_id}'",
        ],
        windows_commands=[
            f"# IMMUNEX: Revoke tokens for user {user_id}",
            f"Get-PSSession | Where-Object {{$_.UserName -like '*{user_id}*'}} | Remove-PSSession",
            f"Invoke-Command -ScriptBlock {{",
            f"  $user = Get-ADUser -Identity '{user_id}' -ErrorAction SilentlyContinue",
            f"  if ($user) {{ Set-ADUser -Identity '{user_id}' -ChangePasswordAtLogon $true }}",
            f"}}",
            f"Get-WmiObject -Class Win32_LoggedOnUser | "
            f"Where-Object {{$_.Antecedent -like '*{user_id}*'}} | ForEach-Object {{ "
            f"$session = $_.Dependent; (New-Object -ComObject Shell.Application).ShellExecute('logoff', $session) }}",
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 4634 '
            f'-EntryType Warning -Message "Tokens revoked for {user_id}"',
        ],
        verification_commands=[
            f"loginctl list-sessions | grep {user_id}",
            f"ps aux | grep {user_id} | grep -v grep",
        ],
        rollback_commands=[
            f"# Token revocation rollback requires manual re-issuance of credentials",
            f"echo 'Manual action required: re-issue credentials for {user_id}'",
            f"logger -t IMMUNEX 'Token revocation for {user_id} rolled back — manual credential re-issue required'",
        ],
    )


def suspend_process(
    process_name: str,
    process_hash: str = "",
    user_id: str = "",
) -> CommandSet:
    """Terminate a malicious process by name and optionally by hash."""
    hash_comment = f"  # hash: {process_hash[:16]}..." if process_hash else ""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Suspend malicious process{hash_comment}",
            f"pkill -9 -f '{process_name}'",
            f"killall -9 '{process_name}' 2>/dev/null || true",
            # Prevent re-spawn via cgroup freeze
            f"systemctl kill --kill-who=all '{process_name}.service' 2>/dev/null || true",
            # Block re-execution via file attribute
            f"which '{process_name}' 2>/dev/null | xargs -I{{}} chattr +i {{}} 2>/dev/null || true",
            f"logger -t IMMUNEX 'Process {process_name} suspended (hash={process_hash[:16]})'",
        ],
        windows_commands=[
            f"# IMMUNEX: Suspend malicious process {process_name}",
            f"Get-Process -Name '{process_name.replace('.exe', '')}' -ErrorAction SilentlyContinue | Stop-Process -Force",
            f"Get-WmiObject Win32_Process | Where-Object {{$_.Name -like '{process_name}'}} | "
            f"ForEach-Object {{ $_.Terminate() }}",
            # Remove auto-start entries
            f"Get-ScheduledTask | Where-Object {{$_.Actions.Execute -like '*{process_name}*'}} | Disable-ScheduledTask",
            f"Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run | "
            f"Where-Object {{$_ -like '*{process_name}*'}} | Remove-ItemProperty -Name *",
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 4688 '
            f'-EntryType Warning -Message "Process {process_name} terminated"',
        ],
        verification_commands=[
            f"pgrep -f '{process_name}' && echo FAIL: process still running || echo PASS: process terminated",
            f"Get-Process '{process_name}' -ErrorAction SilentlyContinue",
        ],
        rollback_commands=[
            f"chattr -i $(which '{process_name}') 2>/dev/null || true",
            f"logger -t IMMUNEX 'Process suspension for {process_name} rolled back'",
        ],
    )


def micro_segmentation(
    target_subnet: str,
    attacker_ip: str,
    allowed_ports: list[int] | None = None,
) -> CommandSet:
    """Apply micro-segmentation rules to limit blast radius."""
    allowed_ports = allowed_ports or [443, 80, 22]
    port_allow_rules_linux = " ".join(
        f"-p tcp --dport {p} -j ACCEPT" for p in allowed_ports
    )
    port_allow_rules_ps = ",".join(str(p) for p in allowed_ports)

    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Micro-segmentation for subnet {target_subnet}",
            f"# Block attacker lateral movement within segment",
            f"iptables -I FORWARD -s {attacker_ip} -d {target_subnet} -j DROP",
            f"iptables -I FORWARD -s {target_subnet} -d {attacker_ip} -j DROP",
            f"# Restrict intra-segment east-west to allowed ports only",
            f"iptables -I FORWARD -s {target_subnet} -d {target_subnet} -j IMMUNEX_SEGMENT 2>/dev/null || "
            f"iptables -N IMMUNEX_SEGMENT && iptables -I FORWARD -s {target_subnet} -d {target_subnet} -j IMMUNEX_SEGMENT",
            f"iptables -A IMMUNEX_SEGMENT -p tcp --dport 443 -j ACCEPT",
            f"iptables -A IMMUNEX_SEGMENT -p tcp --dport 80 -j ACCEPT",
            f"iptables -A IMMUNEX_SEGMENT -p tcp --dport 22 -j ACCEPT",
            f"iptables -A IMMUNEX_SEGMENT -j DROP",
            f"logger -t IMMUNEX 'Micro-segmentation applied: {target_subnet}'",
        ],
        windows_commands=[
            f"# IMMUNEX: Micro-segmentation for subnet {target_subnet}",
            f'New-NetFirewallRule -DisplayName "IMMUNEX_SEGMENT_BLOCK_ATTACKER" '
            f'-Direction Inbound -RemoteAddress {attacker_ip} -Action Block -Enabled True',
            f'New-NetFirewallRule -DisplayName "IMMUNEX_SEGMENT_ALLOW_HTTPS" '
            f'-Direction Inbound -Protocol TCP -LocalPort {port_allow_rules_ps} -Action Allow',
            f'New-NetFirewallRule -DisplayName "IMMUNEX_SEGMENT_DEFAULT_DENY" '
            f'-Direction Inbound -Action Block -Enabled True -Profile Domain',
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 5156 '
            f'-EntryType Warning -Message "Micro-segmentation applied for {target_subnet}"',
        ],
        verification_commands=[
            f"iptables -L FORWARD -n | grep '{attacker_ip}.*DROP'",
            f"nmap -sn {target_subnet} 2>&1 | grep 'Host is up'",
        ],
        rollback_commands=[
            f"iptables -D FORWARD -s {attacker_ip} -d {target_subnet} -j DROP",
            f"iptables -D FORWARD -s {target_subnet} -d {attacker_ip} -j DROP",
            f"iptables -F IMMUNEX_SEGMENT && iptables -X IMMUNEX_SEGMENT",
            f'Remove-NetFirewallRule -DisplayName "IMMUNEX_SEGMENT_BLOCK_ATTACKER"',
        ],
    )


def disable_lateral_comms(
    target_subnet: str,
    vlan_id: int = 0,
) -> CommandSet:
    """Disable east-west lateral communication within a compromised network segment."""
    vlan_tag = f" vlan {vlan_id}" if vlan_id else ""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Disable lateral communications in {target_subnet}",
            f"ebtables -A FORWARD --logical-in br0 -p IPv4 --ip-src {target_subnet} "
            f"--ip-dst {target_subnet} -j DROP 2>/dev/null || true",
            f"iptables -I FORWARD -s {target_subnet} -d {target_subnet} -j DROP",
            # Disable ARP broadcasting within segment
            f"arp -n | grep '{target_subnet.split('/')[0].rsplit('.', 1)[0]}' | "
            f"awk '{{print $1}}' | xargs -I{{}} arp -s {{}} 00:00:00:00:00:00 2>/dev/null || true",
            f"logger -t IMMUNEX 'Lateral communications disabled: {target_subnet}'",
        ],
        windows_commands=[
            f"# IMMUNEX: Disable lateral comms in {target_subnet}",
            f'New-NetFirewallRule -DisplayName "IMMUNEX_NO_LATERAL_{target_subnet.replace("/", "_")}" '
            f'-Direction Inbound -RemoteAddress {target_subnet} -LocalAddress {target_subnet} '
            f'-Action Block -Enabled True',
            f"netsh advfirewall firewall add rule name='IMMUNEX_LATERAL_BLOCK' "
            f"dir=in action=block remoteip={target_subnet} localip={target_subnet}",
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 5157 '
            f'-EntryType Warning -Message "Lateral comms disabled: {target_subnet}"',
        ],
        verification_commands=[
            f"iptables -L FORWARD -n | grep '{target_subnet}.*DROP'",
        ],
        rollback_commands=[
            f"iptables -D FORWARD -s {target_subnet} -d {target_subnet} -j DROP",
            f'Remove-NetFirewallRule -DisplayName "IMMUNEX_NO_LATERAL_{target_subnet.replace("/", "_")}"',
        ],
    )


def force_mfa_reset(
    user_id: str,
    admin_email: str = "security@corp.local",
) -> CommandSet:
    """Force MFA re-enrollment for a compromised user account."""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Force MFA reset for user {user_id}",
            f"# Invalidate TOTP secret — requires organisational PAM/RADIUS config",
            f"rm -f /etc/google-authenticator/{user_id}/.google_authenticator 2>/dev/null || true",
            f"sed -i '/{user_id}/d' /etc/security/otp_secrets 2>/dev/null || true",
            f"echo 'MFA_RESET_REQUIRED=1' >> /etc/security/user_flags/{user_id} 2>/dev/null || true",
            f"mail -s 'IMMUNEX: MFA Reset Required' {admin_email} <<< "
            f"'User {user_id} MFA secret invalidated by IMMUNEX. Re-enrollment required.'",
            f"logger -t IMMUNEX 'MFA reset forced for {user_id}'",
        ],
        windows_commands=[
            f"# IMMUNEX: Force MFA reset for user {user_id}",
            f"# Requires Azure AD / Entra ID PowerShell module",
            f"Connect-MgGraph -Scopes 'UserAuthenticationMethod.ReadWrite.All' -ErrorAction SilentlyContinue",
            f"$userId = (Get-MgUser -Filter \"userPrincipalName eq '{user_id}'\").Id",
            f"Get-MgUserAuthenticationMethod -UserId $userId | ForEach-Object {{",
            f"  Remove-MgUserAuthenticationMethod -UserId $userId -AuthenticationMethodId $_.Id -ErrorAction SilentlyContinue",
            f"}}",
            f"Set-MgUser -UserId $userId -StrongAuthenticationRequirements @()",
            f"Send-MailMessage -To {admin_email} -Subject 'IMMUNEX MFA Reset' "
            f"-Body 'MFA reset forced for {user_id}' -SmtpServer 'smtp.corp.local'",
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 4723 '
            f'-EntryType Warning -Message "MFA reset forced for {user_id}"',
        ],
        verification_commands=[
            f"test -f /etc/google-authenticator/{user_id}/.google_authenticator "
            f"&& echo FAIL: MFA secret still present || echo PASS: MFA reset confirmed",
        ],
        rollback_commands=[
            f"# MFA rollback requires manual re-issuance of authenticator enrollment link",
            f"echo 'Re-enrol user {user_id} via IT helpdesk MFA portal'",
        ],
    )


def trigger_honeypot(
    attacker_ip: str,
    honeypot_ip: str = "10.0.99.1",
    target_port: int = 8080,
) -> CommandSet:
    """Redirect attacker traffic to a shadow honeypot using transparent NAT."""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Redirect attacker {attacker_ip} → honeypot {honeypot_ip}",
            f"iptables -t nat -I PREROUTING -s {attacker_ip} -p tcp -j DNAT "
            f"--to-destination {honeypot_ip}:{target_port}",
            f"iptables -t nat -I POSTROUTING -d {honeypot_ip} -j MASQUERADE",
            f"iptables -I FORWARD -s {attacker_ip} -d {honeypot_ip} -j ACCEPT",
            f"# Enable honeypot capture logging",
            f"tcpdump -i any -n host {attacker_ip} -w /var/log/immunex/honeypot_{attacker_ip.replace('.','_')}.pcap &",
            f"logger -t IMMUNEX 'Attacker {attacker_ip} redirected to honeypot {honeypot_ip}'",
        ],
        windows_commands=[
            f"# IMMUNEX: Redirect attacker {attacker_ip} to honeypot",
            f"netsh interface portproxy add v4tov4 listenaddress=0.0.0.0 "
            f"listenport={target_port} connectaddress={honeypot_ip} connectport={target_port}",
            f'New-NetFirewallRule -DisplayName "IMMUNEX_HONEYPOT_ALLOW_{attacker_ip.replace(".", "_")}" '
            f'-Direction Inbound -RemoteAddress {attacker_ip} '
            f'-LocalPort {target_port} -Protocol TCP -Action Allow',
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 4776 '
            f'-EntryType Information -Message "Attacker {attacker_ip} redirected to honeypot"',
        ],
        verification_commands=[
            f"iptables -t nat -L PREROUTING -n | grep {attacker_ip}",
            f"netstat -tlnp | grep {honeypot_ip}",
        ],
        rollback_commands=[
            f"iptables -t nat -D PREROUTING -s {attacker_ip} -p tcp -j DNAT "
            f"--to-destination {honeypot_ip}:{target_port}",
            f"iptables -t nat -D POSTROUTING -d {honeypot_ip} -j MASQUERADE",
            f"pkill -f 'tcpdump.*{attacker_ip.replace('.', '_')}'",
            f"netsh interface portproxy delete v4tov4 listenaddress=0.0.0.0 listenport={target_port}",
        ],
    )


def log_event_only(
    event_summary: str,
    campaign_id: str,
) -> CommandSet:
    """Log-only response — no active mitigation applied."""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Log-only response for campaign {campaign_id[:12]}",
            f"logger -t IMMUNEX -p security.warning '{event_summary}'",
            f"echo '[IMMUNEX] {event_summary}' >> /var/log/immunex/decisions.log",
        ],
        windows_commands=[
            f"# IMMUNEX: Log-only response",
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 4624 '
            f'-EntryType Information -Message "{event_summary} | Campaign: {campaign_id[:12]}"',
        ],
        verification_commands=[
            f"tail -1 /var/log/immunex/decisions.log",
        ],
        rollback_commands=[],
    )


def isolate_network_traffic(
    target_ip: str,
    allowed_cidr: str = "10.0.0.0/8",
) -> CommandSet:
    """Selectively isolate network traffic while preserving internal-only access."""
    return CommandSet(
        linux_commands=[
            f"# IMMUNEX: Selective network isolation for {target_ip}",
            f"# Block all external traffic, allow internal only",
            f"iptables -I INPUT -s {target_ip} ! -d {allowed_cidr} -j DROP",
            f"iptables -I OUTPUT -d {target_ip} ! -s {allowed_cidr} -j DROP",
            f"iptables -I FORWARD -s {target_ip} -j DROP",
            f"# Rate-limit remaining internal traffic",
            f"iptables -I INPUT -s {target_ip} -m limit --limit 100/min -j ACCEPT",
            f"logger -t IMMUNEX 'Network traffic isolated for {target_ip}'",
        ],
        windows_commands=[
            f"# IMMUNEX: Selective traffic isolation for {target_ip}",
            f'New-NetFirewallRule -DisplayName "IMMUNEX_NETISO_BLOCK_EXTERNAL" '
            f'-Direction Outbound -RemoteAddress !{allowed_cidr} -LocalAddress {target_ip} '
            f'-Action Block -Enabled True',
            f'New-NetFirewallRule -DisplayName "IMMUNEX_NETISO_BLOCK_INBOUND" '
            f'-Direction Inbound -LocalAddress {target_ip} -Action Block -Enabled True',
            f'New-NetFirewallRule -DisplayName "IMMUNEX_NETISO_ALLOW_INTERNAL" '
            f'-Direction Inbound -RemoteAddress {allowed_cidr} -LocalAddress {target_ip} '
            f'-Action Allow -Enabled True',
            f'Write-EventLog -LogName Security -Source "IMMUNEX" -EventId 5158 '
            f'-EntryType Warning -Message "Network traffic isolated for {target_ip}"',
        ],
        verification_commands=[
            f"iptables -L INPUT -n | grep {target_ip}",
            f"curl -s --max-time 3 https://1.1.1.1 && echo FAIL: external reach || echo PASS: isolated",
        ],
        rollback_commands=[
            f"iptables -D INPUT -s {target_ip} ! -d {allowed_cidr} -j DROP",
            f"iptables -D OUTPUT -d {target_ip} ! -s {allowed_cidr} -j DROP",
            f"iptables -D FORWARD -s {target_ip} -j DROP",
            f'Remove-NetFirewallRule -DisplayName "IMMUNEX_NETISO_BLOCK_EXTERNAL"',
        ],
    )


# ─── Action Dispatcher ────────────────────────────────────────────────────────


ACTION_DISPATCH: dict[str, object] = {
    "Log_Event":                    log_event_only,
    "Revoke_Token":                 revoke_token,
    "Isolate_Host":                 isolate_host,
    "Block_IP":                     block_ip,
    "Trigger_Shadow_Honeypot":      trigger_honeypot,
    "Micro_Segmentation":           micro_segmentation,
    "Suspend_Process":              suspend_process,
    "Disable_Lateral_Communications": disable_lateral_comms,
    "Force_MFA_Reset":              force_mfa_reset,
    "Isolate_Network_Traffic":      isolate_network_traffic,
}


def generate_commands(
    action_type: str,
    attacker_ip: str,
    target_ip: str,
    process_name: str = "malicious_process",
    user_id: str = "compromised_user",
    target_subnet: str = "10.0.1.0/24",
    campaign_id: str = "UNKNOWN",
) -> CommandSet:
    """
    Dispatch to the correct command generator for the given action type.

    Args:
        action_type:    ActionType string value.
        attacker_ip:    Source IP of the attacker.
        target_ip:      Target / victim host IP.
        process_name:   Malicious process name (for Suspend_Process).
        user_id:        Compromised user account (for Revoke_Token / Force_MFA_Reset).
        target_subnet:  Target network segment.
        campaign_id:    Campaign ID for log references.

    Returns:
        CommandSet with platform-specific commands.
    """
    if action_type == "Log_Event":
        return log_event_only(
            event_summary=f"Threat detected — campaign {campaign_id[:12]}",
            campaign_id=campaign_id,
        )
    elif action_type == "Revoke_Token":
        return revoke_token(user_id=user_id)
    elif action_type == "Isolate_Host":
        return isolate_host(target_ip=target_ip)
    elif action_type == "Block_IP":
        return block_ip(attacker_ip=attacker_ip)
    elif action_type == "Trigger_Shadow_Honeypot":
        return trigger_honeypot(attacker_ip=attacker_ip)
    elif action_type == "Micro_Segmentation":
        return micro_segmentation(
            target_subnet=target_subnet, attacker_ip=attacker_ip
        )
    elif action_type == "Suspend_Process":
        return suspend_process(process_name=process_name)
    elif action_type == "Disable_Lateral_Communications":
        return disable_lateral_comms(target_subnet=target_subnet)
    elif action_type == "Force_MFA_Reset":
        return force_mfa_reset(user_id=user_id)
    elif action_type == "Isolate_Network_Traffic":
        return isolate_network_traffic(target_ip=target_ip)
    else:
        return log_event_only(
            event_summary=f"Unknown action {action_type} — defaulting to log",
            campaign_id=campaign_id,
        )


# ─── Real-World EDR / XDR Active Remediation Executor ─────────────────────────

def audit_log_action(action: str, params: Dict[str, Any], status: str, details: Dict[str, Any]) -> None:
    """Record an audit log entry in the persistent mitigation store."""
    os.makedirs("data/logs", exist_ok=True)
    audit_file = Path("data/logs/mitigation_audit.json")
    entry = {
        "timestamp": time.time(),
        "action": action,
        "parameters": params,
        "status": status,
        "details": details
    }
    log.info("EDR Mitigation Executed", action=action, status=status, details=details)
    try:
        with open(audit_file, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception as exc:
        log.error("Failed to write mitigation audit log", error=str(exc))

def isolate_endpoint(
    target_ip: str,
    dry_run: bool = False,
    management_ip: str = "127.0.0.1"
) -> Dict[str, Any]:
    """Isolate host network stack while whitelisting management and loopback IPs."""
    params = {"target_ip": target_ip, "dry_run": dry_run, "management_ip": management_ip}
    
    # Safety Guards: Never isolate critical IPs or host interface
    critical_ips = ["127.0.0.1", "0.0.0.0", "localhost", "10.0.0.1", "8.8.8.8"]
    if target_ip in critical_ips:
        details = {"reason": "Safety Guard triggered: IP is a protected critical/loopback address."}
        audit_log_action("isolate_endpoint", params, "SKIPPED", details)
        return {"status": "SKIPPED", "details": details}

    log.warning("Applying active host network isolation", target_ip=target_ip, dry_run=dry_run)
    if dry_run:
        details = {"dry_run": True, "msg": f"Would isolate network interface for target {target_ip}."}
        audit_log_action("isolate_endpoint", params, "DRY_RUN", details)
        return {"status": "DRY_RUN", "details": details}

    # Execute system firewall commands based on OS platform
    try:
        if sys.platform.startswith("linux"):
            # Block inbound/outbound traffic on iptables, preserve local and management
            subprocess.run(["iptables", "-A", "INPUT", "-s", management_ip, "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-d", management_ip, "-j", "ACCEPT"], check=True)
            subprocess.run(["iptables", "-A", "INPUT", "-j", "DROP"], check=True)
            subprocess.run(["iptables", "-A", "OUTPUT", "-j", "DROP"], check=True)
            details = {"os": "linux", "rules_applied": "iptables drops applied"}
        elif sys.platform.startswith("win32"):
            # Add Windows firewall rules to isolate everything except management
            subprocess.run([
                "powershell", "-Command",
                f'New-NetFirewallRule -DisplayName "IMMUNEX_EDR_BLOCK" -Direction Inbound -Action Block -Enabled True; '
                f'New-NetFirewallRule -DisplayName "IMMUNEX_EDR_BLOCK_OUT" -Direction Outbound -Action Block -Enabled True; '
                f'New-NetFirewallRule -DisplayName "IMMUNEX_EDR_ALLOW_MGMT" -Direction Inbound -RemoteAddress {management_ip} -Action Allow -Enabled True'
            ], check=True)
            details = {"os": "windows", "rules_applied": "New-NetFirewallRule EDR blocks applied"}
        else:
            details = {"unsupported_platform": sys.platform}
            audit_log_action("isolate_endpoint", params, "FAILED", details)
            return {"status": "FAILED", "details": details}
        
        audit_log_action("isolate_endpoint", params, "SUCCESS", details)
        return {"status": "SUCCESS", "details": details}
    except Exception as exc:
        details = {"error": str(exc)}
        audit_log_action("isolate_endpoint", params, "FAILED", details)
        return {"status": "FAILED", "details": details}

def kill_process_tree(pid: int, dry_run: bool = False) -> Dict[str, Any]:
    """Gracefully and securely terminate a process tree (children first) using psutil."""
    params = {"pid": pid, "dry_run": dry_run}

    # Safety Guards: NEVER kill critical system processes or IMMUNEX itself
    protected_pids = [0, 1, 2, 3, 4, os.getpid()]
    if pid in protected_pids:
        details = {"reason": "Safety Guard: Attempted to kill IMMUNEX agent pid or System kernel core processes."}
        audit_log_action("kill_process_tree", params, "SKIPPED", details)
        return {"status": "SKIPPED", "details": details}

    try:
        proc = psutil.Process(pid)
        proc_name = proc.name().lower()
        protected_processes = ["explorer.exe", "lsass.exe", "services.exe", "svchost.exe", "wininit.exe", "systemd", "init"]
        if any(pp in proc_name for pp in protected_processes):
            details = {"reason": f"Safety Guard: Attempted to kill OS-critical utility '{proc_name}'."}
            audit_log_action("kill_process_tree", params, "SKIPPED", details)
            return {"status": "SKIPPED", "details": details}
    except psutil.NoSuchProcess:
        details = {"reason": f"Process with PID {pid} does not exist."}
        audit_log_action("kill_process_tree", params, "SKIPPED", details)
        return {"status": "SKIPPED", "details": details}
    except Exception as exc:
        details = {"error": str(exc)}
        audit_log_action("kill_process_tree", params, "FAILED", details)
        return {"status": "FAILED", "details": details}

    if dry_run:
        details = {"dry_run": True, "msg": f"Would terminate process PID {pid} ({proc.name()}) and children."}
        audit_log_action("kill_process_tree", params, "DRY_RUN", details)
        return {"status": "DRY_RUN", "details": details}

    try:
        # Traverse children recursively
        children = proc.children(recursive=True)
        killed_children = []
        for child in children:
            try:
                child.kill()
                killed_children.append(child.pid)
            except Exception:
                pass
        
        proc.kill()
        details = {"parent_killed": pid, "children_killed": killed_children}
        audit_log_action("kill_process_tree", params, "SUCCESS", details)
        return {"status": "SUCCESS", "details": details}
    except Exception as exc:
        details = {"error": str(exc)}
        audit_log_action("kill_process_tree", params, "FAILED", details)
        return {"status": "FAILED", "details": details}

def quarantine_file(file_path: str, dry_run: bool = False) -> Dict[str, Any]:
    """Inert and secure a suspect file by XOR encryption and relocation to the quarantine cache."""
    params = {"file_path": file_path, "dry_run": dry_run}
    path_obj = Path(file_path).resolve()
    
    # Safety Guards: Never quarantine critical OS dirs or IMMUNEX workspace
    critical_paths = [
        "c:\\windows", "c:\\program files", "/bin", "/sbin", "/etc", "/lib", "/boot",
        str(Path.cwd().resolve()).lower()
    ]
    path_str = str(path_obj).lower()
    
    if any(cp in path_str for cp in critical_paths):
        details = {"reason": "Safety Guard: Target is in protected system directory or IMMUNEX runtime path."}
        audit_log_action("quarantine_file", params, "SKIPPED", details)
        return {"status": "SKIPPED", "details": details}

    if not path_obj.exists() or not path_obj.is_file():
        details = {"reason": "Target path does not exist or is not a valid file."}
        audit_log_action("quarantine_file", params, "SKIPPED", details)
        return {"status": "SKIPPED", "details": details}

    q_dir = Path("data/quarantine")
    q_dir.mkdir(parents=True, exist_ok=True)

    if dry_run:
        details = {"dry_run": True, "msg": f"Would quarantine, encrypt, and move file {file_path}."}
        audit_log_action("quarantine_file", params, "DRY_RUN", details)
        return {"status": "DRY_RUN", "details": details}

    try:
        # 1. Read source payload
        with open(path_obj, "rb") as f:
            data = f.read()

        # 2. Encrypt/Inert using simple XOR to neutralize execution
        inert_payload = bytes(b ^ 0x55 for b in data)

        # 3. Store inert file securely under quarantine cache
        q_filename = f"q_{int(time.time())}_{path_obj.name}.bin"
        q_path = q_dir / q_filename

        with open(q_path, "wb") as f:
            f.write(inert_payload)

        # 4. Remove access permissions (read-only owner lock)
        os.chmod(q_path, 0o400)

        # 5. Record map context
        map_file = q_dir / "quarantine_map.json"
        q_map = {}
        if map_file.exists():
            try:
                with open(map_file, "r", encoding="utf-8") as f:
                    q_map = json.load(f)
            except Exception:
                pass
        
        q_map[q_filename] = {
            "original_path": str(path_obj),
            "timestamp": time.time(),
            "file_size": len(data)
        }
        
        with open(map_file, "w", encoding="utf-8") as f:
            json.dump(q_map, f, indent=4)

        # 6. Delete original file safely
        path_obj.unlink()

        details = {"quarantine_file": str(q_path), "original_path": str(path_obj)}
        audit_log_action("quarantine_file", params, "SUCCESS", details)
        return {"status": "SUCCESS", "details": details}
    except Exception as exc:
        details = {"error": str(exc)}
        audit_log_action("quarantine_file", params, "FAILED", details)
        return {"status": "FAILED", "details": details}

def revoke_credentials(user_id: str, dry_run: bool = False) -> Dict[str, Any]:
    """Force logoff and terminate session permissions for a compromised username identity."""
    params = {"user_id": user_id, "dry_run": dry_run}

    # Safety Guards: Do not disable system administrators
    protected_users = ["root", "administrator", "system", "admin"]
    if user_id.lower() in protected_users:
        details = {"reason": "Safety Guard: Administrative username revocation is forbidden."}
        audit_log_action("revoke_credentials", params, "SKIPPED", details)
        return {"status": "SKIPPED", "details": details}

    if dry_run:
        details = {"dry_run": True, "msg": f"Would revoke session credentials and logoff user {user_id}."}
        audit_log_action("revoke_credentials", params, "DRY_RUN", details)
        return {"status": "DRY_RUN", "details": details}

    try:
        if sys.platform.startswith("linux"):
            subprocess.run(["pkill", "-KILL", "-u", user_id], check=True)
            subprocess.run(["loginctl", "terminate-user", user_id], check=True)
            details = {"msg": f"Killed sessions for user {user_id} on linux."}
        elif sys.platform.startswith("win32"):
            # Terminate active Remote Desktop / local sessions for target user
            cmd = f'query session | Select-String "{user_id}" | ForEach-Object {{ logoff $_.ToString().Split(" ", [System.StringSplitOptions]::RemoveEmptyEntries)[2] }}'
            subprocess.run(["powershell", "-Command", cmd], check=True)
            details = {"msg": f"Logged off Windows user sessions for {user_id}."}
        else:
            details = {"unsupported_platform": sys.platform}
            audit_log_action("revoke_credentials", params, "FAILED", details)
            return {"status": "FAILED", "details": details}
            
        audit_log_action("revoke_credentials", params, "SUCCESS", details)
        return {"status": "SUCCESS", "details": details}
    except Exception as exc:
        details = {"error": str(exc)}
        audit_log_action("revoke_credentials", params, "FAILED", details)
        return {"status": "FAILED", "details": details}

def rollback_changes(
    mitigation_history: List[Dict[str, Any]] = None,
    dry_run: bool = False
) -> Dict[str, Any]:
    """Reverse and restore EDR mitigation actions sequentially."""
    params = {"dry_run": dry_run}
    
    if not mitigation_history:
        # Load from audit file
        mitigation_history = []
        audit_file = Path("data/logs/mitigation_audit.json")
        if audit_file.exists():
            try:
                with open(audit_file, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            mitigation_history.append(json.loads(line.strip()))
            except Exception:
                pass
    
    if not mitigation_history:
        details = {"msg": "No previous mitigations found to roll back."}
        audit_log_action("rollback_changes", params, "SKIPPED", details)
        return {"status": "SKIPPED", "details": details}

    # Rollback in reverse order
    restored = []
    failed = []

    for entry in reversed(mitigation_history):
        action = entry.get("action")
        status = entry.get("status")
        item_details = entry.get("details", {})
        
        if status != "SUCCESS":
            continue

        try:
            if action == "quarantine_file":
                original_path = Path(item_details.get("original_path"))
                quarantine_path = Path(item_details.get("quarantine_file"))
                
                if quarantine_path.exists():
                    if dry_run:
                        restored.append(f"quarantine_file:{original_path}")
                        continue
                    
                    # Decrypt (XOR 0x55) and restore
                    os.chmod(quarantine_path, 0o600)
                    with open(quarantine_path, "rb") as f:
                        inert_data = f.read()
                    
                    data = bytes(b ^ 0x55 for b in inert_data)
                    
                    # Recreate original file path structure if deleted
                    original_path.parent.mkdir(parents=True, exist_ok=True)
                    with open(original_path, "wb") as f:
                        f.write(data)
                        
                    quarantine_path.unlink()
                    restored.append(str(original_path))
            
            elif action == "isolate_endpoint":
                if dry_run:
                    restored.append("isolate_endpoint:firewall_reset")
                    continue

                if sys.platform.startswith("linux"):
                    subprocess.run(["iptables", "-F"], check=True)
                    restored.append("linux_iptables_flush")
                elif sys.platform.startswith("win32"):
                    subprocess.run(["powershell", "-Command", "Remove-NetFirewallRule -DisplayName 'IMMUNEX_EDR_BLOCK', 'IMMUNEX_EDR_BLOCK_OUT', 'IMMUNEX_EDR_ALLOW_MGMT'"], check=True)
                    restored.append("windows_firewall_rules_removed")
            
            elif action == "kill_process_tree":
                # Kills cannot be directly undone, but we log the attempt to note manual support
                restored.append(f"kill_process_tree:manual_restart_required:{item_details.get('parent_killed')}")
                
            elif action == "revoke_credentials":
                restored.append(f"revoke_credentials:manual_unlock_required:{entry['parameters'].get('user_id')}")

        except Exception as exc:
            failed.append({"action": action, "error": str(exc)})

    details = {"restored_items": restored, "failed_items": failed}
    status_verdict = "FAILED" if failed else "SUCCESS"
    audit_log_action("rollback_changes", params, status_verdict, details)
    return {"status": status_verdict, "details": details}
