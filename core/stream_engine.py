"""
IMMUNEX Stream Engine
=======================
Asynchronous SIEM/EDR log simulator.

Generates a continuous stream of SecurityEvent objects mixing:
- Normal baseline traffic (authentication, DNS, HTTP, file access)
- Multi-stage attack chains (reconnaissance → credential access →
  execution → persistence → exfiltration)

Architecture:
- AsyncGenerator pattern so consumers can iterate with `async for`
- Attack chains are stateful objects that advance through stages
- Event cadence is controlled via asyncio.sleep + configurable EPS
"""

from __future__ import annotations

import asyncio
import random
from datetime import datetime
from typing import AsyncGenerator, Optional, Any

from config import get_config, StreamConfig
from utils.constants import (
    BENIGN_EVENT_TYPES,
    BENIGN_PROCESSES,
    GEO_LOCATIONS,
    MALICIOUS_PROCESSES,
    PROTOCOL_MAP,
)
from utils.helpers import (
    fake_sha256,
    new_chain_id,
    new_event_id,
    random_external_ip,
    random_internal_ip,
    utcnow,
)
from utils.logger import log
from utils.schemas import AttackChain, SecurityEvent

# ─── Attack Stage Definitions ────────────────────────────────────────────────

_ATTACK_STAGES: list[list[dict]] = [
    # Stage 0 – Reconnaissance
    [
        {
            "event_type": "Port_Scan",
            "protocol": "TCP",
            "src_bytes": (50, 200),
            "dst_bytes": (0, 50),
            "duration": (0.001, 0.1),
            "failed_logins": (0, 0),
            "connection_count": (200, 1000),
            "packet_rate": (500.0, 5000.0),
            "process_name": "nmap",
        },
        {
            "event_type": "Network_Sweep",
            "protocol": "ICMP",
            "src_bytes": (28, 64),
            "dst_bytes": (0, 64),
            "duration": (0.001, 0.05),
            "failed_logins": (0, 0),
            "connection_count": (50, 500),
            "packet_rate": (100.0, 1000.0),
            "process_name": "ping",
        },
    ],
    # Stage 1 – Credential Access
    [
        {
            "event_type": "Brute_Force_Login",
            "protocol": "TCP",
            "src_bytes": (200, 800),
            "dst_bytes": (100, 400),
            "duration": (0.05, 0.5),
            "failed_logins": (5, 50),
            "connection_count": (10, 100),
            "packet_rate": (20.0, 200.0),
            "process_name": "hydra",
        },
        {
            "event_type": "Password_Spray",
            "protocol": "TCP",
            "src_bytes": (300, 900),
            "dst_bytes": (100, 300),
            "duration": (0.1, 1.0),
            "failed_logins": (3, 30),
            "connection_count": (5, 50),
            "packet_rate": (10.0, 100.0),
            "process_name": "spray.py",
        },
    ],
    # Stage 2 – Execution
    [
        {
            "event_type": "PowerShell_Execution",
            "protocol": "TCP",
            "src_bytes": (1024, 8192),
            "dst_bytes": (512, 4096),
            "duration": (1.0, 30.0),
            "failed_logins": (0, 0),
            "connection_count": (1, 5),
            "packet_rate": (5.0, 50.0),
            "process_name": "powershell.exe",
        },
        {
            "event_type": "Suspicious_Process_Spawn",
            "protocol": "TCP",
            "src_bytes": (512, 4096),
            "dst_bytes": (256, 2048),
            "duration": (0.5, 10.0),
            "failed_logins": (0, 0),
            "connection_count": (1, 10),
            "packet_rate": (2.0, 20.0),
            "process_name": "cmd.exe",
        },
    ],
    # Stage 3 – Persistence
    [
        {
            "event_type": "Registry_Modification",
            "protocol": "TCP",
            "src_bytes": (256, 1024),
            "dst_bytes": (128, 512),
            "duration": (0.1, 2.0),
            "failed_logins": (0, 0),
            "connection_count": (1, 3),
            "packet_rate": (1.0, 10.0),
            "process_name": "reg.exe",
        },
        {
            "event_type": "Scheduled_Task",
            "protocol": "TCP",
            "src_bytes": (512, 2048),
            "dst_bytes": (256, 1024),
            "duration": (0.2, 5.0),
            "failed_logins": (0, 0),
            "connection_count": (1, 5),
            "packet_rate": (1.0, 15.0),
            "process_name": "schtasks.exe",
        },
    ],
    # Stage 4 – Exfiltration
    [
        {
            "event_type": "Data_Exfiltration",
            "protocol": "HTTPS",
            "src_bytes": (100_000, 10_000_000),
            "dst_bytes": (256, 2048),
            "duration": (5.0, 120.0),
            "failed_logins": (0, 0),
            "connection_count": (1, 10),
            "packet_rate": (50.0, 500.0),
            "process_name": "certutil.exe",
        },
        {
            "event_type": "DNS_Tunneling",
            "protocol": "DNS",
            "src_bytes": (200, 4096),
            "dst_bytes": (100, 2048),
            "duration": (0.1, 60.0),
            "failed_logins": (0, 0),
            "connection_count": (50, 500),
            "packet_rate": (20.0, 200.0),
            "process_name": "nslookup.exe",
        },
    ],
]

# ─── Normal Event Templates ───────────────────────────────────────────────────

_NORMAL_TEMPLATES: list[dict] = [
    {
        "event_type": "Normal_Connection",
        "protocol": "TCP",
        "src_bytes": (200, 5000),
        "dst_bytes": (200, 8000),
        "duration": (0.01, 5.0),
        "failed_logins": (0, 0),
        "connection_count": (1, 20),
        "packet_rate": (1.0, 50.0),
    },
    {
        "event_type": "Authentication_Success",
        "protocol": "TCP",
        "src_bytes": (300, 1200),
        "dst_bytes": (200, 800),
        "duration": (0.05, 2.0),
        "failed_logins": (0, 1),
        "connection_count": (1, 5),
        "packet_rate": (2.0, 20.0),
    },
    {
        "event_type": "DNS_Query",
        "protocol": "DNS",
        "src_bytes": (50, 200),
        "dst_bytes": (50, 500),
        "duration": (0.001, 0.5),
        "failed_logins": (0, 0),
        "connection_count": (1, 10),
        "packet_rate": (1.0, 10.0),
    },
    {
        "event_type": "HTTP_Request",
        "protocol": "HTTP",
        "src_bytes": (500, 10_000),
        "dst_bytes": (2000, 500_000),
        "duration": (0.1, 10.0),
        "failed_logins": (0, 0),
        "connection_count": (1, 50),
        "packet_rate": (5.0, 100.0),
    },
    {
        "event_type": "File_Access",
        "protocol": "SMB",
        "src_bytes": (100, 50_000),
        "dst_bytes": (100, 50_000),
        "duration": (0.01, 3.0),
        "failed_logins": (0, 0),
        "connection_count": (1, 5),
        "packet_rate": (2.0, 30.0),
    },
    {
        "event_type": "Process_Start",
        "protocol": "TCP",
        "src_bytes": (50, 500),
        "dst_bytes": (50, 500),
        "duration": (0.001, 1.0),
        "failed_logins": (0, 0),
        "connection_count": (1, 3),
        "packet_rate": (1.0, 5.0),
    },
]


# ─── StreamEngine Class ───────────────────────────────────────────────────────

class StreamEngine:
    """
    Asynchronous security event stream simulator.

    Usage::

        engine = StreamEngine()
        async for event in engine.stream():
            process(event)
    """

    def __init__(
        self,
        cfg: Optional[StreamConfig] = None,
        use_real_telemetry: bool = False,
        pipeline: Optional[Any] = None
    ) -> None:
        self._cfg: StreamConfig = cfg or get_config().stream
        self._rng = random.Random(self._cfg.seed)
        self._active_chains: list[AttackChain] = []
        self._internal_ips: list[str] = [
            random_internal_ip(self._rng) for _ in range(20)
        ]
        self._user_pool: list[str] = [
            f"user{i:03d}" for i in range(1, 51)
        ]
        self._event_count: int = 0
        
        # Phase 1: Real Telemetry Integration
        self.use_real_telemetry = use_real_telemetry
        if pipeline is not None:
            self.telemetry_pipeline = pipeline
        else:
            from telemetry.ingestion_pipeline import TelemetryIngestionPipeline
            self.telemetry_pipeline = TelemetryIngestionPipeline()
            
        log.info("StreamEngine initialised", eps=self._cfg.events_per_second,
                 malicious_ratio=self._cfg.malicious_ratio, use_real_telemetry=self.use_real_telemetry)

    # ── Public API ────────────────────────────────────────────────────────────

    async def stream(self) -> AsyncGenerator[SecurityEvent, None]:
        """Yield SecurityEvent objects indefinitely at the configured EPS."""
        interval = 1.0 / self._cfg.events_per_second
        while True:
            if self.use_real_telemetry:
                events = await self.telemetry_pipeline.consume_batch(limit=10)
                for event in events:
                    self._event_count += 1
                    yield event
                if not events:
                    await asyncio.sleep(0.1)
                else:
                    await asyncio.sleep(interval)
            else:
                burst = (
                    self._rng.random() < self._cfg.burst_probability
                )
                count = self._cfg.burst_multiplier if burst else 1
                for _ in range(count):
                    event = self._generate_event()
                    self._event_count += 1
                    yield event
                await asyncio.sleep(interval)

    def generate_batch(self, n: int = 100) -> list[SecurityEvent]:
        """Generate n events synchronously (used for training data)."""
        return [self._generate_event() for _ in range(n)]

    # ── Private Helpers ───────────────────────────────────────────────────────

    def _generate_event(self) -> SecurityEvent:
        """Route to benign or malicious event generation."""
        # Possibly spawn a new attack chain
        if self._rng.random() < self._cfg.malicious_ratio * 0.2:
            self._spawn_chain()

        # Advance existing chains
        if self._active_chains:
            chain = self._rng.choice(self._active_chains)
            event = self._chain_event(chain)
            self._active_chains = [c for c in self._active_chains if c.active]
            return event

        # Otherwise generate a normal event
        return self._benign_event()

    def _spawn_chain(self) -> None:
        """Create a new AttackChain with unique attacker/target IPs."""
        chain = AttackChain(
            chain_id=new_chain_id(),
            attacker_ip=random_external_ip(self._rng),
            target_ip=self._rng.choice(self._internal_ips),
        )
        self._active_chains.append(chain)
        log.debug("Attack chain spawned", chain_id=chain.chain_id,
                  attacker=chain.attacker_ip, target=chain.target_ip)

    def _chain_event(self, chain: AttackChain) -> SecurityEvent:
        """Generate the next event in an attack chain's stage progression."""
        stage_idx = min(chain.stage, len(_ATTACK_STAGES) - 1)
        template = self._rng.choice(_ATTACK_STAGES[stage_idx])
        stage_name = template["event_type"]

        event = self._build_event(
            template=template,
            src_ip=chain.attacker_ip,
            dst_ip=chain.target_ip,
            process_name=template.get("process_name", "unknown.exe"),
        )
        chain.advance(stage_name)
        return event

    def _benign_event(self) -> SecurityEvent:
        """Generate a single realistic benign event."""
        template = self._rng.choice(_NORMAL_TEMPLATES)
        src = self._rng.choice(self._internal_ips)
        dst = self._rng.choice(self._internal_ips + [random_external_ip(self._rng)])
        process = self._rng.choice(BENIGN_PROCESSES)
        return self._build_event(template=template, src_ip=src,
                                 dst_ip=dst, process_name=process)

    def _build_event(
        self,
        template: dict,
        src_ip: str,
        dst_ip: str,
        process_name: str,
    ) -> SecurityEvent:
        """Construct a fully-populated SecurityEvent from a template."""
        protocol = template.get("protocol", self._rng.choice(list(PROTOCOL_MAP.keys())))
        src_bytes = self._rng.randint(*template["src_bytes"])
        dst_bytes = self._rng.randint(*template["dst_bytes"])
        duration = round(
            self._rng.uniform(*template["duration"]), 6
        )
        failed_logins = self._rng.randint(*template["failed_logins"])
        connection_count = self._rng.randint(*template["connection_count"])
        packet_rate = round(
            self._rng.uniform(*template["packet_rate"]), 4
        )

        process_seed = f"{process_name}_{self._event_count}"
        phash = fake_sha256(process_seed)

        return SecurityEvent(
            timestamp=utcnow(),
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=self._rng.randint(1024, 65535),
            dst_port=self._rng.choice([80, 443, 22, 3389, 445, 53, 8080, 3306]),
            protocol=protocol,
            user_id=self._rng.choice(self._user_pool),
            process_name=process_name,
            process_hash=phash,
            event_type=template["event_type"],
            src_bytes=src_bytes,
            dst_bytes=dst_bytes,
            duration=duration,
            failed_logins=failed_logins,
            connection_count=connection_count,
            packet_rate=packet_rate,
            geo_location=self._rng.choice(GEO_LOCATIONS),
            asset_criticality=self._rng.choice(
                ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            ),
        )
