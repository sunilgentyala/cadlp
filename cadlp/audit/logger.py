"""
Zero-retention audit logger.

Records metadata about each proxy decision without retaining prompt content.
Exports in CEF (Common Event Format) for SIEM integration.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import List, Optional

from cadlp.policy.engine import PolicyDecision

logger = logging.getLogger("cadlp.audit")


@dataclass
class AuditEvent:
    timestamp:        float
    tenant_id:        str
    user_id:          str
    session_id:       str
    action:           str
    triggered_rule:   Optional[str]
    entity_types:     List[str]
    redaction_count:  int
    prompt_length:    int
    latency_ms:       float

    # Deliberately no prompt_content, no original values.

    def to_cef(self) -> str:
        """Render as CEF syslog line."""
        ext = (
            f"ts={self.timestamp:.0f} "
            f"tenant={self.tenant_id} "
            f"user={self.user_id} "
            f"session={self.session_id} "
            f"action={self.action} "
            f"rule={self.triggered_rule or 'none'} "
            f"entities={','.join(self.entity_types)} "
            f"redactions={self.redaction_count} "
            f"promptLen={self.prompt_length} "
            f"latencyMs={self.latency_ms:.1f}"
        )
        return f"CEF:0|CADLP|DLPProxy|1.0.0|100|PromptInspection|5|{ext}"

    def to_json(self) -> str:
        return json.dumps(asdict(self), default=str)


class AuditLogger:
    def __init__(self, emit_cef: bool = False):
        self._emit_cef = emit_cef
        self._events: List[AuditEvent] = []

    def record(
        self,
        tenant_id: str,
        user_id: str,
        session_id: str,
        decision: PolicyDecision,
        entity_types: List[str],
        redaction_count: int,
        prompt_length: int,
        latency_ms: float,
    ) -> AuditEvent:
        event = AuditEvent(
            timestamp=time.time(),
            tenant_id=tenant_id,
            user_id=user_id,
            session_id=session_id,
            action=decision.action.value,
            triggered_rule=decision.triggered_rule,
            entity_types=entity_types,
            redaction_count=redaction_count,
            prompt_length=prompt_length,
            latency_ms=latency_ms,
        )
        self._events.append(event)
        if self._emit_cef:
            logger.info(event.to_cef())
        else:
            logger.debug(event.to_json())
        return event

    def get_events(self) -> List[AuditEvent]:
        return list(self._events)

    def clear(self) -> None:
        self._events.clear()
