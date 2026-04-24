import operator
import json
import logging
import sqlite3
from typing import Any
from datetime import datetime, timezone
from ..database import get_db
from ..services.notifications import send_email

logger = logging.getLogger("secure_file_storage")

OPERATORS = {
    "==": operator.eq,
    "!=": operator.ne,
    ">": lambda a, b: a is not None and a > b,
    "<": lambda a, b: a is not None and a < b,
    "contains": lambda a, b: b in str(a) if a is not None else False,
    "in": lambda a, b: a in b if b is not None else False,
}

def evaluate_rule(rule: dict[str, Any], event: dict[str, Any]) -> bool:
    field = rule.get("field")
    op_name = rule.get("operator")
    target_value = rule.get("value")
    
    if not field or not op_name:
        return False
        
    actual_value = event.get(field)
    
    # Handle metadata fields like metadata.risk_score
    if "." in field:
        parts = field.split(".")
        actual_value = event
        for p in parts:
            if isinstance(actual_value, dict):
                actual_value = actual_value.get(p)
            else:
                actual_value = None
                break

    op_func = OPERATORS.get(op_name)
    if not op_func:
        return False
        
    try:
        return op_func(actual_value, target_value)
    except Exception:
        return False

def evaluate_group(group: dict[str, Any], event: dict[str, Any]) -> bool:
    op = group.get("operator", "AND").upper()
    rules = group.get("rules", [])
    
    if not rules:
        return True

    results = []
    for rule in rules:
        if "rules" in rule and "operator" in rule:
            results.append(evaluate_group(rule, event))
        else:
            results.append(evaluate_rule(rule, event))
            
    if op == "AND":
        return all(results)
    else:
        return any(results)

def execute_actions(actions: list[dict[str, Any]], event: dict[str, Any], policy_name: str):
    for action in actions:
        try:
            a_type = action.get("type")
            target = action.get("target")
            
            if a_type == "email" and target:
                send_email(
                    to_email=target,
                    subject=f"[SIEM ALERT] Policy Triggered: {policy_name}",
                    body=f"SIEM Policy '{policy_name}' triggered.\n\nEvent:\n{json.dumps(event, indent=2)}"
                )
            elif a_type == "dashboard_alert":
                # Currently broadcast via ws_alerts in dam.py directly.
                # In the future, this could push a specific alert to an alerts table.
                pass
        except Exception as exc:
            logger.error("SIEM Action failed type=%s target=%s exc=%s", a_type, target, exc)

import uuid
async def create_incident(conn, title: str, owasp_vector: str, risk_score: int, affected_resource: str, attacker_ip: str, log_event_id: str):
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    conn.execute(
        """
        INSERT INTO siem_incidents (id, title, owasp_vector, risk_score, status, affected_resource, attacker_ip, created_at)
        VALUES (?, ?, ?, ?, 'open', ?, ?, ?)
        """,
        (incident_id, title, owasp_vector, risk_score, affected_resource, attacker_ip, datetime.now(timezone.utc).isoformat())
    )
    conn.execute(
        "INSERT INTO siem_incident_logs (incident_id, log_event_id) VALUES (?, ?)",
        (incident_id, log_event_id)
    )
    
    # Broadcast incident to WS
    try:
        from ..routers.ws_alerts import broadcaster
        await broadcaster.broadcast({
            "type": "incident",
            "incident_id": incident_id,
            "title": title,
            "owasp_vector": owasp_vector,
            "risk_score": risk_score
        })
    except:
        pass

async def process_event_siem(event: dict[str, Any]):
    """Called by the background stream worker in dam.py"""
    with get_db() as conn:
        conn.row_factory = sqlite3.Row
        
        # Hardcoded OWASP Top 10 Core Engine Rules for demonstration
        action = event.get("action", "")
        status = event.get("status", "")
        event_type = event.get("event_type", "")
        ip = event.get("source_ip", "")
        
        if event_type == "intrusion" and action == "brute_force_detected":
            await create_incident(conn, "Distributed Password Spray Detected", "A07: Identification and Authentication Failures", 85, f"IP: {ip}", ip, event.get("event_id"))
            
        elif action == "malware_detected" and status == "blocked":
            await create_incident(conn, "Malicious File Upload Blocked", "A03: Injection", 75, f"File: {event.get('file_name', 'Unknown')}", ip, event.get("event_id"))
            
        elif action == "unauthorized_access" and status == "failed":
            await create_incident(conn, "IDOR Share Bypass Attempt", "A01: Broken Access Control", 90, f"Resource: {event.get('file_id')}", ip, event.get("event_id"))
        
        # Then execute dynamic policies
        policies = conn.execute("SELECT * FROM log_policies WHERE is_active = 1").fetchall()
        for p in policies:
            try:
                conditions = json.loads(p["conditions_json"])
                actions = json.loads(p["actions_json"])
                
                if evaluate_group(conditions, event):
                    if p["trigger_type"] == "real_time":
                        execute_actions(actions, event, p["name"])
            except Exception as exc:
                logger.error("Failed to process SIEM policy id=%s exc=%s", p["id"], exc)
