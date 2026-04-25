from __future__ import annotations


def normalize_role(role: str | None) -> str:
    value = (role or "").strip().lower()
    if value == "owner":
        return "OWNER"
    if value == "admin":
        return "ADMIN"
    if value in {"auditor", "requester", "user"}:
        return "REQUESTER"
    return "REQUESTER"
