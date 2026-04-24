from __future__ import annotations

from typing import Any

from ..config import get_settings

try:
    from keycloak import KeycloakAdmin, KeycloakOpenID
except Exception:  # pragma: no cover - optional dependency guard
    KeycloakAdmin = None
    KeycloakOpenID = None


class KeycloakUnavailableError(RuntimeError):
    pass


class KeycloakIAM:
    def __init__(self) -> None:
        settings = get_settings()
        if not settings.keycloak_enabled:
            raise KeycloakUnavailableError("Keycloak is disabled")
        if KeycloakOpenID is None or KeycloakAdmin is None:
            raise KeycloakUnavailableError("python-keycloak is not installed")
        if not settings.keycloak_server_url or not settings.keycloak_client_id:
            raise KeycloakUnavailableError("Keycloak configuration is incomplete")

        self._openid = KeycloakOpenID(
            server_url=settings.keycloak_server_url,
            realm_name=settings.keycloak_realm,
            client_id=settings.keycloak_client_id,
            client_secret_key=settings.keycloak_client_secret,
        )
        self._admin = KeycloakAdmin(
            server_url=settings.keycloak_server_url,
            realm_name=settings.keycloak_realm,
            client_id=settings.keycloak_admin_client_id or settings.keycloak_client_id,
            client_secret_key=settings.keycloak_admin_client_secret or settings.keycloak_client_secret,
            verify=True,
        )

    def register_user(self, *, email: str, username: str, password: str, role: str = "REQUESTER") -> dict[str, Any]:
        payload = {
            "email": email,
            "username": username,
            "enabled": True,
            "emailVerified": False,
            "requiredActions": ["VERIFY_EMAIL"],
            "credentials": [{"type": "password", "value": password, "temporary": False}],
        }
        user_id = self._admin.create_user(payload)
        self._admin.send_verify_email(user_id)
        self._assign_role(user_id=user_id, role=role)
        return {"id": user_id, "email": email, "role": role}

    def login(self, *, username: str, password: str) -> dict[str, Any]:
        token = self._openid.token(username=username, password=password)
        return token

    def introspect(self, access_token: str) -> dict[str, Any]:
        return self._openid.introspect(access_token)

    def _assign_role(self, *, user_id: str, role: str) -> None:
        role_name = role.strip().upper()
        mapping = {"OWNER": "OWNER", "REQUESTER": "REQUESTER", "ADMIN": "ADMIN"}
        if role_name not in mapping:
            return
        role_obj = self._admin.get_realm_role(mapping[role_name])
        self._admin.assign_realm_roles(user_id=user_id, roles=[role_obj])
