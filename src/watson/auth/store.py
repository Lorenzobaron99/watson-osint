"""Auth store — workspace/user management backed by a JSON file.

Minimal implementation for Phase B auth endpoints.
"""

from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Optional


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


@dataclass
class User:
    user_id: str
    workspace_id: str
    email: str
    role: UserRole = UserRole.ANALYST
    created_at: str = ""


@dataclass
class Workspace:
    workspace_id: str
    name: str
    created_at: str = ""


class AuthStore:
    """In-memory JSON-backed auth store."""

    def __init__(self, path: str | Path | None = None):
        if path is None:
            path = Path.home() / ".watson" / "auth_store.json"
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict = self._load()

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text())
            except (json.JSONDecodeError, OSError):
                pass
        return {"workspaces": {}, "users": {}, "api_keys": {}, "tokens": {}}

    def _save(self):
        self._path.write_text(json.dumps(self._data, indent=2, default=str))

    def create_workspace(self, name: str, email: str) -> tuple[Workspace, User]:
        ws_id = f"ws-{uuid.uuid4().hex[:8]}"
        user_id = f"usr-{uuid.uuid4().hex[:8]}"
        now = datetime.now(timezone.utc).isoformat()

        ws = Workspace(workspace_id=ws_id, name=name, created_at=now)
        user = User(user_id=user_id, workspace_id=ws_id, email=email,
                     role=UserRole.ADMIN, created_at=now)

        self._data["workspaces"][ws_id] = {"workspace_id": ws_id, "name": name, "created_at": now}
        self._data["users"][user_id] = {"user_id": user_id, "workspace_id": ws_id,
                                         "email": email, "role": "admin", "created_at": now}
        self._save()
        return ws, user

    def generate_api_key(self, user_id: str) -> str:
        key = f"watson-{uuid.uuid4().hex}"
        self._data["api_keys"][key] = user_id
        self._save()
        return key

    def validate_api_key(self, api_key: str) -> Optional[User]:
        user_id = self._data["api_keys"].get(api_key)
        if user_id:
            return self.get_user(user_id)
        # Fallback: check env keys
        valid = os.environ.get("WATSON_API_KEYS", "").split(",")
        if api_key in [k.strip() for k in valid if k.strip()]:
            # Return a synthetic user for env-based keys
            return User(user_id="env-user", workspace_id="default",
                        email="admin@watson.local", role=UserRole.ADMIN)
        return None

    def create_token(self, user: User) -> "Token":
        token_str = f"tok-{uuid.uuid4().hex}"
        expires = (datetime.now(timezone.utc) + timedelta(hours=24)).isoformat()
        self._data["tokens"][token_str] = {"user_id": user.user_id, "expires_at": expires}
        self._save()
        return Token(token=token_str, expires_at=expires, user_id=user.user_id)

    def get_user(self, user_id: str) -> Optional[User]:
        u = self._data["users"].get(user_id)
        if u:
            return User(user_id=u["user_id"], workspace_id=u["workspace_id"],
                        email=u.get("email", ""), role=UserRole(u.get("role", "analyst")),
                        created_at=u.get("created_at", ""))
        return None

    def get_user_by_email(self, email: str, workspace_id: str) -> Optional[User]:
        for u in self._data["users"].values():
            if u.get("email") == email and u.get("workspace_id") == workspace_id:
                return User(**{k: v for k, v in u.items() if k in
                               ("user_id", "workspace_id", "email", "role", "created_at")})
        return None

    def get_workspace(self, workspace_id: str) -> Optional[Workspace]:
        w = self._data["workspaces"].get(workspace_id)
        if w:
            return Workspace(workspace_id=w["workspace_id"],
                             name=w.get("name", ""), created_at=w.get("created_at", ""))
        return None

    def list_users(self, workspace_id: str) -> list[User]:
        return [User(**{k: v for k, v in u.items() if k in
                        ("user_id", "workspace_id", "email", "role", "created_at")})
                for u in self._data["users"].values()
                if u.get("workspace_id") == workspace_id]


@dataclass
class Token:
    token: str
    expires_at: str
    user_id: str = ""


# Singleton
_auth_store: Optional[AuthStore] = None


def get_auth_store() -> AuthStore:
    global _auth_store
    if _auth_store is None:
        _auth_store = AuthStore()
    return _auth_store
