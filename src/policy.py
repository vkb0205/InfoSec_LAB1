"""Small persistent ACL model shared by KV secrets and Transit keys."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from src.errors import InvalidInputError
from src.storage.repository import _replace_json

POLICY_SCHEMA_VERSION = 1
KV_SECRET = "KV_SECRET"
TRANSIT_KEY = "TRANSIT_KEY"

KV_PERMISSIONS = frozenset({"READ", "WRITE", "DELETE"})
TRANSIT_PERMISSIONS = frozenset({"ENCRYPT", "DECRYPT", "SIGN", "VERIFY"})
ALLOWED_PERMISSIONS = {
    KV_SECRET: KV_PERMISSIONS,
    TRANSIT_KEY: TRANSIT_PERMISSIONS,
}

EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")


class PolicyStoreValidationError(ValueError):
    """Internal validation failure for the policy-store document."""


def canonical_email(email: str) -> str:
    if not isinstance(email, str):
        raise InvalidInputError()
    canonical = email.strip().casefold()
    if not EMAIL_RE.fullmatch(canonical):
        raise InvalidInputError()
    return canonical


def normalize_permissions(
    permissions: str | Iterable[str],
    allowed: frozenset[str],
) -> list[str]:
    values: Iterable[str] = [permissions] if isinstance(permissions, str) else permissions
    try:
        values = list(values)
    except TypeError as exc:
        raise InvalidInputError() from exc
    if not values or not all(
        isinstance(permission, str) and permission.strip()
        for permission in values
    ):
        raise InvalidInputError()
    normalized = {permission.strip().upper() for permission in values}
    if not normalized or not normalized.issubset(allowed):
        raise InvalidInputError()
    return sorted(normalized)


def validate_policy_store(store: Any) -> dict[str, Any]:
    if not isinstance(store, dict) or set(store) != {"schema_version", "policies"}:
        raise PolicyStoreValidationError()
    if store["schema_version"] != POLICY_SCHEMA_VERSION or not isinstance(store["policies"], list):
        raise PolicyStoreValidationError()

    resources: set[tuple[str, str, str]] = set()
    for policy in store["policies"]:
        if not isinstance(policy, dict) or set(policy) != {
            "resource_type",
            "owner_email",
            "resource_id",
            "grants",
        }:
            raise PolicyStoreValidationError()
        resource_type = policy["resource_type"]
        owner_email = policy["owner_email"]
        resource_id = policy["resource_id"]
        grants = policy["grants"]
        if resource_type not in ALLOWED_PERMISSIONS:
            raise PolicyStoreValidationError()
        if (
            not isinstance(owner_email, str)
            or not EMAIL_RE.fullmatch(owner_email)
            or owner_email != owner_email.casefold()
            or not isinstance(resource_id, str)
            or not resource_id
            or not isinstance(grants, dict)
            or not grants
        ):
            raise PolicyStoreValidationError()

        identity = (resource_type, owner_email, resource_id)
        if identity in resources:
            raise PolicyStoreValidationError()
        resources.add(identity)

        for principal, permissions in grants.items():
            if (
                not isinstance(principal, str)
                or not EMAIL_RE.fullmatch(principal)
                or principal != principal.casefold()
                or principal == owner_email
                or not isinstance(permissions, list)
                or not permissions
                or not all(isinstance(permission, str) for permission in permissions)
                or permissions != sorted(set(permissions))
                or not set(permissions).issubset(ALLOWED_PERMISSIONS[resource_type])
            ):
                raise PolicyStoreValidationError()
    return store


class PolicyRepository:
    """Atomic JSON persistence for explicit per-resource allow lists."""

    def __init__(self, policy_path: str | Path | None = None) -> None:
        if policy_path is None:
            policy_path = Path(__file__).resolve().parents[1] / "data/policies.json"
        self.policy_path = Path(policy_path)

    def read(self) -> dict[str, Any]:
        if not self.policy_path.exists():
            return {"schema_version": POLICY_SCHEMA_VERSION, "policies": []}
        try:
            with self.policy_path.open("r", encoding="utf-8") as fh:
                return validate_policy_store(json.load(fh))
        except (OSError, json.JSONDecodeError, PolicyStoreValidationError) as exc:
            raise InvalidInputError() from exc

    def grant(
        self,
        resource_type: str,
        owner_email: str,
        resource_id: str,
        principal_email: str,
        permissions: str | Iterable[str],
    ) -> list[str]:
        allowed = self._allowed(resource_type)
        normalized = normalize_permissions(permissions, allowed)
        self._validate_resource(owner_email, resource_id, principal_email)
        store = self.read()
        policy = self._find(store, resource_type, owner_email, resource_id)
        if policy is None:
            policy = {
                "resource_type": resource_type,
                "owner_email": owner_email,
                "resource_id": resource_id,
                "grants": {},
            }
            store["policies"].append(policy)
        current = policy["grants"].get(principal_email, [])
        policy["grants"][principal_email] = sorted(set(current) | set(normalized))
        store["policies"].sort(
            key=lambda item: (item["resource_type"], item["owner_email"], item["resource_id"])
        )
        self._replace(store)
        return list(policy["grants"][principal_email])

    def revoke(
        self,
        resource_type: str,
        owner_email: str,
        resource_id: str,
        principal_email: str,
        permissions: str | Iterable[str] | None = None,
    ) -> list[str]:
        allowed = self._allowed(resource_type)
        self._validate_resource(owner_email, resource_id, principal_email)
        normalized = None if permissions is None else normalize_permissions(permissions, allowed)
        store = self.read()
        policy = self._find(store, resource_type, owner_email, resource_id)
        if policy is None or principal_email not in policy["grants"]:
            return []

        if normalized is None:
            remaining: list[str] = []
        else:
            remaining = sorted(set(policy["grants"][principal_email]) - set(normalized))
        if remaining:
            policy["grants"][principal_email] = remaining
        else:
            policy["grants"].pop(principal_email)
        if not policy["grants"]:
            store["policies"].remove(policy)
        self._replace(store)
        return remaining

    def allows(
        self,
        resource_type: str,
        owner_email: str,
        resource_id: str,
        principal_email: str,
        permission: str,
    ) -> bool:
        allowed = self._allowed(resource_type)
        normalized = normalize_permissions(permission, allowed)[0]
        policy = self._find(self.read(), resource_type, owner_email, resource_id)
        return policy is not None and normalized in policy["grants"].get(principal_email, [])

    def get_acl(self, resource_type: str, owner_email: str, resource_id: str) -> dict[str, list[str]]:
        self._allowed(resource_type)
        policy = self._find(self.read(), resource_type, owner_email, resource_id)
        if policy is None:
            return {}
        return {
            principal: list(permissions)
            for principal, permissions in sorted(policy["grants"].items())
        }

    def list_shared(self, resource_type: str, principal_email: str) -> list[dict[str, Any]]:
        self._allowed(resource_type)
        return [
            {
                "owner_email": policy["owner_email"],
                "resource_id": policy["resource_id"],
                "permissions": list(policy["grants"][principal_email]),
            }
            for policy in self.read()["policies"]
            if policy["resource_type"] == resource_type and principal_email in policy["grants"]
        ]

    def delete_resource(self, resource_type: str, owner_email: str, resource_id: str) -> None:
        self._allowed(resource_type)
        store = self.read()
        remaining = [
            policy
            for policy in store["policies"]
            if (
                policy["resource_type"],
                policy["owner_email"],
                policy["resource_id"],
            )
            != (resource_type, owner_email, resource_id)
        ]
        if len(remaining) != len(store["policies"]):
            store["policies"] = remaining
            self._replace(store)

    @staticmethod
    def _allowed(resource_type: str) -> frozenset[str]:
        try:
            return ALLOWED_PERMISSIONS[resource_type]
        except (KeyError, TypeError) as exc:
            raise InvalidInputError() from exc

    @staticmethod
    def _validate_resource(owner_email: str, resource_id: str, principal_email: str) -> None:
        if (
            not isinstance(owner_email, str)
            or not EMAIL_RE.fullmatch(owner_email)
            or owner_email != owner_email.casefold()
            or not isinstance(resource_id, str)
            or not resource_id
            or not isinstance(principal_email, str)
            or not EMAIL_RE.fullmatch(principal_email)
            or principal_email != principal_email.casefold()
            or principal_email == owner_email
        ):
            raise InvalidInputError()

    @staticmethod
    def _find(
        store: dict[str, Any],
        resource_type: str,
        owner_email: str,
        resource_id: str,
    ) -> dict[str, Any] | None:
        for policy in store["policies"]:
            if (
                policy["resource_type"],
                policy["owner_email"],
                policy["resource_id"],
            ) == (resource_type, owner_email, resource_id):
                return policy
        return None

    def _replace(self, store: dict[str, Any]) -> None:
        try:
            validate_policy_store(store)
        except PolicyStoreValidationError as exc:
            raise InvalidInputError() from exc
        _replace_json(self.policy_path, store)
