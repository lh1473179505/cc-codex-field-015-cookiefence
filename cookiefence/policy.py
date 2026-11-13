"""Set-Cookie admission policy loader."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


class PolicyError(ValueError):
    pass


@dataclass
class Policy:
    service_host: str
    require_secure: bool
    require_https_only_prefixes: bool
    max_name_bytes: int
    max_value_bytes: int
    max_header_bytes: int
    allowed_samesite: set[str]
    raw: dict[str, Any] = field(default_factory=dict)


def load_policy(path: str | Path) -> Policy:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception as exc:
        raise PolicyError(f"failed to read policy: {exc}") from exc
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")
    host = data.get("service_host")
    if not isinstance(host, str) or host == "":
        raise PolicyError("service_host must be a non-empty string")
    def _int(name: str, default: int) -> int:
        val = data.get(name, default)
        if not isinstance(val, int) or isinstance(val, bool) or val <= 0:
            raise PolicyError(f"{name} must be a positive integer")
        return val
    samesite = data.get("allowed_samesite", ["Strict", "Lax", "None"])
    if not isinstance(samesite, list) or not all(isinstance(x, str) for x in samesite):
        raise PolicyError("allowed_samesite must be an array of strings")
    return Policy(
        service_host=host.lower(),
        require_secure=bool(data.get("require_secure", True)),
        require_https_only_prefixes=bool(data.get("require_https_only_prefixes", True)),
        max_name_bytes=_int("max_name_bytes", 64),
        max_value_bytes=_int("max_value_bytes", 256),
        max_header_bytes=_int("max_header_bytes", 512),
        allowed_samesite=set(samesite),
        raw=data,
    )
