"""Set-Cookie admission engine. Not implemented in this snapshot."""

from __future__ import annotations

from typing import Any

from cookiefence.parse import ParsedSetCookie
from cookiefence.policy import Policy


def validate_set_cookie(parsed: ParsedSetCookie, policy: Policy) -> dict[str, Any]:
    raise NotImplementedError("validate_set_cookie is not implemented in this snapshot")
