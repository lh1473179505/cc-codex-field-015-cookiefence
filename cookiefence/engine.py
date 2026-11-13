"""Fail-closed admission engine for a single Set-Cookie header line."""

from __future__ import annotations

import re
from typing import Any

from cookiefence.parse import ParsedSetCookie, attr_get
from cookiefence.policy import Policy

# Cookie name token per RFC 6265, expanded for the documented allowlist.
_NAME_RE = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")
_MAX_AGE_RE = re.compile(r"^\+?(?:0|[1-9][0-9]*)$")
_PATH_FORBIDDEN_RE = re.compile(r"[;?#\\\x00-\x1f]")


def validate_set_cookie(parsed: ParsedSetCookie, policy: Policy) -> dict[str, Any]:
    raw = parsed.raw
    reasons: list[str] = []

    # Structural checks on the raw line first.
    if len(raw.encode("utf-8")) > policy.max_header_bytes:
        reasons.append("too_long")
    if (
        parsed.has_cr
        or parsed.has_lf
        or parsed.has_nul
        or parsed.has_other_c0
    ):
        reasons.append("control_char")

    name = parsed.name if parsed.parse_ok else None
    value = parsed.value if parsed.parse_ok else None

    if not parsed.parse_ok or not name:
        reasons.append("malformed")
        name = None

    if name is not None:
        if parsed.name_has_space or not _NAME_RE.fullmatch(name):
            reasons.append("bad_name")
        if len(name.encode("utf-8")) > policy.max_name_bytes:
            reasons.append("name_too_long")
    if value is not None and len(value.encode("utf-8")) > policy.max_value_bytes:
        reasons.append("value_too_long")

    if parsed.duplicate_attributes:
        reasons.append("duplicate_attr")

    secure_present, secure_value = attr_get(parsed, "Secure")
    secure = bool(secure_present)
    if secure_present and secure_value is not None:
        reasons.append("bad_secure")
    if policy.require_secure and not secure_present:
        reasons.append("missing_secure")

    if name is not None:
        if name.startswith("__Host-"):
            path_present, path_value = attr_get(parsed, "Path")
            domain_present, _ = attr_get(parsed, "Domain")
            if (
                not secure_present
                or not path_present
                or path_value != "/"
                or domain_present
            ):
                reasons.append("host_prefix")
        elif name.startswith("__Secure-") and not secure_present:
            reasons.append("secure_prefix")

    domain_present, domain_value = attr_get(parsed, "Domain")
    if domain_present:
        domain = (domain_value or "").removeprefix(".")
        host = policy.service_host
        if domain == "" or not (
            host == domain.lower() or host.endswith("." + domain.lower())
        ):
            reasons.append("bad_domain")

    path_present, path_value = attr_get(parsed, "Path")
    if path_present and (
        not isinstance(path_value, str)
        or not path_value.startswith("/")
        or _PATH_FORBIDDEN_RE.search(path_value) is not None
    ):
        reasons.append("bad_path")

    samesite_present, samesite_value = attr_get(parsed, "SameSite")
    samesite_report: str | None = None
    if samesite_present:
        candidate = (samesite_value or "").strip()
        canonical = {
            allowed.lower(): allowed for allowed in policy.allowed_samesite
        }
        if candidate.lower() in canonical:
            samesite_report = canonical[candidate.lower()]
            if candidate.lower() == "none" and not secure_present:
                reasons.append("samesite_none")
        else:
            reasons.append("bad_samesite")

    max_age_present, max_age_value = attr_get(parsed, "Max-Age")
    if max_age_present and (
        not isinstance(max_age_value, str)
        or _MAX_AGE_RE.fullmatch(max_age_value) is None
    ):
        reasons.append("bad_max_age")

    return {
        "decision": "allow" if not reasons else "deny",
        "reason_codes": reasons,
        "name": name,
        "secure": secure,
        "path": path_value if path_present else None,
        "domain": domain_value if domain_present else None,
        "samesite": samesite_report,
    }
