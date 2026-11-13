"""Split a single Set-Cookie header line into a name, a value, and attributes.

This parser does not decide allow or deny. It records structural fields and
raw anomalies (CR/LF, spaces in the name, duplicate attributes) so inspect
can print them and validate can apply policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ParsedSetCookie:
    raw: str
    name: str | None = None
    value: str | None = None
    attributes: dict[str, str | None] = field(default_factory=dict)
    attribute_order: list[str] = field(default_factory=list)
    has_cr: bool = False
    has_lf: bool = False
    has_nul: bool = False
    has_other_c0: bool = False
    name_has_space: bool = False
    duplicate_attributes: list[str] = field(default_factory=list)
    parse_ok: bool = False
    parse_error: str | None = None
    flags: list[str] = field(default_factory=list)


def _flags(p: ParsedSetCookie) -> list[str]:
    out = []
    for name in ("has_cr", "has_lf", "has_nul", "has_other_c0", "name_has_space"):
        if getattr(p, name):
            out.append(name[4:] if name.startswith("has_") else name)
    if p.duplicate_attributes:
        out.append("duplicate_attributes")
    return out


def parse_set_cookie(raw: str) -> ParsedSetCookie:
    if not isinstance(raw, str):
        return ParsedSetCookie(raw="", parse_ok=False, parse_error="header must be a string")
    p = ParsedSetCookie(raw=raw)
    p.has_cr = "\r" in raw
    p.has_lf = "\n" in raw
    p.has_nul = "\x00" in raw
    p.has_other_c0 = any(ord(ch) < 32 and ch not in "\r\n\t" or ord(ch) == 127 for ch in raw)
    # Strip a leading "Set-Cookie:" label if present (case-insensitive).
    body = raw
    lower = raw.lower()
    if lower.startswith("set-cookie:"):
        body = raw.split(":", 1)[1]
        if body.startswith(" "):
            body = body[1:]
    if ";" in body:
        first, rest = body.split(";", 1)
        attr_text = rest
    else:
        first, attr_text = body, ""
    if "=" not in first:
        p.parse_error = "missing name/value pair"
        p.flags = _flags(p)
        return p
    name, value = first.split("=", 1)
    p.name = name
    p.value = value
    p.name_has_space = any(ch in name for ch in " \t")
    if attr_text:
        # Split attributes on semicolons. Values may be empty (Secure, HttpOnly).
        parts = attr_text.split(";")
        for part in parts:
            token = part
            if token.startswith(" "):
                token = token[1:]
            if token == "":
                continue
            if "=" in token:
                aname, aval = token.split("=", 1)
            else:
                aname, aval = token, None
            key = aname
            lkey = key.lower()
            if lkey in {k.lower() for k in p.attributes}:
                p.duplicate_attributes.append(key)
            p.attributes[key] = aval
            p.attribute_order.append(key)
    p.parse_ok = p.name != ""
    if not p.parse_ok:
        p.parse_error = "empty cookie name"
    p.flags = _flags(p)
    return p


def attr_get(parsed: ParsedSetCookie, name: str) -> tuple[bool, str | None]:
    """Case-insensitive attribute lookup. Returns (present, value)."""
    want = name.lower()
    for key, val in parsed.attributes.items():
        if key.lower() == want:
            return True, val
    return False, None


def parsed_to_dict(parsed: ParsedSetCookie) -> dict:
    return {
        "raw": parsed.raw,
        "name": parsed.name,
        "value": parsed.value,
        "attributes": parsed.attributes,
        "attribute_order": parsed.attribute_order,
        "duplicate_attributes": parsed.duplicate_attributes,
        "parse_ok": parsed.parse_ok,
        "parse_error": parsed.parse_error,
        "flags": parsed.flags,
    }
