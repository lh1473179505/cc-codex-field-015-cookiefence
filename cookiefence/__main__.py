"""CLI. inspect already works; validate is the piece to implement."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cookiefence.parse import parse_set_cookie, parsed_to_dict
from cookiefence.policy import PolicyError, load_policy


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="cookiefence")
    sub = p.add_subparsers(dest="cmd", required=True)
    ins = sub.add_parser("inspect", help="print the parsed fields of a Set-Cookie line")
    ins.add_argument("--header", required=True, help="header string, a path, or @path")
    val = sub.add_parser("validate", help="fail-closed admission check for a Set-Cookie line")
    val.add_argument("--header", required=True, help="header string, a path, or @path")
    val.add_argument("--policy", required=True)
    val.add_argument("--report", required=True)
    return p


def _read_header(value: str) -> str:
    if value.startswith("@"):
        text = Path(value[1:]).read_text(encoding="utf-8")
    else:
        try:
            path = Path(value)
            if path.is_file():
                text = path.read_text(encoding="utf-8")
            else:
                return value
        except OSError:
            return value
    if text.endswith("\r\n"):
        return text[:-2]
    if text.endswith("\n"):
        return text[:-1]
    return text


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        raw = _read_header(args.header)
    except OSError as exc:
        print(f"failed to read header: {exc}", file=sys.stderr)
        return 2

    parsed = parse_set_cookie(raw)
    if args.cmd == "inspect":
        print(json.dumps(parsed_to_dict(parsed), ensure_ascii=False, indent=2))
        return 0
    if args.cmd == "validate":
        try:
            policy = load_policy(args.policy)
        except (PolicyError, OSError) as exc:
            print(f"failed to load policy: {exc}", file=sys.stderr)
            return 2
        from cookiefence.engine import validate_set_cookie
        try:
            report = validate_set_cookie(parsed, policy)
        except NotImplementedError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        except Exception as exc:
            print(f"validate failed unexpectedly: {exc}", file=sys.stderr)
            return 2
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        decision = str(report.get("decision", "")).lower()
        if decision == "allow":
            return 0
        if decision == "deny":
            return 1
        print("report is missing a decision of allow or deny", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
