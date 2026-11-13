# cookiefence

A small fail-closed admission check for a single `Set-Cookie` line. Parsing already works. `inspect` can print the name, value, and attributes, including flags such as CR/LF or a space in the name. `validate` is still a stub in this snapshot.

This tool is meant to sit in front of a session service that started adding `__Host-` prefixes. The checker must reject response-splitting characters, a `__Host-` cookie that still carries a `Domain` attribute, and `SameSite=None` without `Secure`.

## Requirements

- Python 3.11+
- Standard library only
- No containers

## Already working

```bash
python -m cookiefence inspect --header fixtures/headers/ok-host.txt
```

`--header` may be the header string, a path, or `@path`. When the value is a file, a single trailing newline is stripped.

Rules are in `docs/cookie-rules.md`. The report object is in `docs/report-schema.md`.

## Intended CLI

```bash
python -m cookiefence validate \
  --header fixtures/headers/ok-host.txt \
  --policy fixtures/policy.json \
  --report /tmp/cookiefence-report.json
```

Parameter names are fixed in `cookiefence/__main__.py`. Keep them.
