# Validate rules

`validate` is fail-closed. A `Set-Cookie` line is only allowed when every check below succeeds. An unreadable policy or an unreadable `--header` file is a process error (exit 2). A header that can be read as a string, even when it does not parse, must produce a deny report and exit 1.

Reuse `parse_set_cookie`, `attr_get`, and `load_policy`. Do not add a cookie library.

## Structural rejects

- If the raw string (after a trailing newline is stripped by the CLI) is longer than `max_header_bytes` (512 in the public policy), deny with `too_long`.
- If the raw string contains CR, LF, NUL, other C0, or DEL, deny with `control_char`. Do not emit a header that could split an HTTP response.
- If `parse_ok` is false, or the cookie name is empty, deny with `malformed`.
- If the name contains a space or tab, deny with `bad_name`.
- Names and values are measured in UTF-8 bytes. A name longer than `max_name_bytes` (64) is `name_too_long`. A value longer than `max_value_bytes` (256) is `value_too_long`.
- Cookie names may only use ASCII letters, digits, or one of `!#$%&'*+-.^_`|~`. Anything else, including a comma, semicolon, or equals in the name, is `bad_name`.
- Duplicate attributes (same name, case-insensitive) are `duplicate_attr`.

## Secure and prefixes

- If `require_secure` is true (the public default), a missing `Secure` attribute is `missing_secure`. `Secure` is a flag: it must be present and must not have a value other than empty or `None`-like absence; a value such as `Secure=false` is `bad_secure`.
- A name starting with `__Host-` (case-sensitive prefix) additionally requires: `Secure` present, `Path=/` exactly, and no `Domain` attribute. Otherwise `host_prefix`. This applies even if someone later loosens `require_secure`.
- A name starting with `__Secure-` (case-sensitive prefix) requires `Secure`. Otherwise `secure_prefix`.
- The public policy sets `require_https_only_prefixes` to true, which is already implied by the two prefix rules above.

## Domain, Path, SameSite, Max-Age

- If `Domain` is present, compare it case-insensitively after stripping a single leading dot. It must equal `service_host` or be a proper suffix of it (the service host ends with `"." + domain`). `Domain=shop.test` is acceptable for `service_host` `www.shop.test`; `Domain=evil.test` and `Domain=shop.test.evil.test` are `bad_domain`. A `__Host-` cookie that also has `Domain` is still `host_prefix` (already stated).
- If `Path` is present, it must start with `/` and must not contain `;`, `?`, `#`, backslash, or a C0 character. Otherwise `bad_path`. For `__Host-` cookies the path must be exactly `/`.
- If `SameSite` is present, its value must be exactly one of `allowed_samesite` after stripping surrounding spaces, compared case-insensitively against `Strict`, `Lax`, or `None`, but the canonical report value uses the policy spelling. The public policy allows `Strict`, `Lax`, and `None`. Any other value is `bad_samesite`. `SameSite=None` additionally requires `Secure`; otherwise `samesite_none`.
- If `Max-Age` is present, it must be a non-negative integer in decimal with no sign other than an optional `+`, no leading zeros except the value `0`, and no trailing junk. Otherwise `bad_max_age`.

## Public fixtures

Against `fixtures/policy.json` (`service_host` is `www.shop.test`):

- `fixtures/headers/ok-host.txt` → allow
- `fixtures/headers/ok-lax.txt` → allow
- `fixtures/headers/missing-secure.txt` → deny / `missing_secure`
- `fixtures/headers/host-with-domain.txt` → deny / `host_prefix`
- `fixtures/headers/crlf.txt` → deny / `control_char`
- `fixtures/headers/bad-domain.txt` → deny / `bad_domain`
- `fixtures/headers/samesite-none-insecure.txt` → deny / `samesite_none` (and typically `missing_secure`)

## Exit status

- `allow` → exit 0
- `deny` → exit 1
- Policy load errors or an unreadable `--header` file → exit 2, and do not write a report that claims `allow`.
