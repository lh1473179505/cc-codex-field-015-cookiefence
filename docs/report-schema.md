# Report schema

```json
{
  "decision": "allow",
  "reason_codes": [],
  "name": "__Host-session",
  "secure": true,
  "path": "/",
  "domain": null,
  "samesite": "Lax"
}
```

- `decision` is `allow` or `deny`.
- `reason_codes` is an empty array on `allow`. On `deny` it contains one or more of `too_long`, `control_char`, `malformed`, `bad_name`, `name_too_long`, `value_too_long`, `duplicate_attr`, `missing_secure`, `bad_secure`, `host_prefix`, `secure_prefix`, `bad_domain`, `bad_path`, `bad_samesite`, `samesite_none`, `bad_max_age`.
- `name` is the cookie name when parsed, otherwise `null`.
- `secure` is `true` when the `Secure` flag is present, otherwise `false`.
- `path`, `domain`, and `samesite` are the parsed attribute values, or `null` when absent or unparseable.
