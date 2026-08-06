# Blind LDAP Injector

A generic **blind boolean-based LDAP injection** exploitation/extraction tool for authorized penetration testing.

It targets endpoints where a request parameter is concatenated unsanitized into an LDAP filter, and the application's response differs detectably between a TRUE and a FALSE condition a classic boolean oracle. Everything target-specific (which field is injectable, the TRUE/FALSE response markers, how a rotating CSRF/antiforgery token gets refreshed) is supplied via flags. Nothing about any specific target is hardcoded.

> **Authorized use only.** Only run this against systems you own or are explicitly authorized to test (e.g. a signed pentest engagement or bug bounty program in scope). Unauthorized use against systems you don't have permission to test is illegal.

## How it works

Boolean-based blind LDAP injection works by injecting a payload that closes out the intended filter clause and appends your own condition, e.g.:

```
*)(objectClass=*        <- always TRUE
*)(!(objectClass=*)     <- always FALSE
```

If the app's response differs between these two (different text, different status code, different redirect whatever you can detect), you have an oracle: a single bit of information per request. Chaining many such requests lets you:

- Confirm the injection is real (`--confirm`)
- Brute-force attribute values character-by-character (`--extract`)
- Sweep a wordlist/numeric range for exact matches (`--enumerate`)
- Discover which attributes exist on an anchored entry (`--attr-discover`)
- Binary-search integer-syntax attributes like `lastLogon`/`pwdLastSet` (`--extract-numeric`)
- Verify an anchor value pins exactly one directory entry before trusting correlated extraction (`--anchor-diag`)

Because most of these forms rotate a CSRF/antiforgery token every response, the tool scrapes a fresh token out of each response (via a regex you provide) and threads it through the next request automatically. Independent oracle checks (different characters, different candidates) can be run concurrently across multiple session/token "lanes" for a large speedup over serializing every request behind one token.

## Requirements

```
pip install requests urllib3
```

Python 3.8+.

## Quick start

### 1. Capture a request

Using Burp (or any intercepting proxy), capture the vulnerable request and save it raw ("Copy to file" / "Save item"). Replace the vulnerable parameter's value with `{{INJECT}}`, and — if the app rotates a CSRF token replace that field's value with `{{TOKEN}}`:

```
POST /path/to/vulnerable/form HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Cookie: ASP.NET_SessionId=...

__RequestVerificationToken={{TOKEN}}&Email={{INJECT}}
```

Save this as `request.txt`.

### 2. Confirm the oracle

You'll need to identify a substring in the response that's unique to the TRUE case and one unique to the FALSE case (send `*)(objectClass=*` and `*)(!(objectClass=*)` manually first, in Burp, and diff the two responses). If the token rotates, you also need a regex with one capture group to pull the fresh value out of each response.

```bash
python3 ldap_blind_extract.py --request-file request.txt \
    --true-marker "<substring unique to the TRUE response>" \
    --false-marker "<substring unique to the FALSE response>" \
    --token-regex 'name="__RequestVerificationToken"[^>]*value="([^"]+)"' \
    --confirm
```

A successful run prints:

```
[+] Oracle confirmed: boolean-based blind LDAP injection is live.
```

### 3. Extract data

```bash
python3 ldap_blind_extract.py --request-file request.txt \
    --true-marker "..." --false-marker "..." --token-regex '...' \
    --extract --attr mail --charset 'abcdefghijklmnopqrstuvwxyz0123456789.@_-' \
    --concurrency 8
```

This does a breadth-first character-by-character brute force (not greedy it tracks every prefix still consistent with the oracle, so it doesn't silently jump between two directory entries that share a prefix), and prints every confirmed complete value it finds.

Speed things up with `--concurrency N`: each lane gets its own cookie jar + token and paces itself independently with `--delay`, so raising this is the main lever for extraction speed without hitting the target any harder per-connection.

### No request file? Quick-start fallback

If you'd rather not capture a raw request, `--url`/`--path` work directly against a POST form with fields named `Email`/`__RequestVerificationToken` (a common ASP.NET MVC pattern) — still requires `--true-marker`/`--false-marker`:

```bash
python3 ldap_blind_extract.py --url https://target.example --path /path/to/form \
    --true-marker "..." --false-marker "..." --confirm
```

`--url` is prompted for interactively if omitted in either mode.

## Typical workflow

1. `--confirm` — verify the oracle behaves as expected.
2. `--enumerate --wordlist users.txt` — cold-start discovery: cheap exact-equality sweep to find valid identifiers (usernames, employee IDs, etc.) without ambiguity from prefix wildcards.
3. `--anchor-diag --anchor-attr sAMAccountName --anchor-value <hit>` — confirm a discovered value pins exactly one directory entry before trusting it as an anchor.
4. `--attr-discover --anchor-attr sAMAccountName --anchor-value <hit>` — see which attributes are populated on that entry.
5. `--charset-probe --anchor-attr sAMAccountName --anchor-value <hit> --attr <name>` — check whether an attribute supports substring/wildcard matching at all before spending requests on `--extract`.
6. `--extract --anchor-attr sAMAccountName --anchor-value <hit> --attr <name>` (or `--extract-numeric` for integer-syntax attributes like `lastLogon`) — pull the value.

## Key flags

| Flag | Purpose |
|---|---|
| `--request-file` | Raw HTTP request template (recommended — see Quick start) |
| `--inject-marker` / `--token-marker` | Placeholders in the request file (default `{{INJECT}}` / `{{TOKEN}}`) |
| `--true-marker` / `--false-marker` | Response substrings identifying TRUE/FALSE (repeatable, required) |
| `--token-regex` | Regex with one capture group to scrape a fresh token per response |
| `--concurrency` | Parallel session/token lanes for `--extract`/`--enumerate` |
| `--delay` | Per-lane delay between requests (default 0.3s — be polite to a live target) |
| `--retries` | Retries per oracle check before giving up on a candidate (default 3) |
| `--dump-responses` | Directory to dump every full raw response to, for diffing by hand |
| `--case-insensitive` | Dedupe `--extract` branches that differ only by case |
| `--anchor-attr` / `--anchor-value` | Bind extraction to one already-confirmed entry |
| `--proxy` / `--insecure` | Route through Burp for visibility |

Run `python3 ldap_blind_extract.py --help` for the full list.

## Notes

- `DEFAULT_ATTR_CANDIDATES` in the script is a broad but non-exhaustive list of common Active Directory user attributes (identity, HR/employee, contact, account state, Exchange/Entra hybrid, POSIX) used by `--attr-discover`'s built-in default. Pass `--attr-list` to use your own.
- LDAP filter escaping ([RFC 4515](https://www.rfc-editor.org/rfc/rfc4515)) is applied to every literal candidate value tested — see `ldap_escape()`.
- Every oracle check retries with backoff and a fresh token on anomaly before giving up and marking that candidate inconclusive, so a flaky/rate-limited target doesn't kill the whole run.

## Troubleshooting: "matched neither TRUE nor FALSE marker"

This is the most common snag, and it's almost never the injection itself — it's usually that `--true-marker`/`--false-marker` don't fully describe the app's real response set yet. Work through these in order:

1. **Run `--confirm` alone first**, no anchor, no attribute. If this doesn't cleanly resolve, nothing downstream will either — fix this before touching `--extract`/`--attr-discover`.
2. **Check for more than one TRUE message.** Many apps have several distinct true-condition responses (e.g. "account disabled" vs. "confirmation sent" vs. "unable to send confirmation" are all different TRUE outcomes on some targets). `--true-marker` is repeatable — pass it multiple times rather than assuming one string covers every case. Watch for one marker being a substring of another (e.g. a FALSE message that contains a TRUE message as a prefix); the tool checks all `--false-marker`s before any `--true-marker`, so order your marker choices with that precedence in mind.
3. **Use `--diag --attr <name> --known-value <value you know is correct>`** to isolate whether it's the attribute, the value, or wildcard syntax causing the anomaly — it runs exact-equality, full-value prefix, first-char prefix, and a negative control in sequence.
4. **Use `--anchor-diag`** to check whether an anchor value uniquely pins one entry before trusting anything pulled through it.
5. **Use `--dump-responses <dir>`** to write every full raw response to disk (tagged true/false/anomaly, numbered) and diff a working response against a failing one by hand. Response snippets printed to the terminal are truncated to 300 characters, which is often just boilerplate (`<head>`, favicons) the actual differentiating text can be well past that cutoff.
6. **If failures are inconsistent for identically-shaped payloads** (not tied to specific content), it's more likely infrastructure noise (rate limiting, a load-balanced backend) than a real marker problem — raise `--retries` rather than chasing payload content further.
7. **Remember `--diag`/`--anchor-diag` without `--anchor-attr` query the whole directory**, not one entry a "should be FALSE" sanity check can legitimately come back TRUE if some other real entry happens to match. That's expected on any directory with more than a handful of entries, not a bug; anchor your real extraction runs with `--anchor-attr`/`--anchor-value` to avoid it.
