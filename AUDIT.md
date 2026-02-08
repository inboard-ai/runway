# Security Audit Report

**Date:** 2026-02-07
**Scope:** Full codebase review of `runway` server framework
**Branch:** `audit` (builds on fixes from `security` branch)
**Methodology:** Manual code review against SOC 2 Type II trust service criteria,
OWASP Top 10, and enterprise deployment expectations.

---

## Prior work

The `security` branch addressed 11 items from the original `SECURITY_TODO.md`:

- Body size limits, connection limits, header-read timeouts (items 1-3)
- Error disclosure hardening (item 4)
- JWT secret minimum length at both config and auth layers (item 5)
- Debug redaction of secrets (item 6)
- Content-Disposition filename sanitization (item 7)
- Redirect URL validation (item 8)
- Standard security headers on every response (item 9)
- Default bind to loopback (item 10)
- Case-insensitive Bearer parsing per RFC 7235 (item 11)
- Request-level logging (item 14)
- SharedConfig / db::Handle type wrappers (item 17)
- MSRV pinned in Cargo.toml (item 18)

All 20 security tests pass. This audit identifies the remaining gaps.

---

## Findings

### A. Audit trail & logging (SOC 2 CC7.2, CC7.3)

#### A1. No request correlation ID

**Severity:** Medium
**Location:** `src/server.rs:77-161`

Every request should carry a unique identifier so that:
- Clients can report issues with a reference the ops team can grep for.
- Distributed traces across services can be correlated.
- Incident response can reconstruct request timelines.

**Current state:** `handle_request` logs method, path, status, and latency but
nothing linkable to a specific request.

**Recommendation:**
- Generate a `Uuid::now_v7()` per request (time-ordered, sortable).
- Return it in an `X-Request-Id` response header.
- Include it in the structured log line.
- If the client sends `X-Request-Id`, propagate it (but validate format).

#### A2. No remote address in request logs

**Severity:** Medium
**Location:** `src/server.rs:159`

`remote_addr` is captured at accept time (line 189) but only logged on
connection errors (line 207) and connection-limit rejections (line 214).
Successful requests have no source-IP audit trail.

**Current state:** `info!("{method} {path} {} {elapsed:.3?}", status)` -- no
address.

**Recommendation:**
- Thread `remote_addr` through to `handle_request` (or store it in `Context`).
- Log at `info!` alongside the existing fields.
- Consider a `forwarded`/`X-Forwarded-For` parser for reverse-proxy deployments.

#### A3. No structured log format

**Severity:** Low
**Location:** `src/server.rs:159`, framework-wide

SOC 2 auditors expect machine-parseable logs for SIEM ingestion. The current
`info!()` call uses a format string that produces human-readable but
unstructured output.

**Current state:** No `tracing_subscriber` setup in the library; left to the
consumer.

**Recommendation:**
- Use `tracing`'s structured fields (`info!(method = %method, path = %path, ...)`)
  instead of format-string interpolation so any JSON subscriber can emit them.
- Optionally expose a convenience `runway::logging::init()` that wires up
  `tracing_subscriber` with a JSON layer for production.

---

### B. Authentication & session management (SOC 2 CC6.1, CC6.3)

#### B4. No rate limiting on authentication endpoints

**Severity:** High
**Location:** Framework-wide (no rate-limiting mechanism exists)

There is no mechanism to throttle brute-force token guessing, credential
stuffing, or general request flooding per IP or per user.

**Current state:** Connection-limit semaphore (128 max) is the only
backpressure. It does not distinguish between endpoints or clients.

**Recommendation:**
- Add a `RateLimiter` middleware using a token-bucket or sliding-window
  algorithm, keyed by client IP (or `X-Forwarded-For` behind a proxy).
- Make it configurable: global default + per-route overrides.
- Return `429 Too Many Requests` with a `Retry-After` header.
- Can start with an in-process implementation; Redis-backed for
  multi-instance deployments is a future concern.

#### B5. Default token expiry too long (30 days)

**Severity:** Medium
**Location:** `src/config.rs:106`

A 30-day token lifetime means a stolen token is usable for a month.
Enterprise posture expects short-lived access tokens (15-60 minutes) with a
refresh token flow.

**Current state:** `default_token_expiry_days()` returns `30`.

**Recommendation:**
- Change default to `1` day as a safer baseline.
- Add `token_expiry_hours` (or rename to `token_expiry`) with a default of 1
  hour for access tokens.
- Document the refresh-token pattern for consumers who need longer sessions.
- The `SECURITY_TODO.md` item 15 (token revocation) remains relevant here.

#### B6. Missing `aud` and `iss` JWT claims

**Severity:** Medium
**Location:** `src/auth.rs:56-60`, `src/auth.rs:80-84`

`Claims` only contains `sub`, `exp`, `iat`. Without `aud` (audience) and
`iss` (issuer), a token minted by one runway-based service can be replayed
against another.

**Current state:** `Validation::default()` does not check `aud` or `iss`
because they are not set.

**Recommendation:**
- Add `iss` and `aud` fields to `Claims`.
- Populate `iss` from a new `AuthConfig.issuer` field (default: crate name +
  version, or hostname).
- Populate `aud` from a new `AuthConfig.audience` field.
- Enable `Validation::set_issuer` and `Validation::set_audience` in
  `verify_token`.
- These fields should be optional with a deprecation path: warn if unset,
  require in a future major version.

#### B7. HMAC-SHA256 only -- no asymmetric signing option

**Severity:** Low
**Location:** `src/auth.rs:62-66`

`Header::default()` selects HS256. The signing key and verification key are
the same secret, meaning every service that needs to verify tokens must also
possess the signing key.

**Current state:** Single shared secret in `AuthConfig.jwt_secret`.

**Recommendation:**
- Add an `AuthConfig.jwt_algorithm` enum (`HS256`, `RS256`, `ES256`).
- Support `EncodingKey::from_rsa_pem` / `from_ec_pem` and corresponding
  `DecodingKey` variants.
- Default to HS256 for backward compatibility; document RS256/ES256 for
  multi-service deployments.
- This is the lowest priority auth item -- HS256 is fine for single-service
  deployments.

---

### C. Transport security (SOC 2 CC6.1, CC6.7)

#### C8. No TLS termination and no HSTS header

**Severity:** High
**Location:** `src/server.rs` (entire accept loop), `src/server.rs:59-74`

The server listens on plain TCP. In production this is typically behind a
reverse proxy, but:
- The framework offers no native TLS option.
- The expectation is undocumented.
- The `Strict-Transport-Security` header is missing from
  `add_standard_headers`, so even behind a TLS-terminating proxy, browsers
  are not instructed to upgrade future requests.

**Current state:** No TLS, no HSTS.

**Recommendation:**
- Add `Strict-Transport-Security: max-age=63072000; includeSubDomains` to
  `add_standard_headers`, gated behind a config flag
  (`config.server.hsts = true`, default `false` so local dev isn't broken).
- Optionally support native TLS via `tokio-rustls` with cert/key paths in
  config, for deployments without a reverse proxy.
- Document the reverse-proxy expectation in the README.

---

### D. CORS (SOC 2 CC6.1)

#### D9. Origin reflection without allowlist

**Severity:** High
**Location:** `src/server.rs:68-73`

`add_standard_headers` echoes back whatever `Origin` the client sends. This
is functionally equivalent to `Access-Control-Allow-Origin: *` but worse --
it mirrors the exact origin, which browsers treat as a credentialed CORS
response.

Also missing:
- `Access-Control-Allow-Methods`
- `Access-Control-Allow-Headers`
- `Access-Control-Max-Age`
- `OPTIONS` preflight handling

**Current state:** Unconditional origin reflection, no preflight.

**Recommendation:**
- Add `config.server.cors_origins: Vec<String>` (allowlist).
- Only reflect the `Origin` if it matches the allowlist (or if the list
  contains `"*"`).
- Add a dedicated `OPTIONS` handler that returns preflight headers with the
  allowed methods, headers, and a max-age.
- Return `Access-Control-Allow-Credentials: true` only when explicitly
  configured.

---

### E. Input validation (SOC 2 CC6.1)

#### E10. No `Content-Type` enforcement on JSON endpoints

**Severity:** Medium
**Location:** `src/server.rs:108-122`, `src/router.rs:41-47`

`handle_request` reads the body and routes regardless of `Content-Type`.
`Context::json()` deserializes whatever bytes arrive. A client can send
`text/plain` or `multipart/form-data` and the server will happily attempt
JSON parsing.

This enables content-type confusion attacks and bypasses WAF rules that
inspect only `application/json` bodies.

**Current state:** No content-type check anywhere in the pipeline.

**Recommendation:**
- In `Context::json()`, verify that the `Content-Type` header is
  `application/json` (with optional charset parameter). Return
  `415 Unsupported Media Type` otherwise.
- Add an `UnsupportedMediaType` variant to `Error`.

---

### F. Availability (SOC 2 A1.2)

#### F11. No graceful shutdown with drain period

**Severity:** Medium
**Location:** `src/server.rs:183-245`

`shutdown()` stops the accept loop but in-flight requests on already-spawned
tasks are abandoned. During a rolling deploy, clients with active requests
get connection resets.

**Current state:** `oneshot` channel breaks the accept loop; spawned tasks
run to completion only if they finish before the runtime shuts down.

**Recommendation:**
- Replace `tokio::spawn` with a `JoinSet` tracked on the accept loop.
- On shutdown signal, stop accepting, then `join_all` with a configurable
  drain timeout (default: 30 seconds).
- After the drain timeout, drop remaining tasks and exit.
- Wire `tokio::signal::ctrl_c()` and optional `SIGTERM` handling into
  `run()` as the default shutdown trigger.

#### F12. Panics in handlers are silently swallowed

**Severity:** Medium
**Location:** `src/server.rs:195-211`

`tokio::spawn` returns a `JoinHandle` that is never awaited. If a handler
panics, the task disappears with no log entry and no error response -- the
client sees a connection reset.

**Current state:** Dropped `JoinHandle`s.

**Recommendation:**
- Use `JoinSet` (ties into F11) and log panics at `error!` level with the
  request ID from A1.
- Wrap handler execution in `std::panic::AssertUnwindSafe` +
  `futures::FutureExt::catch_unwind` and return a `500 Internal Server Error`
  to the client instead of resetting the connection.

---

### G. Dependency & supply chain (SOC 2 CC6.1, CC8.1)

#### G13. No dependency vulnerability scanning in CI

**Severity:** Medium
**Location:** Process / CI (no code change)

SOC 2 CC6.1 requires identification of vulnerabilities in system components.
There is no `cargo audit` or `cargo deny` step in CI, and no
`deny.toml` / `audit.toml` configuration.

**Recommendation:**
- Add `cargo audit` (RustSec advisory database) to CI.
- Add `cargo deny` with a `deny.toml` that enforces license allowlist and
  bans known-bad crates.
- Run on every PR and on a nightly schedule.

#### G14. Loose dependency version pins

**Severity:** Low
**Location:** `Cargo.toml`

Most dependencies use major-version pins (`"1"`, `"0.1"`) which is fine for
semver, but `libsql = "0.6"` is a `0.x` crate where minor bumps can be
breaking. A `Cargo.lock` should be committed for the library's test suite to
ensure reproducible builds.

**Current state:** No `Cargo.lock` in the repository (standard for libraries,
but the test suite should be reproducible).

**Recommendation:**
- Commit `Cargo.lock` for reproducible CI builds (Rust RFC 2495 recommends
  this even for libraries).
- Consider pinning `libsql` to `0.6.x` or `=0.6.y` until 1.0.
- Document the version policy.

---

## Summary matrix

| ID  | Finding                              | Severity | SOC 2 Criteria | Phase |
|-----|--------------------------------------|----------|-----------------|-------|
| A1  | No request correlation ID            | Medium   | CC7.2, CC7.3    | 1     |
| A2  | No remote address in request logs    | Medium   | CC7.2, CC7.3    | 1     |
| A3  | No structured log format             | Low      | CC7.2           | 1     |
| B4  | No rate limiting                     | High     | CC6.1, CC6.3    | 3     |
| B5  | Default token expiry too long        | Medium   | CC6.3           | 2     |
| B6  | Missing `aud`/`iss` JWT claims       | Medium   | CC6.1           | 2     |
| B7  | HMAC-SHA256 only                     | Low      | CC6.1           | 4     |
| C8  | No TLS / no HSTS header              | High     | CC6.1, CC6.7    | 2     |
| D9  | CORS origin reflection, no allowlist | High     | CC6.1           | 2     |
| E10 | No Content-Type enforcement          | Medium   | CC6.1           | 1     |
| F11 | No graceful shutdown / drain         | Medium   | A1.2            | 3     |
| F12 | Handler panics silently swallowed    | Medium   | A1.2            | 3     |
| G13 | No dependency scanning in CI         | Medium   | CC6.1, CC8.1    | 4     |
| G14 | Loose dependency version pins        | Low      | CC8.1           | 4     |

---

## Proposed phases

**Phase 1 -- Observability & input validation (A1, A2, A3, E10)**
Low-risk, additive changes. Improves auditability immediately.

**Phase 2 -- Auth hardening & transport (B5, B6, C8, D9)**
Config changes and header additions. Touches auth and server modules.

**Phase 3 -- Reliability & rate limiting (B4, F11, F12)**
Structural changes to the accept loop and handler execution model.

**Phase 4 -- Ecosystem & future-proofing (B7, G13, G14)**
Asymmetric JWT support, CI pipeline, dependency policy.
