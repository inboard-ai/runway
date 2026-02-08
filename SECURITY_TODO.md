# Security TODO

Findings from manual audit, verified by `cargo test --test security_audit`.
Each item references the test that proves the issue. When a fix lands, the
corresponding test will fail — flip its assertion to lock in the fix.

---

## Critical

### 1. Enforce a request body size limit
`server.rs:33-37` buffers the full request body via `BodyExt::collect(body)`
with no cap. A single client can OOM the process.

- Wrap the body in `http_body_util::Limited` with a configurable max (e.g. 1 MiB default).
- Reject oversized requests with 413 Payload Too Large before reading.
- **Test:** `security::server::no_body_size_limit`

### 2. Add connection limits and backpressure
`server.rs:91-106` spawns a task per connection with no ceiling. Dropped
`JoinHandle`s silently swallow panics.

- Gate `accept()` behind a `tokio::sync::Semaphore` with a configurable max.
- Track spawned tasks with `JoinSet` to catch panics.
- Consider per-IP connection counting.
- **Test:** `security::server::no_connection_limits`

### 3. Configure request and connection timeouts
`server.rs:102` uses a bare `http1::Builder::new()` with zero timeout config.
Vulnerable to slowloris and slow-POST.

- Set `header_read_timeout` on the HTTP/1 builder.
- Set a keep-alive idle timeout.
- Wrap handler execution in `tokio::time::timeout`.
- **Test:** `security::server::no_timeouts`

---

## High

### 4. Stop leaking internal error details to clients
`error.rs:85-89` — `into_response` forwards the raw `Display` output of
`Database`, `Io`, `Json`, and `Internal` errors to the HTTP body.

- For 500-class errors, return a generic `"Internal server error"` message.
- Log the full error server-side at `error!` level.
- **Tests:** `security::error_disclosure::internal_error_leaks_sql`,
  `security::error_disclosure::io_error_leaks_paths`

### 5. Enforce a minimum JWT secret length
`config.rs:193` only rejects the empty string. The JWT layer itself accepts
even an empty secret if `AuthConfig` is constructed directly.

- Reject secrets shorter than 32 bytes in `ConfigLoader::load`.
- Add a `validate()` method on `AuthConfig` that `create_token` and
  `verify_token` call, so the guardrail can't be bypassed.
- **Tests:** `security::auth::accepts_dangerously_short_secret`,
  `security::auth::empty_secret_accepted_at_jwt_layer`

### 6. Redact the JWT secret from `Debug` output
`config.rs:75` — `Auth` derives `Debug`, exposing `jwt_secret` in any
log line, panic message, or error format that touches it.

- Replace the `Debug` derive on `Auth` with a manual impl that prints
  `jwt_secret: "[REDACTED]"`.
- Alternatively, wrap the secret in a newtype that implements `Debug`
  as redacted.
- **Test:** `security::config::debug_output_leaks_jwt_secret`

---

## Medium

### 7. Sanitize the `Content-Disposition` filename
`response.rs:89-91` interpolates the filename without escaping `"`.

- Escape or strip `"`, `\`, and control characters from the filename.
- Consider using RFC 6266 `filename*=UTF-8''...` encoding.
- **Test:** `security::response::content_disposition_injection_via_filename`

### 8. Validate redirect URLs / don't panic on bad input
`response.rs:99-104` — `redirect()` panics on CRLF-containing input
(via `.unwrap()` on the response builder) and accepts arbitrary URLs
(open-redirect).

- Return `Result<HttpResponse>` instead of panicking.
- Optionally restrict to relative paths or a configured allow-list.
- **Tests:** `security::response::redirect_panics_on_crlf_injection`,
  `security::response::redirect_allows_arbitrary_urls`

### 9. Add standard security headers
No response sets `X-Content-Type-Options`, `X-Frame-Options`,
`Cache-Control`, or `Content-Security-Policy`.

- Add a middleware / wrapper that sets baseline security headers on
  every response.
- **Test:** `security::response::missing_security_headers`

### 10. Default host to `127.0.0.1` instead of `0.0.0.0`
`config.rs:48` binds to all interfaces by default.

- Change `default_host()` to return `"127.0.0.1"`.
- Document that `0.0.0.0` must be set explicitly for public-facing
  deployments.

### 11. Make Bearer token parsing case-insensitive
`auth.rs:94` uses `strip_prefix("Bearer ")` which rejects `bearer`
(lowercase). RFC 7235 requires case-insensitive scheme comparison.

- Normalize the scheme to lowercase before prefix-stripping, or use a
  case-insensitive comparison.
- **Test:** `security::auth::bearer_prefix_is_case_sensitive`

---

## Low / Operational

### 12. Add graceful shutdown
The server loop has no signal handling and no drain period. SIGTERM
kills in-flight requests immediately.

- Listen for `SIGTERM`/`SIGINT` via `tokio::signal`.
- Stop accepting new connections, drain existing ones with a timeout.
- **Test:** `security::server::no_graceful_shutdown`

### 13. Remove or wire up the `http2` hyper feature
`Cargo.toml` enables `http2` but only `http1::Builder` is used.

- Either remove `"http2"` from features, or switch to
  `hyper_util::server::conn::auto::Builder` to serve both.
- **Test:** `security::server::http2_feature_enabled_but_unused`

### 14. Add request-level logging
`remote_addr` is captured in the accept loop but never logged for
successful requests. No audit trail for who hit what endpoint.

- Log method, path, status, and latency at `info!` level for every
  request.
- Log `remote_addr` at `debug!` level.

### 15. Add token revocation support
Tokens are valid until expiry (default: 30 days). Key rotation is the
only revocation mechanism.

- Implement short-lived access tokens + refresh token pattern, or
- Add a server-side revocation list checked on every `verify_token` call.

### 16. Add CORS support
No `Access-Control-*` headers are set anywhere. Browser clients are
blocked by same-origin policy without an external proxy.

- Add configurable CORS middleware with `Access-Control-Allow-Origin`,
  `Allow-Methods`, `Allow-Headers`, and preflight (`OPTIONS`) handling.
- **Test:** `security::server::no_cors_headers`

### 17. Stop cloning the full `Config` (including secret) into every request
`server.rs:52` clones `state.config` into every `Context`. This
scatters the JWT secret across memory proportional to concurrency.

- Store `Config` in an `Arc` in `State` and hand out `Arc<Config>`
  references to handlers instead of cloning.
- **Test:** `security::config::config_cloned_into_every_request_carries_secret`

### 18. Pin `edition = "2024"` or document the minimum Rust version
`Cargo.toml` uses `edition = "2024"` which requires nightly or a very
recent stable toolchain. This limits adoption and CI reproducibility.

- Either set `rust-version = "1.85"` (or whatever the MSRV is) in
  `Cargo.toml`, or document the requirement in the README.
