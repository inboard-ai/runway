<div align="center">

# runway

Modular HTTP server framework for Rust

</div>

## Quick Start

```rust
use runway::{Config, Module, Router};

struct MyModule;

impl Module for MyModule {
    fn name(&self) -> &'static str { "my-module" }

    fn routes(&self, router: &mut Router) {
        router.get("/api/v1/hello", |_ctx| async {
            runway::response::ok(&serde_json::json!({ "message": "Hello, world!" }))
        });
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = runway::Loader::new("MYAPP")
        // JWT secret must be >= 32 bytes for HS256
        .load(None, None, None, None, Some("change-me-to-a-real-secret-at-least-32-bytes!"))?;

    let mut router = Router::new();
    MyModule.routes(&mut router);

    runway::server::run(config, None, router.into_handle()).await?;
    Ok(())
}
```

## Configuration

Configuration is loaded in layers (each overrides the previous):

1. Default values
2. Config file (TOML)
3. Environment variables
4. CLI arguments

**Environment variables:**
```bash
export MYAPP_HOST=0.0.0.0
export MYAPP_PORT=8080
export MYAPP_JWT_SECRET=your-secret-key-at-least-32-bytes
export MYAPP_JWT_ISSUER=my-service
export MYAPP_JWT_AUDIENCE=my-app
export DATABASE_URL=sqlite://data.db
```

**Config file:**
```toml
[server]
host = "0.0.0.0"
port = 8080
hsts = false
cors_origins = ["https://myapp.com"]
drain_timeout_secs = 30

[server.rate_limit]
max_requests = 100
window_secs = 60

[database]
url = "data.db"

[auth]
token_expiry_days = 1
token_expiry_hours = 1
jwt_issuer = "my-service"
jwt_audience = "my-app"
jwt_algorithm = "HS256"
```

## Module Trait

Modules encapsulate related routes and functionality:

```rust
use runway::{DbHandle, Module, Router};

pub struct UsersModule {
    db: DbHandle,
}

impl Module for UsersModule {
    fn name(&self) -> &'static str { "users" }

    fn routes(&self, router: &mut Router) {
        let db = self.db.clone();
        router.get("/api/v1/users", move |ctx| {
            let db = db.clone();
            async move { list_users(ctx, db).await }
        });
    }
}
```

## Handler Context

Handlers receive a `Context` with request data and utilities:

```rust
async fn get_user(ctx: Context) -> runway::Result<HttpResponse> {
    let user_id = ctx.require_user_id()?;  // Extract from JWT
    let id = ctx.require_param("id")?;      // Route parameter
    let db = ctx.require_db()?;             // Database (if configured)

    let req_id = ctx.request_id;            // Unique request UUID
    let addr = ctx.remote_addr;             // Direct socket address
    let ip = ctx.client_ip();               // Client IP (respects X-Forwarded-For)

    // ... handle request
    response::ok(&user)
}
```

## Response Helpers

```rust
use runway::response;

response::ok(&data)?;                           // 200 OK (JSON)
response::created(&data)?;                      // 201 Created (JSON)
response::no_content();                         // 204 No Content
response::bad_request("Invalid input");         // 400 Bad Request
response::unauthorized();                       // 401 Unauthorized
response::not_found("User not found");          // 404 Not Found
response::binary(bytes, "application/pdf", Some("file.pdf"));  // Binary download
response::redirect("/new-location");            // 307 Redirect
```

## Security & Transport

Runway is designed to sit behind a reverse proxy (e.g. nginx, Caddy) and does not terminate TLS itself.

- **HSTS** — Opt in with `hsts = true` in `[server]`. Adds `Strict-Transport-Security` header to every response.
- **CORS** — Controlled by `cors_origins` in `[server]`. An empty list (default) disables CORS headers entirely. `["*"]` allows any origin. Specific origins are matched exactly.
- **Rate limiting** — Opt in by adding a `[server.rate_limit]` section. Per-client limits keyed by IP address.
- **Request IDs** — Every response includes an `X-Request-Id` header. If the incoming request already carries one, it is propagated; otherwise a new UUID is generated. Available as `ctx.request_id` in handlers.
- **Graceful shutdown** — On `SIGINT`/`SIGTERM` the server stops accepting new connections and drains in-flight requests for up to `drain_timeout_secs` (default 30).

## Architecture

```
┌──────────────────────────────────────────────────┐
│                     runway                       │
│  ┌───────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │  config   │ │    db    │ │       auth      │  │
│  │ (TOML+    │ │ (libsql/ │ │ (JWT validate)  │  │
│  │  env+CLI) │ │  Turso)  │ │                 │  │
│  └───────────┘ └──────────┘ └─────────────────┘  │
│  ┌───────────┐ ┌──────────┐ ┌─────────────────┐  │
│  │  router   │ │  server  │ │    response     │  │
│  │ (matchit) │ │  (hyper) │ │    (helpers)    │  │
│  └───────────┘ └──────────┘ └─────────────────┘  │
│  ┌──────────────────────┐                        │
│  │     rate_limit       │                        │
│  │ (per-client sliding) │                        │
│  └──────────────────────┘                        │
└────────────────────────┬─────────────────────────┘
                         │
           ┌─────────────┼─────────────┐
           ▼             ▼             ▼
     ┌───────────┐ ┌───────────┐ ┌───────────┐
     │  module:  │ │  module:  │ │  module:  │
     │   users   │ │   auth    │ │   posts   │
     └───────────┘ └───────────┘ └───────────┘
```

## CI

`.github/workflows/ci.yml` runs `cargo fmt --check`, `clippy`, `cargo test`, `cargo audit`, and `cargo deny check`.

## License

MIT
