<div align="center">

# runway

[![Crates.io](https://img.shields.io/crates/v/runway.svg)](https://crates.io/crates/runway)
[![Documentation](https://docs.rs/runway/badge.svg)](https://docs.rs/runway)
[![License](https://img.shields.io/crates/l/runway.svg)](https://github.com/inboard-ai/runway/blob/main/LICENSE)

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
    let config = runway::ConfigLoader::new("MYAPP")
        .load(None, None, None, None, Some("secret"))?;

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
export MYAPP_JWT_SECRET=your-secret-key
export DATABASE_URL=sqlite://data.db
```

**Config file:**
```toml
[server]
host = "0.0.0.0"
port = 8080

[database]
url = "data.db"

[auth]
token_expiry_days = 30
```

## Module Trait

Modules encapsulate related routes and functionality:

```rust
use runway::{Module, Router};

pub struct UsersModule {
    db: Arc<libsql::Database>,
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

## Architecture

```
┌─────────────────────────────────────────┐
│                runway                   │
│  ┌─────────┐ ┌─────────┐ ┌───────────┐  │
│  │ config  │ │   db    │ │   auth    │  │
│  │ (TOML+  │ │(libsql/ │ │ (JWT      │  │
│  │ env+CLI)│ │ Turso)  │ │ validate) │  │
│  └─────────┘ └─────────┘ └───────────┘  │
│  ┌─────────┐ ┌─────────┐ ┌───────────┐  │
│  │ router  │ │ server  │ │ response  │  │
│  │(matchit)│ │ (hyper) │ │ (helpers) │  │
│  └─────────┘ └─────────┘ └───────────┘  │
└───────────────────┬─────────────────────┘
                    │
      ┌─────────────┼─────────────┐
      ▼             ▼             ▼
┌───────────┐ ┌───────────┐ ┌───────────┐
│  module:  │ │  module:  │ │  module:  │
│   users   │ │   auth    │ │   posts   │
└───────────┘ └───────────┘ └───────────┘
```

## License

MIT
