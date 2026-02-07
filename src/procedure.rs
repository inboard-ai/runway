//! Procedure abstraction for colocated route definitions.
//!
//! A `Procedure` combines input schema, output schema, metadata (path, method,
//! summary, tags), and an async handler into a single type. Registering a
//! procedure on the router automatically wires up both the HTTP handler and
//! OpenAPI metadata.

use std::future::Future;

use hyper::Method;
use schemars::JsonSchema;
use serde::Serialize;
use serde::de::DeserializeOwned;

use crate::router::Context;

/// Route metadata builder.
pub struct Meta {
    pub path: &'static str,
    pub method: Method,
    pub summary: &'static str,
    pub tag: &'static str,
    pub status: u16,
}

impl Meta {
    pub fn get(path: &'static str) -> Self {
        Self {
            path,
            method: Method::GET,
            summary: "",
            tag: "",
            status: 200,
        }
    }
    pub fn post(path: &'static str) -> Self {
        Self {
            path,
            method: Method::POST,
            summary: "",
            tag: "",
            status: 200,
        }
    }
    pub fn put(path: &'static str) -> Self {
        Self {
            path,
            method: Method::PUT,
            summary: "",
            tag: "",
            status: 200,
        }
    }
    pub fn delete(path: &'static str) -> Self {
        Self {
            path,
            method: Method::DELETE,
            summary: "",
            tag: "",
            status: 200,
        }
    }
    pub fn patch(path: &'static str) -> Self {
        Self {
            path,
            method: Method::PATCH,
            summary: "",
            tag: "",
            status: 200,
        }
    }

    pub fn summary(mut self, s: &'static str) -> Self {
        self.summary = s;
        self
    }
    pub fn tag(mut self, t: &'static str) -> Self {
        self.tag = t;
        self
    }
    pub fn status(mut self, s: u16) -> Self {
        self.status = s;
        self
    }
}

/// Marker type for procedures that take no request body.
///
/// Used as the default `Input` type. Deserializes from any JSON value (or
/// empty body) and produces a null JSON Schema so the OpenAPI generator
/// omits the `requestBody`.
#[derive(Debug, Clone, Copy, Default)]
pub struct Empty;

impl<'de> serde::Deserialize<'de> for Empty {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        // Accept and discard any value
        let _ = serde::de::IgnoredAny::deserialize(deserializer)?;
        Ok(Empty)
    }
}

impl JsonSchema for Empty {
    fn schema_name() -> std::borrow::Cow<'static, str> {
        "Empty".into()
    }

    fn json_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::Schema::default()
    }
}

/// A procedure is a self-contained endpoint definition: metadata + input +
/// output + handler.
pub trait Procedure: Send + Sync + 'static {
    /// Route metadata (path, method, summary, tag, status code).
    fn meta() -> Meta;

    /// Request body type. Use `Empty` for procedures with no request body.
    type Input: DeserializeOwned + JsonSchema + Send;

    /// Response body type.
    type Output: Serialize + JsonSchema;

    /// The async handler.
    fn handle(
        ctx: Context,
        input: Self::Input,
    ) -> impl Future<Output = crate::Result<Self::Output>> + Send;
}
