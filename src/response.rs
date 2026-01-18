//! HTTP response builders.
//!
//! Provides convenient functions for building JSON responses.

use bytes::Bytes;
use http_body_util::Full;
use hyper::{Response, StatusCode};
use serde::Serialize;

/// Response body type used throughout runway.
pub type Body = Full<Bytes>;

/// Full response type used throughout runway.
pub type HttpResponse = Response<Body>;

/// Build a JSON response with the given status code and body.
pub fn json<T: Serialize>(status: StatusCode, body: &T) -> crate::Result<HttpResponse> {
    let json = serde_json::to_string(body)?;
    Ok(Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap())
}

/// Build a 200 OK JSON response.
pub fn ok<T: Serialize>(body: &T) -> crate::Result<HttpResponse> {
    json(StatusCode::OK, body)
}

/// Build a 201 Created JSON response.
pub fn created<T: Serialize>(body: &T) -> crate::Result<HttpResponse> {
    json(StatusCode::CREATED, body)
}

/// Build a 204 No Content response.
pub fn no_content() -> HttpResponse {
    Response::builder()
        .status(StatusCode::NO_CONTENT)
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Build a 404 Not Found JSON response.
pub fn not_found(message: &str) -> HttpResponse {
    let body = serde_json::json!({ "error": message });
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Build a 400 Bad Request JSON response.
pub fn bad_request(message: &str) -> HttpResponse {
    let body = serde_json::json!({ "error": message });
    Response::builder()
        .status(StatusCode::BAD_REQUEST)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Build a 401 Unauthorized JSON response.
pub fn unauthorized() -> HttpResponse {
    let body = serde_json::json!({ "error": "Unauthorized" });
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}

/// Build a 500 Internal Server Error JSON response.
pub fn internal_error(message: &str) -> HttpResponse {
    let body = serde_json::json!({ "error": message });
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap()
}
