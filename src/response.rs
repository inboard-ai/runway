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

/// Build a binary response with optional download filename.
pub fn binary(data: Bytes, content_type: &str, filename: Option<&str>) -> HttpResponse {
    let mut builder = Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", content_type);
    if let Some(name) = filename {
        let sanitized = sanitize_filename(name);
        if !sanitized.is_empty() {
            builder = builder.header(
                "Content-Disposition",
                format!("attachment; filename=\"{sanitized}\""),
            );
        }
    }
    builder.body(Full::new(data)).unwrap()
}

/// Sanitize a filename for safe use in Content-Disposition headers.
///
/// Inspired by the `sanitize-filename` npm/crate family by Parshap/Kardeiz
/// (MIT License — <https://github.com/parshap/node-sanitize-filename>).
/// This is a regex-free reimplementation with an additional step that
/// truncates at header-syntax delimiters to prevent parameter injection.
///
/// Steps:
///   1. Extract basename (strip directory components)
///   2. Remove illegal filesystem chars: `/ ? < > \ : * | "`
///   3. Remove ASCII control chars (0x00–0x1F) and C1 controls (0x80–0x9F)
///   4. Truncate at header-syntax delimiters that enable parameter injection: `" ; =`
///   5. Replace Windows reserved device names (CON, PRN, AUX, NUL, COM0–9, LPT0–9)
///   6. Strip trailing dots and spaces
///   7. Truncate to 255 bytes on a UTF-8 char boundary
///
/// MIT License (original):
///
/// Copyright (c) Parshap
/// Permission is hereby granted, free of charge, to any person obtaining a
/// copy of this software and associated documentation files (the "Software"),
/// to deal in the Software without restriction, including without limitation
/// the rights to use, copy, modify, merge, publish, distribute, sublicense,
/// and/or sell copies of the Software, and to permit persons to whom the
/// Software is furnished to do so, subject to the following conditions:
///
/// The above copyright notice and this permission notice shall be included in
/// all copies or substantial portions of the Software.
///
/// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
/// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
/// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
/// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
/// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
/// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
/// DEALINGS IN THE SOFTWARE.
fn sanitize_filename(name: &str) -> String {
    // 1. Strip path separators — keep only the final component.
    let name = name.rsplit(['/', '\\']).next().unwrap_or(name);

    // 2–4. Remove illegal, control, and header-syntax characters.
    //
    // Characters that are part of HTTP header parameter syntax (`"`, `;`, `=`)
    // are treated as truncation points rather than stripped, because content
    // after them is attacker-controlled injection payload, not part of the
    // original filename.
    let mut out = String::with_capacity(name.len());
    for c in name.chars() {
        match c {
            // Header-syntax delimiters: truncate here — anything after is
            // injection payload, not filename.
            '"' | ';' | '=' => break,
            // Illegal filesystem / URI characters: strip.
            '/' | '?' | '<' | '>' | '\\' | ':' | '*' | '|' => {}
            // Control characters (C0 + C1): strip.
            c if (c as u32) <= 0x1F || (0x80..=0x9F).contains(&(c as u32)) => {}
            _ => out.push(c),
        }
    }

    // 5. Replace Windows reserved device names.
    {
        let stem = match out.find('.') {
            Some(i) => &out[..i],
            None => &out,
        };
        let upper: String = stem.chars().map(|c| c.to_ascii_uppercase()).collect();
        let reserved = matches!(
            upper.as_str(),
            "CON"
                | "PRN"
                | "AUX"
                | "NUL"
                | "COM0"
                | "COM1"
                | "COM2"
                | "COM3"
                | "COM4"
                | "COM5"
                | "COM6"
                | "COM7"
                | "COM8"
                | "COM9"
                | "LPT0"
                | "LPT1"
                | "LPT2"
                | "LPT3"
                | "LPT4"
                | "LPT5"
                | "LPT6"
                | "LPT7"
                | "LPT8"
                | "LPT9"
        );
        if reserved {
            out.insert(stem.len(), '_');
        }
    }

    // 6. Strip trailing dots and spaces.
    let trimmed_len = out.trim_end_matches(['.', ' ']).len();
    out.truncate(trimmed_len);

    // 7. Truncate to 255 bytes at a UTF-8 char boundary.
    if out.len() > 255 {
        let mut end = 255;
        while !out.is_char_boundary(end) {
            end -= 1;
        }
        out.truncate(end);
    }

    out
}

/// Build a 307 Temporary Redirect response.
pub fn redirect(location: &str) -> crate::Result<HttpResponse> {
    use hyper::header::HeaderValue;
    HeaderValue::from_str(location)
        .map_err(|_| crate::Error::BadRequest(format!("Invalid redirect location: {location}")))?;
    Ok(Response::builder()
        .status(StatusCode::TEMPORARY_REDIRECT)
        .header("Location", location)
        .body(Full::new(Bytes::new()))
        .unwrap())
}
