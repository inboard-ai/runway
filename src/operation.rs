//! OpenAPI operation metadata collected from registered procedures.

/// Metadata for a single API operation, used to generate the OpenAPI spec.
pub struct Meta {
    pub path: String,
    pub method: String,
    pub summary: String,
    pub tag: String,
    pub status: u16,
    pub input_schema: Option<schemars::Schema>,
    pub output_schema: schemars::Schema,
}
