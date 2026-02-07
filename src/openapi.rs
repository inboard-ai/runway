//! OpenAPI 3.1 spec generation from registered procedure metadata.

use serde_json::{Map, Value, json};

use crate::operation;

/// Top-level API info for the OpenAPI spec.
pub struct Info {
    pub title: &'static str,
    pub version: &'static str,
}

/// Build an OpenAPI 3.1 JSON document from collected operation metadata.
pub fn generate(info: &Info, operations: &[operation::Meta]) -> Value {
    let mut paths: Map<String, Value> = Map::new();
    let mut schemas: Map<String, Value> = Map::new();

    for op in operations {
        let mut operation_obj: Map<String, Value> = Map::new();

        // Summary
        if !op.summary.is_empty() {
            operation_obj.insert("summary".into(), Value::String(op.summary.clone()));
        }

        // Tags
        if !op.tag.is_empty() {
            operation_obj.insert("tags".into(), json!([op.tag]));
        }

        // Request body
        if let Some(input_schema) = &op.input_schema {
            let input_json = serde_json::to_value(input_schema).unwrap_or(json!({}));
            let (content_schema, input_defs) = extract_defs(input_json);

            // Merge any $defs into top-level schemas
            for (name, schema) in input_defs {
                schemas.entry(name).or_insert(schema);
            }

            operation_obj.insert(
                "requestBody".into(),
                json!({
                    "required": true,
                    "content": {
                        "application/json": {
                            "schema": rewrite_refs(content_schema)
                        }
                    }
                }),
            );
        }

        // Response
        let output_json = serde_json::to_value(&op.output_schema).unwrap_or(json!({}));
        let (response_schema, output_defs) = extract_defs(output_json);

        for (name, schema) in output_defs {
            schemas.entry(name).or_insert(schema);
        }

        let status_str = op.status.to_string();
        let mut responses: Map<String, Value> = Map::new();
        responses.insert(
            status_str,
            json!({
                "description": "Successful response",
                "content": {
                    "application/json": {
                        "schema": rewrite_refs(response_schema)
                    }
                }
            }),
        );

        // Standard error responses
        responses.insert(
            "400".into(),
            json!({ "description": "Bad request", "content": { "application/json": { "schema": { "type": "object", "properties": { "error": { "type": "string" } } } } } }),
        );
        responses.insert(
            "401".into(),
            json!({ "description": "Unauthorized", "content": { "application/json": { "schema": { "type": "object", "properties": { "error": { "type": "string" } } } } } }),
        );
        responses.insert(
            "500".into(),
            json!({ "description": "Internal server error", "content": { "application/json": { "schema": { "type": "object", "properties": { "error": { "type": "string" } } } } } }),
        );

        operation_obj.insert("responses".into(), Value::Object(responses));

        // Insert into paths grouped by path
        let path_item = paths
            .entry(op.path.clone())
            .or_insert_with(|| Value::Object(Map::new()));
        if let Value::Object(map) = path_item {
            map.insert(op.method.clone(), Value::Object(operation_obj));
        }
    }

    let mut spec = json!({
        "openapi": "3.1.0",
        "info": {
            "title": info.title,
            "version": info.version,
        },
        "paths": paths,
    });

    if !schemas.is_empty() {
        spec.as_object_mut()
            .unwrap()
            .insert("components".into(), json!({ "schemas": schemas }));
    }

    spec
}

/// Extract `$defs` from a schemars-generated schema and return
/// (root schema without $defs, Vec of (name, schema) pairs).
fn extract_defs(mut schema: Value) -> (Value, Vec<(String, Value)>) {
    let mut defs = Vec::new();

    if let Some(obj) = schema.as_object_mut()
        && let Some(Value::Object(defs_map)) = obj.remove("$defs")
    {
        for (name, def_schema) in defs_map {
            defs.push((name, rewrite_refs(def_schema)));
        }
    }

    (rewrite_refs(schema), defs)
}

/// Rewrite `$ref` values from schemars' `#/$defs/Foo` format to OpenAPI's
/// `#/components/schemas/Foo` format.
fn rewrite_refs(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let new_map: Map<String, Value> = map
                .into_iter()
                .map(|(k, v)| {
                    if k == "$ref" {
                        if let Value::String(ref s) = v
                            && let Some(name) = s.strip_prefix("#/$defs/")
                        {
                            return (k, Value::String(format!("#/components/schemas/{name}")));
                        }
                        (k, v)
                    } else {
                        (k, rewrite_refs(v))
                    }
                })
                .collect();
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(rewrite_refs).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::operation;

    #[test]
    fn test_generate_empty_spec() {
        let info = Info {
            title: "Test API",
            version: "1.0.0",
        };
        let spec = generate(&info, &[]);

        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["info"]["title"], "Test API");
        assert_eq!(spec["info"]["version"], "1.0.0");
        assert_eq!(spec["paths"], json!({}));
        assert!(spec.get("components").is_none());
    }

    #[test]
    fn test_generate_with_operations() {
        use schemars::JsonSchema;
        use serde::{Deserialize, Serialize};

        #[derive(Serialize, Deserialize, JsonSchema)]
        struct CreateUserInput {
            name: String,
            email: String,
        }

        #[derive(Serialize, JsonSchema)]
        struct UserResponse {
            id: String,
            name: String,
        }

        let input_schema = schemars::schema_for!(CreateUserInput);
        let output_schema = schemars::schema_for!(UserResponse);
        let list_output_schema = schemars::schema_for!(Vec<UserResponse>);

        let operations = vec![
            operation::Meta {
                path: "/api/users".to_string(),
                method: "get".to_string(),
                summary: "List users".to_string(),
                tag: "users".to_string(),
                status: 200,
                input_schema: None,
                output_schema: list_output_schema,
            },
            operation::Meta {
                path: "/api/users".to_string(),
                method: "post".to_string(),
                summary: "Create a user".to_string(),
                tag: "users".to_string(),
                status: 201,
                input_schema: Some(input_schema),
                output_schema,
            },
        ];

        let info = Info {
            title: "My API",
            version: "2.0.0",
        };
        let spec = generate(&info, &operations);

        // Basic structure
        assert_eq!(spec["openapi"], "3.1.0");
        assert_eq!(spec["info"]["title"], "My API");

        // Paths
        let paths = &spec["paths"];
        assert!(paths.get("/api/users").is_some());

        let get_op = &paths["/api/users"]["get"];
        assert_eq!(get_op["summary"], "List users");
        assert_eq!(get_op["tags"], json!(["users"]));
        assert!(get_op.get("requestBody").is_none());
        assert!(get_op["responses"].get("200").is_some());

        let post_op = &paths["/api/users"]["post"];
        assert_eq!(post_op["summary"], "Create a user");
        assert!(post_op.get("requestBody").is_some());
        assert_eq!(post_op["requestBody"]["required"], true);
        assert!(post_op["responses"].get("201").is_some());

        // Error responses present
        assert!(post_op["responses"].get("400").is_some());
        assert!(post_op["responses"].get("401").is_some());
        assert!(post_op["responses"].get("500").is_some());
    }

    #[test]
    fn test_rewrite_refs() {
        let input = json!({
            "$ref": "#/$defs/Foo",
            "nested": {
                "$ref": "#/$defs/Bar"
            }
        });
        let result = rewrite_refs(input);
        assert_eq!(result["$ref"], "#/components/schemas/Foo");
        assert_eq!(result["nested"]["$ref"], "#/components/schemas/Bar");
    }

    #[test]
    fn test_procedure_registration() {
        use crate::procedure::{Empty, Meta as ProcMeta, Procedure};
        use crate::router::{Context, Router};
        use schemars::JsonSchema;
        use serde::Serialize;

        #[derive(Serialize, JsonSchema)]
        struct HealthResponse {
            status: String,
        }

        struct HealthCheck;

        impl Procedure for HealthCheck {
            fn meta() -> ProcMeta {
                ProcMeta::get("/health")
                    .summary("Health check")
                    .tag("system")
            }

            type Input = Empty;
            type Output = HealthResponse;

            async fn handle(_ctx: Context, _input: Empty) -> crate::Result<HealthResponse> {
                Ok(HealthResponse {
                    status: "ok".to_string(),
                })
            }
        }

        let mut router = Router::new();
        router.procedure::<HealthCheck>();

        assert_eq!(router.operations.len(), 1);
        assert_eq!(router.operations[0].path, "/health");
        assert_eq!(router.operations[0].method, "get");
        assert_eq!(router.operations[0].summary, "Health check");
        assert_eq!(router.operations[0].tag, "system");
        assert!(router.operations[0].input_schema.is_none());
    }
}
