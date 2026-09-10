//! Runtime assertions for the JSON a sink value carries.
//!
//! Requires both `testing` and `redaction`. These helpers never enable raw Debug.
//! Pair shape assertions with independently authored expected JSON and exact
//! public sentinel values. A matching shape alone does not prove correct
//! masking, confidentiality, or a complete logging contract.

use serde_json::Value;

use crate::RedactedValue;

/// Asserts that a value's JSON has the same shape as `plain`, except at opaque nodes.
///
/// Objects must have exactly the same keys, regardless of key order. Arrays
/// must have equal lengths and matching shapes at corresponding indices.
/// Scalars must have matching JSON kinds; all numbers share one kind, and
/// scalar values are ignored. An opaque node may change kind or structure.
/// Its parent still requires that node to exist on both sides.
///
/// `opaque_paths` uses strict JSON Pointer syntax: `""` denotes the root;
/// otherwise paths start with `/`, with only `~0` (tilde) and `~1` (slash)
/// escapes. `/` addresses an empty object key. Wildcards and URI fragments
/// have no special meaning. Array tokens must be `0` or nonzero decimal
/// indices without signs or leading zeroes, representable as `usize`.
/// Object tokens are exact keys, including numeric strings. Duplicate paths
/// are harmless. Every path is parsed before comparison, even beneath an
/// opaque ancestor. Array tokens are checked whenever either value reaches
/// an array, including an empty array.
///
/// Valid unmatched paths are inactive beneath absent keys, scalar parents
/// (including null), or out-of-range indices. They cannot waive a mismatch
/// at an earlier nonopaque node. Tokens beyond an absent or scalar parent
/// cannot be checked as array indices. Test populated samples as well as
/// absent optional values and empty collections to exercise intended paths.
///
/// To allow set collapse or custom serialization changes, mark the containing
/// node opaque and check its exact expected value separately.
///
/// The comparison reads `value.json()`, so it follows the documented fallback:
/// a text-only producer is compared as `{"message": text}` rather than
/// refused. Assert a text producer's `text()` directly instead.
///
/// # Panics
///
/// Panics for malformed paths, invalid array tokens, or a shape mismatch.
/// Diagnostics identify the path without printing values.
///
/// ```
/// # #![allow(hidden_glob_reexports)]
/// # pub use redactable::*;
/// use redactable::{Secret, Sensitive, ToRedacted, testing::assert_json_shape};
/// use serde_json::json;
///
/// #[derive(Clone, serde::Serialize, Sensitive)]
/// struct Decision {
///     #[sensitive(Secret)]
///     owner: String,
///     #[not_sensitive]
///     approved: bool,
/// }
/// # fn main() {
/// let decision = Decision { owner: "Ada".into(), approved: true };
/// let plain = serde_json::to_value(&decision).unwrap();
/// let expected = json!({"owner": "[REDACTED]", "approved": true});
/// let value = decision.to_redacted();
/// assert_json_shape(&plain, &value, &[]);
/// assert_eq!(value.json(), expected);
/// # }
/// ```
#[track_caller]
pub fn assert_json_shape(plain: &Value, value: &RedactedValue, opaque_paths: &[&str]) {
    let paths: Vec<_> = opaque_paths
        .iter()
        .map(|path| parse_pointer(path))
        .collect();
    let selected = value.json();
    for path in &paths {
        validate_indices(plain, path);
        validate_indices(&selected, path);
    }
    compare(plain, &selected, &paths, &mut Vec::new());
}

fn parse_pointer(path: &str) -> Vec<String> {
    if path.is_empty() {
        return Vec::new();
    }
    assert!(
        path.starts_with('/'),
        "invalid opaque JSON pointer: {path:?}"
    );
    path[1..]
        .split('/')
        .map(|token| {
            let mut decoded = String::new();
            let mut chars = token.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    match chars.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        _ => panic!("invalid escape in opaque JSON pointer: {path:?}"),
                    }
                } else {
                    decoded.push(ch);
                }
            }
            decoded
        })
        .collect()
}

fn array_index(token: &str) -> usize {
    assert!(
        token == "0"
            || (token.starts_with(|ch: char| ch.is_ascii_digit() && ch != '0')
                && token.bytes().all(|ch| ch.is_ascii_digit())),
        "invalid array index in opaque JSON pointer: {token:?}"
    );
    token
        .parse()
        .expect("opaque JSON pointer array index exceeds usize")
}

fn validate_indices(mut value: &Value, path: &[String]) {
    for token in path {
        let next = match value {
            Value::Array(items) => items.get(array_index(token)),
            Value::Object(fields) => fields.get(token),
            _ => return,
        };
        let Some(next) = next else { return };
        value = next;
    }
}

fn compare(plain: &Value, selected: &Value, opaque: &[Vec<String>], path: &mut Vec<String>) {
    if opaque.contains(path) {
        return;
    }
    match (plain, selected) {
        (Value::Object(left), Value::Object(right)) => {
            assert!(
                left.len() == right.len() && left.keys().all(|key| right.contains_key(key)),
                "JSON shape mismatch at {}: object keys differ",
                pointer(path)
            );
            for (key, value) in left {
                path.push(key.clone());
                compare(value, &right[key], opaque, path);
                path.pop();
            }
        }
        (Value::Array(left), Value::Array(right)) => {
            assert_eq!(
                left.len(),
                right.len(),
                "JSON shape mismatch at {}: array lengths differ",
                pointer(path)
            );
            for (index, (left, right)) in left.iter().zip(right).enumerate() {
                path.push(index.to_string());
                compare(left, right, opaque, path);
                path.pop();
            }
        }
        (Value::Null, Value::Null)
        | (Value::Bool(_), Value::Bool(_))
        | (Value::Number(_), Value::Number(_))
        | (Value::String(_), Value::String(_)) => {}
        _ => panic!(
            "JSON shape mismatch at {}: JSON kinds differ",
            pointer(path)
        ),
    }
}

fn pointer(path: &[String]) -> String {
    if path.is_empty() {
        return "root".to_owned();
    }
    let mut pointer = String::new();
    for token in path {
        pointer.push('/');
        pointer.push_str(&token.replace('~', "~0").replace('/', "~1"));
    }
    pointer
}
