//! Item-call limits and JSON shape assertion boundaries.

use std::{cell::RefCell, num::NonZeroUsize};

use redactable::{
    BypassJsonRedaction, BypassTextRedaction, RedactedList, RedactedValue, ToRedacted,
};
use serde_json::{Value, json};

struct Item<'a> {
    index: usize,
    calls: &'a RefCell<Vec<usize>>,
    panic_if_called: bool,
}

impl ToRedacted for Item<'_> {
    fn to_redacted(&self) -> RedactedValue {
        assert!(!self.panic_if_called, "omitted producer must never run");
        self.calls.borrow_mut().push(self.index);
        if self.index.is_multiple_of(2) {
            BypassTextRedaction(format!("item{}", self.index)).to_redacted()
        } else {
            BypassJsonRedaction(&json!({"index":self.index})).to_redacted()
        }
    }
}

fn selected_json(value: &impl ToRedacted) -> Value {
    value.to_redacted().json()
}

#[test]
fn list_invokes_included_items_once_in_order_and_never_omitted_items() {
    let calls = RefCell::new(Vec::new());
    let items: Vec<_> = (0..5)
        .map(|index| Item {
            index,
            calls: &calls,
            panic_if_called: index >= 2,
        })
        .collect();
    let list = RedactedList::new(&items, NonZeroUsize::new(2).unwrap());
    assert!(calls.borrow().is_empty());
    assert_eq!(
        selected_json(&list),
        json!({"items":[{"message":"item0"},{"index":1}],"omitted":3})
    );
    assert_eq!(*calls.borrow(), [0, 1]);
}

#[test]
fn list_limits_cover_empty_exact_overlarge_and_maximum() {
    for len in [0, 1, 2, 3] {
        for limit in [1, 2, 3, usize::MAX] {
            let calls = RefCell::new(Vec::new());
            let items: Vec<_> = (0..len)
                .map(|index| Item {
                    index,
                    calls: &calls,
                    panic_if_called: false,
                })
                .collect();
            let included = len.min(limit);
            let expected_items: Vec<_> = (0..included)
                .map(|index| {
                    if index % 2 == 0 {
                        // A text item follows `json()`: `{"message": text}`.
                        json!({"message": format!("item{index}")})
                    } else {
                        json!({"index":index})
                    }
                })
                .collect();
            assert_eq!(
                selected_json(&RedactedList::new(
                    &items,
                    NonZeroUsize::new(limit).unwrap()
                )),
                json!({"items":expected_items,"omitted":len-included})
            );
            assert_eq!(*calls.borrow(), (0..included).collect::<Vec<_>>());
        }
    }
    let empty_summary = [BypassTextRedaction(String::new())];
    assert_eq!(
        selected_json(&RedactedList::new(
            &empty_summary,
            NonZeroUsize::new(1).unwrap()
        )),
        json!({"items":[{"message":""}],"omitted":0})
    );
}

#[cfg(feature = "testing")]
mod shape {
    use std::panic::catch_unwind;

    use redactable::{
        BypassJsonRedaction, BypassTextRedaction, ToRedacted, testing::assert_json_shape,
    };
    use serde_json::{Value, json};

    fn shape(plain: &Value, selected: &Value, opaque: &[&str]) {
        assert_json_shape(plain, &BypassJsonRedaction(selected).to_redacted(), opaque);
    }

    fn rejects(plain: &Value, selected: &Value, opaque: &[&str]) {
        assert!(catch_unwind(|| shape(plain, selected, opaque)).is_err());
    }

    #[test]
    fn shape_checks_nested_structure_and_ignores_only_scalar_values() {
        let plain = json!({"rows":[{"a":"raw","b":true},null,3],"empty":{},"list":[]});
        let selected = json!({"list":[],"empty":{},"rows":[{"b":false,"a":"masked"},null,3.5]});
        shape(&plain, &selected, &[]);
        // Exact values are authored independently from the shape assertion.
        assert_eq!(selected["rows"][0], json!({"a":"masked","b":false}));
        rejects(&plain, &json!("[REDACTED]"), &[]);
        rejects(&json!(["s", 1]), &json!([1, "s"]), &[]);
        rejects(&json!([1]), &json!([]), &[]);
        rejects(&json!({"a":1}), &json!({"b":1}), &[]);
        rejects(&json!({"a":1}), &json!({"a":1,"b":1}), &[]);
        rejects(&json!(null), &json!(false), &[]);
    }

    #[test]
    fn opaque_nodes_allow_changes_without_waiving_parent_keys_or_siblings() {
        let plain = json!({"opaque":{"secret":[1,2]},"set":["a","b"],"public":true});
        let selected = json!({"opaque":"[REDACTED]","set":["[REDACTED]"],"public":true});
        shape(&plain, &selected, &["/opaque", "/set"]);
        assert_eq!(
            selected,
            json!({"opaque":"[REDACTED]","set":["[REDACTED]"],"public":true})
        );
        rejects(&plain, &selected, &["/opaque"]);
        rejects(
            &plain,
            &json!({"set":[],"public":true}),
            &["/opaque", "/set"],
        );
        rejects(
            &plain,
            &json!({"opaque":"masked","set":[],"public":"wrong"}),
            &["/opaque", "/set"],
        );
        shape(&plain, &json!("summary"), &[""]);
        rejects(&plain, &json!("summary"), &["/opaque"]);
    }

    #[test]
    fn pointer_escapes_empty_keys_literal_stars_and_numeric_object_keys_are_exact() {
        let plain = json!({"":{"a/b":{"~key":[1]}},"*":{},"01":true,"~1":[]});
        let selected = json!({"":{"a/b":{"~key":"masked"}},"*":"masked","01":null,"~1":false});
        shape(&plain, &selected, &["//a~1b/~0key", "/*", "/01", "/~01"]);
        shape(&json!({"":{}}), &json!({"":"masked"}), &["/"]);
        shape(
            &json!([{"a":[]}]),
            &json!([{"a":"masked"}]),
            &["/0/a", "/0/a"],
        );
        rejects(&json!({"a":1}), &json!({"a":"wrong"}), &["/*"]);
    }

    #[test]
    fn malformed_paths_are_rejected_even_beneath_an_opaque_root() {
        for path in ["a", "#/a", "/~", "/~2", "/a~x", "/nested/~9"] {
            rejects(&json!({}), &json!({}), &["", path]);
        }
        for token in [
            "",
            "-",
            "+1",
            "-1",
            "00",
            "01",
            "1.0",
            "*",
            "a",
            "999999999999999999999999999999999999999",
        ] {
            let path = format!("/rows/{token}");
            // Even empty arrays validate the reached token.
            rejects(&json!({"rows":[]}), &json!({"rows":[]}), &["", &path]);
            // Reaching an array on only one side still validates the token.
            rejects(
                &json!({"rows":null}),
                &json!({"rows":[]}),
                &["/rows", &path],
            );
        }
    }

    #[test]
    fn unmatched_paths_are_inactive_and_cannot_hide_ancestor_mismatches() {
        let absent = json!({"optional":null,"items":[],"scalar":7});
        shape(
            &absent,
            &absent,
            &[
                "/missing/nested",
                "/optional/00",
                "/items/2/nested",
                "/scalar/-",
            ],
        );
        shape(&json!([1]), &json!([0]), &["/2"]);
        rejects(
            &absent,
            &json!({"items":[],"scalar":7}),
            &["/optional/nested"],
        );
        rejects(
            &absent,
            &json!({"optional":{},"items":[],"scalar":7}),
            &["/optional/nested"],
        );
        rejects(&json!({"items":[]}), &json!({"items":[1]}), &["/items/2"]);
        rejects(&json!({"items":[]}), &json!({"items":[1]}), &["/items/0"]);
    }

    #[test]
    fn a_text_only_value_is_compared_through_its_documented_fallback() {
        for text in ["", "[REDACTED]", "{\"owner\":\"masked\"}"] {
            let summary = BypassTextRedaction(text.into()).to_redacted();
            // The fallback shape is `{"message": text}`, so an object carrying
            // any other key still mismatches.
            assert!(
                catch_unwind(|| assert_json_shape(&json!({"owner":"Ada"}), &summary, &[])).is_err()
            );
            // It is no longer refused outright: the fallback matches its own
            // shape, and an opaque root waives the comparison entirely.
            assert_json_shape(&json!({"message": "anything"}), &summary, &[]);
            assert_json_shape(&json!({}), &summary, &[""]);
        }
    }

    #[test]
    fn mismatch_diagnostic_names_the_path_without_printing_values() {
        let error = catch_unwind(|| {
            shape(
                &json!({"nested":["secret"]}),
                &json!({"nested":[null]}),
                &[],
            )
        })
        .unwrap_err();
        let message = error.downcast_ref::<String>().expect("string panic");
        assert!(message.contains("/nested/0"));
        assert!(!message.contains("secret"));
    }
}
