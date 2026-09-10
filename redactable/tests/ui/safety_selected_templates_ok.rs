use redactable::{
    NotSensitive, NotSensitiveDisplay, Redactable, RedactableWithFormatter, Secret, Sensitive,
    SensitiveDisplay, SensitiveDual,
};
use std::fmt::{Display, Formatter, Result as FmtResult};

// Omitted foreign fields need neither structural traversal nor Debug.
struct Foreign;
#[derive(SensitiveDisplay)]
#[error("category")]
struct Constant {
    foreign: Foreign,
}
#[derive(SensitiveDisplay)]
/// docs {public}
struct Docs {
    #[not_sensitive]
    public: String,
    omitted: Foreign,
}
#[derive(SensitiveDisplay)]
#[error("error {public}")]
/// docs {omitted}
struct Precedence {
    #[not_sensitive]
    public: String,
    omitted: Foreign,
}
#[derive(Clone, SensitiveDual, serde::Serialize)]
#[error("{secret}")]
struct Protected {
    #[sensitive(Secret)]
    secret: String,
}
#[derive(Clone, serde::Serialize, Sensitive)]
struct Bypass {
    #[not_sensitive]
    nested: Protected,
}
#[derive(NotSensitive, serde::Serialize)]
struct WholePublic {
    nested: Protected,
}
#[derive(NotSensitiveDisplay)]
struct PublicText {
    foreign: Foreign,
}
impl Display for PublicText {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        f.write_str("PUBLIC")
    }
}
#[derive(SensitiveDisplay)]
#[error("{field:?}")]
struct UsesDeclared {
    field: PublicText,
}

fn main() {
    assert_eq!(format!("{:?}", Constant { foreign: Foreign }), "category");
    assert_eq!(
        Docs {
            public: "ok".into(),
            omitted: Foreign
        }
        .redacted_display()
        .to_string(),
        "docs ok"
    );
    assert_eq!(
        Precedence {
            public: "ok".into(),
            omitted: Foreign
        }
        .redacted_display()
        .to_string(),
        "error ok"
    );
    assert_eq!(
        Bypass {
            nested: Protected {
                secret: "declared public".into()
            }
        }
        .redact()
        .nested
        .secret,
        "declared public"
    );
    assert_eq!(
        WholePublic {
            nested: Protected {
                secret: "declared public".into()
            }
        }
        .redact()
        .nested
        .secret,
        "declared public"
    );
    assert_eq!(
        UsesDeclared {
            field: PublicText { foreign: Foreign }
        }
        .redacted_display()
        .to_string(),
        "PUBLIC"
    );
}
