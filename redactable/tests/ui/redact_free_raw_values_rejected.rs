use redactable::redact;

fn main() {
    let _ = redact(String::from("secret"));
    let _ = redact(7_u64);
    let _ = redact(vec![String::from("secret")]);
    let _ = redact(Some(String::from("secret")));
}
