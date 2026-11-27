fn fields() {
    let user = ();
    let message = ();
    redactable::info!(type = (), r#match:% = (); "distinct keywords");
    redactable::info!(user, other = (), user:? = (); "repeated name");
    redactable::warn!(r#type = (), type:% = (); "repeated keyword");
    redactable::error!(message; "reserved field");
}

fn main() {}
