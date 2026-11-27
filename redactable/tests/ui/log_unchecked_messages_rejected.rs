fn unchecked() {
    let secret = "raw";
    redactable::info!("signed in {secret}");
    redactable::warn!(data = (); "signed in as {who} with {secret}", who = ());
    redactable::error!(data = (); secret);
}

fn main() {}
