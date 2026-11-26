use redactable::logging::Sink;

fn unchecked(sink: &Sink) {
    let secret = "raw";
    redactable::info!(sink, "signed in {secret}");
    redactable::warn!(sink, data = (); "signed in {}", secret);
    redactable::error!(sink, data = (); secret);
}

fn main() {}
