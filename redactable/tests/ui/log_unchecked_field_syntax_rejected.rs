use redactable::logging::Sink;

fn unchecked(sink: &Sink) {
    let key = "runtime key";
    let raw = 42_u32;
    redactable::info!(sink, valid = (), data:serde = raw; "unchecked serialization");
    redactable::warn!(sink, (key) = (); "dynamic key");
}

fn main() {}
