use redactable::logging::Sink;

fn unchecked(sink: &Sink) {
    let key = "runtime key";
    let raw = 42_u32;
    redactable::info!(valid = (), data:serde = raw; "unchecked serialization");
    redactable::warn!(sink: sink, (key) = (); "dynamic key");
    redactable::info!(sink, "positional sink");
}

fn main() {}
