use redactable::logging::Sink;

fn fields(sink: &Sink) {
    redactable::info!(sink, type = (), r#match:% = (); "distinct keywords");
    redactable::info!(sink, user = (), other = (), user:? = (); "repeated name");
    redactable::warn!(sink, r#type = (), type:% = (); "repeated keyword");
}

fn main() {}
