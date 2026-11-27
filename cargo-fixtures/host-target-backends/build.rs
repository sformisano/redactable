use safe::tracing::TracingRedacted as BackendMarker;

#[path = "src/declarations.rs"]
mod declarations;

fn main() {
    declarations::require_backend_impls();
}
