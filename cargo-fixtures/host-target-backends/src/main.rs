use safe::slog::SlogRedacted as BackendMarker;

mod declarations;

fn main() {
    declarations::require_backend_impls();
}
