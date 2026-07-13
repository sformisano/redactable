use redactable::{Redactable, Sensitive};

struct PhantomData<T>(T);

#[derive(Sensitive)]
struct Envelope<T> {
    marker: PhantomData<T>,
}

fn main() {
    let _ = Envelope {
        marker: PhantomData(String::from("phase01-canary")),
    }
    .redact();
}
