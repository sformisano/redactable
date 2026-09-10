use redactable::{Redactable, Sensitive};

// A user type named `PhantomData` is not the std marker: it carries a value and
// must be declared. `Clone` and `Serialize` are written by hand and hold for
// every `T`, so the only diagnostic left is the missing redaction declaration.
struct PhantomData<T>(T);

impl<T> Clone for PhantomData<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T> serde::Serialize for PhantomData<T> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_unit()
    }
}

#[derive(Clone, serde::Serialize, Sensitive)]
struct Envelope<T> {
    marker: PhantomData<T>,
}

fn main() {
    let _ = Envelope {
        marker: PhantomData(String::from("phase01-canary")),
    }
    .redact();
}
