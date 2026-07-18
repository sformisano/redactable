//! Owned container implementations of [`PolicyApplicable`].
//!
//! Each implementation consumes the container, applies the policy to every
//! element by value, and rebuilds the same container shape. Traversal through
//! `Arc`/`Rc` clones the shared referent because other owners may still hold
//! it — and only such cloning (or otherwise borrowing) paths can observe a
//! `RefCell` borrow panic: owned `RefCell` traversal consumes the cell with
//! `into_inner()` and never inspects the borrow flag, so it survives even a
//! stuck borrow. Implementations are written out explicitly per container —
//! never blanket — so unsupported owned shapes fail closed at compile time.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
    sync::Arc,
};

use crate::policy::{RecursivePolicyKind, RedactionPolicy};

use super::core::{PolicyApplicable, RedactableMapper};

// =============================================================================
// PolicyApplicable: Recursive implementations (wrapper types)
// =============================================================================

impl<T: PolicyApplicable> PolicyApplicable for Option<T> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.map(|v| v.apply_policy::<P, M>(mapper))
    }
}

impl<T: PolicyApplicable> PolicyApplicable for Vec<T> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.into_iter()
            .map(|v| v.apply_policy::<P, M>(mapper))
            .collect()
    }
}

impl<T: PolicyApplicable> PolicyApplicable for VecDeque<T> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.into_iter()
            .map(|v| v.apply_policy::<P, M>(mapper))
            .collect()
    }
}

impl<T: PolicyApplicable, const N: usize> PolicyApplicable for [T; N] {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.map(|v| v.apply_policy::<P, M>(mapper))
    }
}

impl<T: PolicyApplicable> PolicyApplicable for Box<T> {
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Box::new((*self).apply_policy::<P, M>(mapper))
    }
}

impl<T> PolicyApplicable for Arc<T>
where
    T: PolicyApplicable + Clone,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Arc::new((*self).clone().apply_policy::<P, M>(mapper))
    }
}

impl<T> PolicyApplicable for Rc<T>
where
    T: PolicyApplicable + Clone,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Rc::new((*self).clone().apply_policy::<P, M>(mapper))
    }
}

impl<T> PolicyApplicable for RefCell<T>
where
    T: PolicyApplicable,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        RefCell::new(self.into_inner().apply_policy::<P, M>(mapper))
    }
}

impl<T> PolicyApplicable for Cell<T>
where
    T: PolicyApplicable + Copy,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Cell::new(self.get().apply_policy::<P, M>(mapper))
    }
}

impl<T, E> PolicyApplicable for Result<T, E>
where
    T: PolicyApplicable,
    E: PolicyApplicable,
{
    fn apply_policy<P, M>(self, mapper: &M) -> Self
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        match self {
            Ok(v) => Ok(v.apply_policy::<P, M>(mapper)),
            Err(e) => Err(e.apply_policy::<P, M>(mapper)),
        }
    }
}
