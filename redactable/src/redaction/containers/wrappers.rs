//! Redaction traversal for wrapper container types.

use std::{
    collections::VecDeque,
    sync::{Mutex, RwLock},
};

use crate::redaction::{redact::RedactableMapper, traits::RedactableWithMapper};

// =============================================================================
// Wrapper container implementations
// =============================================================================

impl<T> RedactableWithMapper for Option<T>
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.map(|value| value.redact_with(mapper))
    }
}

impl<T, E> RedactableWithMapper for Result<T, E>
where
    T: RedactableWithMapper,
    E: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        match self {
            Ok(value) => Ok(value.redact_with(mapper)),
            Err(err) => Err(err.redact_with(mapper)),
        }
    }
}

impl<T> RedactableWithMapper for Vec<T>
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|value| value.redact_with(mapper))
            .collect()
    }
}

impl<T> RedactableWithMapper for VecDeque<T>
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|value| value.redact_with(mapper))
            .collect()
    }
}

impl<T, const N: usize> RedactableWithMapper for [T; N]
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.map(|value| value.redact_with(mapper))
    }
}

impl<T> RedactableWithMapper for Box<T>
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        Box::new((*self).redact_with(mapper))
    }
}

impl<T> RedactableWithMapper for std::sync::Arc<T>
where
    T: RedactableWithMapper + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::sync::Arc::new((*self).clone().redact_with(mapper))
    }
}

impl<T> RedactableWithMapper for std::rc::Rc<T>
where
    T: RedactableWithMapper + Clone,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        std::rc::Rc::new((*self).clone().redact_with(mapper))
    }
}

impl<T> RedactableWithMapper for Mutex<T>
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // Keep poison recovery explicit at the lock extraction boundary.
        #[allow(clippy::redundant_closure_for_method_calls)]
        let value = self.into_inner().unwrap_or_else(|err| err.into_inner());
        Mutex::new(value.redact_with(mapper))
    }
}

impl<T> RedactableWithMapper for RwLock<T>
where
    T: RedactableWithMapper,
{
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        // Keep poison recovery explicit at the lock extraction boundary.
        #[allow(clippy::redundant_closure_for_method_calls)]
        let value = self.into_inner().unwrap_or_else(|err| err.into_inner());
        RwLock::new(value.redact_with(mapper))
    }
}

macro_rules! impl_tuple_redactable_with_mapper {
    ($($name:ident),+ $(,)?) => {
        impl<$($name),+> RedactableWithMapper for ($($name,)+)
        where
            $($name: RedactableWithMapper,)+
        {
            #[allow(non_snake_case)]
            fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
                let ($($name,)+) = self;
                ($($name.redact_with(mapper),)+)
            }
        }
    };
}

impl_tuple_redactable_with_mapper!(T0);
impl_tuple_redactable_with_mapper!(T0, T1);
impl_tuple_redactable_with_mapper!(T0, T1, T2);
impl_tuple_redactable_with_mapper!(T0, T1, T2, T3);
