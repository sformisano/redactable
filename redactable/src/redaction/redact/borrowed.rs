//! Borrowed and formatting container implementations.
//!
//! [`PolicyApplicableRef`] implementations apply a policy through `&self`,
//! producing owned redacted output without consuming the source container.
//! [`PolicyApplicableRefForGeneratedFormatting`] implementations render the
//! same container family for generated `Display`/`Debug` output, using
//! [`PolicyFormattingOutput`] to distinguish rendered values from
//! pass-through borrows. Both families are written out explicitly per
//! container — never blanket — so unsupported borrowed shapes are rejected
//! at compile time rather than silently passed through.

use std::{
    cell::{Cell, RefCell},
    collections::VecDeque,
    rc::Rc,
    sync::Arc,
};

use crate::{
    __private::{PolicyApplicableRefForGeneratedFormatting, PolicyFormattingOutput},
    policy::{RecursivePolicyKind, RedactionPolicy},
};

use super::core::{
    PolicyApplicableRef, RedactableMapper, apply_child_policy_ref_for_formatting,
    collect_policy_formatting,
};

// =============================================================================
// PolicyApplicableRef: Recursive implementations (wrapper types)
// =============================================================================

impl<T> PolicyApplicableRef for Option<T>
where
    T: PolicyApplicableRef,
{
    type Output = Option<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.as_ref().map(|v| v.apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Option<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Option<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.as_ref().map_or_else(
            || PolicyFormattingOutput::Value(None),
            |value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper).map(Some),
        )
    }
}

impl<T> PolicyApplicableRef for Vec<T>
where
    T: PolicyApplicableRef,
{
    type Output = Vec<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.iter()
            .map(|v| v.apply_policy_ref::<P, M>(mapper))
            .collect()
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Vec<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Vec<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        collect_policy_formatting(
            self.iter()
                .map(|value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper)),
        )
    }
}

impl<T> PolicyApplicableRef for VecDeque<T>
where
    T: PolicyApplicableRef,
{
    type Output = VecDeque<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.iter()
            .map(|v| v.apply_policy_ref::<P, M>(mapper))
            .collect()
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for VecDeque<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = VecDeque<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        collect_policy_formatting(
            self.iter()
                .map(|value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper)),
        )
    }
}

impl<T, const N: usize> PolicyApplicableRef for [T; N]
where
    T: PolicyApplicableRef,
{
    type Output = [T::Output; N];

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.each_ref().map(|v| v.apply_policy_ref::<P, M>(mapper))
    }
}

impl<T, const N: usize> PolicyApplicableRefForGeneratedFormatting for [T; N]
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = [T::FormattingOutput; N];

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let values = self
            .each_ref()
            .map(|value| apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper));
        if values
            .iter()
            .any(|value| matches!(value, PolicyFormattingOutput::Borrowed))
        {
            return PolicyFormattingOutput::Borrowed;
        }
        PolicyFormattingOutput::Value(values.map(|value| match value {
            PolicyFormattingOutput::Value(value) => value,
            PolicyFormattingOutput::Borrowed => unreachable!("borrow conflicts returned above"),
        }))
    }
}

impl<T> PolicyApplicableRef for Box<T>
where
    T: PolicyApplicableRef,
{
    type Output = Box<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Box::new((**self).apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Box<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Box<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        apply_child_policy_ref_for_formatting::<P, _, M>(&**self, mapper).map(Box::new)
    }
}

impl<T> PolicyApplicableRef for Arc<T>
where
    T: PolicyApplicableRef,
{
    type Output = Arc<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Arc::new((**self).apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Arc<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Arc<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        apply_child_policy_ref_for_formatting::<P, _, M>(&**self, mapper).map(Arc::new)
    }
}

impl<T> PolicyApplicableRef for Rc<T>
where
    T: PolicyApplicableRef,
{
    type Output = Rc<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        Rc::new((**self).apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Rc<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Rc<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        apply_child_policy_ref_for_formatting::<P, _, M>(&**self, mapper).map(Rc::new)
    }
}

impl<T> PolicyApplicableRef for RefCell<T>
where
    T: PolicyApplicableRef,
{
    type Output = RefCell<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        RefCell::new(self.borrow().apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for RefCell<T>
where
    T: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = RefCell<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        self.try_borrow().map_or_else(
            |_| PolicyFormattingOutput::Borrowed,
            |value| {
                apply_child_policy_ref_for_formatting::<P, _, M>(&*value, mapper).map(RefCell::new)
            },
        )
    }
}

impl<T> PolicyApplicableRef for Cell<T>
where
    T: PolicyApplicableRef + Copy,
    T::Output: Copy,
{
    type Output = Cell<T::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        let value = self.get();
        Cell::new(value.apply_policy_ref::<P, M>(mapper))
    }
}

impl<T> PolicyApplicableRefForGeneratedFormatting for Cell<T>
where
    T: PolicyApplicableRefForGeneratedFormatting + Copy,
    T::FormattingOutput: Copy,
{
    type FormattingOutput = Cell<T::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        apply_child_policy_ref_for_formatting::<P, _, M>(&self.get(), mapper).map(Cell::new)
    }
}

impl<T, E> PolicyApplicableRef for Result<T, E>
where
    T: PolicyApplicableRef,
    E: PolicyApplicableRef,
{
    type Output = Result<T::Output, E::Output>;

    fn apply_policy_ref<P, M>(&self, mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        match self {
            Ok(v) => Ok(v.apply_policy_ref::<P, M>(mapper)),
            Err(e) => Err(e.apply_policy_ref::<P, M>(mapper)),
        }
    }
}

impl<T, E> PolicyApplicableRefForGeneratedFormatting for Result<T, E>
where
    T: PolicyApplicableRefForGeneratedFormatting,
    E: PolicyApplicableRefForGeneratedFormatting,
{
    type FormattingOutput = Result<T::FormattingOutput, E::FormattingOutput>;

    fn apply_policy_ref_for_generated_formatting<P, M>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::FormattingOutput>
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        match self {
            Ok(value) => apply_child_policy_ref_for_formatting::<P, _, M>(value, mapper).map(Ok),
            Err(error) => apply_child_policy_ref_for_formatting::<P, _, M>(error, mapper).map(Err),
        }
    }
}
