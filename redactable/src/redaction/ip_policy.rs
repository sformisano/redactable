//! Fail-closed structural traversal for IP-address policy kinds.

use std::{
    borrow::Cow,
    cell::{Cell, RefCell},
    collections::{BTreeMap, BTreeSet, HashMap, HashSet, VecDeque},
    hash::{BuildHasher, Hash},
    rc::Rc,
    sync::Arc,
};

use crate::{
    __private::PolicyFormattingOutput, IpAddressPolicyKind, RedactableMapper, RedactionPolicy,
    SensitiveValue, SensitiveWithPolicy,
};

/// Sealed positive allowlist for map keys under an IP-address policy kind.
#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a supported map key for this IP-address policy",
    note = "IP-address policy map keys must be known-safe non-text scalars; put typed IP data in values wrapped as `SensitiveValue<T, IpAddress>`"
)]
trait IpMapKeySafe: key_sealed::Sealed {}

mod key_sealed {
    pub(super) trait Sealed {}
}

mod traversal_sealed {
    #[allow(unreachable_pub)]
    pub trait Sealed {}
}

macro_rules! impl_sealed_unary {
    ($($container:ty),+ $(,)?) => {$ (
        impl<T> traversal_sealed::Sealed for $container {}
    )+ };
}

impl traversal_sealed::Sealed for String {}
impl traversal_sealed::Sealed for Cow<'_, str> {}
impl traversal_sealed::Sealed for &str {}
impl<T, P> traversal_sealed::Sealed for SensitiveValue<T, P> {}
impl_sealed_unary!(
    Option<T>,
    Vec<T>,
    VecDeque<T>,
    Box<T>,
    Arc<T>,
    Rc<T>,
    RefCell<T>,
    Cell<T>,
    BTreeSet<T>,
);
impl<T, const N: usize> traversal_sealed::Sealed for [T; N] {}
impl<T, E> traversal_sealed::Sealed for Result<T, E> {}
impl<K, V, S> traversal_sealed::Sealed for HashMap<K, V, S> {}
impl<K, V> traversal_sealed::Sealed for BTreeMap<K, V> {}
impl<T, S> traversal_sealed::Sealed for HashSet<T, S> {}

macro_rules! impl_safe_keys {
    ($($ty:ty),+ $(,)?) => {$ (
        impl key_sealed::Sealed for $ty {}
        impl IpMapKeySafe for $ty {}
    )+ };
}

impl_safe_keys!(
    (),
    bool,
    i8,
    i16,
    i32,
    i64,
    i128,
    isize,
    u8,
    u16,
    u32,
    u64,
    u128,
    usize,
    std::num::NonZeroI8,
    std::num::NonZeroI16,
    std::num::NonZeroI32,
    std::num::NonZeroI64,
    std::num::NonZeroI128,
    std::num::NonZeroIsize,
    std::num::NonZeroU8,
    std::num::NonZeroU16,
    std::num::NonZeroU32,
    std::num::NonZeroU64,
    std::num::NonZeroU128,
    std::num::NonZeroUsize,
);

#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a supported field shape for this IP-address policy",
    note = "typed IP values are bare-field-only; inside containers wrap each value in `SensitiveValue<T, IpAddress>`"
)]
#[doc(hidden)]
pub trait IpPolicyApplicable<P>: traversal_sealed::Sealed + Sized
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
{
    #[must_use]
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self;
}

#[diagnostic::on_unimplemented(
    message = "`{Self}` is not a supported formatted field shape for this IP-address policy",
    note = "typed IP values are bare-field-only; inside containers wrap each value in `SensitiveValue<T, IpAddress>`"
)]
#[doc(hidden)]
pub trait IpPolicyApplicableRef<P>: traversal_sealed::Sealed
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
{
    type Output;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output;

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        PolicyFormattingOutput::Value(self.apply_ip_policy_ref(mapper))
    }
}

fn collect_formatting<T, C>(
    values: impl IntoIterator<Item = PolicyFormattingOutput<T>>,
) -> PolicyFormattingOutput<C>
where
    C: FromIterator<T>,
{
    values
        .into_iter()
        .map(|value| match value {
            PolicyFormattingOutput::Value(value) => Some(value),
            PolicyFormattingOutput::Borrowed => None,
        })
        .collect::<Option<C>>()
        .map_or(
            PolicyFormattingOutput::Borrowed,
            PolicyFormattingOutput::Value,
        )
}

impl<P> IpPolicyApplicable<P> for String
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        mapper.map_sensitive::<_, P>(self)
    }
}

impl<P> IpPolicyApplicable<P> for Cow<'_, str>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        mapper.map_sensitive::<_, P>(self)
    }
}

impl<P> IpPolicyApplicableRef<P> for String
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
{
    type Output = String;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, _mapper: &M) -> Self::Output {
        P::policy().apply_to(self)
    }
}

impl<P> IpPolicyApplicableRef<P> for Cow<'_, str>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
{
    type Output = Cow<'static, str>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, _mapper: &M) -> Self::Output {
        Cow::Owned(P::policy().apply_to(self))
    }
}

impl<P> IpPolicyApplicableRef<P> for &str
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
{
    type Output = String;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, _mapper: &M) -> Self::Output {
        P::policy().apply_to(self)
    }
}

impl<T, P> IpPolicyApplicable<P> for SensitiveValue<T, P>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: SensitiveWithPolicy<P>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        crate::RedactableWithMapper::redact_with(self, mapper)
    }
}

impl<T, P> IpPolicyApplicableRef<P> for SensitiveValue<T, P>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: SensitiveWithPolicy<P>,
{
    type Output = String;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, _mapper: &M) -> Self::Output {
        self.redacted()
    }
}

impl<T, P> IpPolicyApplicable<P> for Option<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.map(|value| value.apply_ip_policy(mapper))
    }
}

impl<T, P> IpPolicyApplicableRef<P> for Option<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
{
    type Output = Option<T::Output>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        self.as_ref().map(|value| value.apply_ip_policy_ref(mapper))
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        self.as_ref()
            .map_or(PolicyFormattingOutput::Value(None), |value| {
                value.apply_ip_policy_ref_for_formatting(mapper).map(Some)
            })
    }
}

macro_rules! impl_sequence {
    ($container:ident) => {
        impl<T, P> IpPolicyApplicable<P> for $container<T>
        where
            P: RedactionPolicy<Kind = IpAddressPolicyKind>,
            T: IpPolicyApplicable<P>,
        {
            fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
                self.into_iter()
                    .map(|value| value.apply_ip_policy(mapper))
                    .collect()
            }
        }

        impl<T, P> IpPolicyApplicableRef<P> for $container<T>
        where
            P: RedactionPolicy<Kind = IpAddressPolicyKind>,
            T: IpPolicyApplicableRef<P>,
        {
            type Output = $container<T::Output>;

            fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
                self.iter()
                    .map(|value| value.apply_ip_policy_ref(mapper))
                    .collect()
            }

            fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
                &self,
                mapper: &M,
            ) -> PolicyFormattingOutput<Self::Output> {
                collect_formatting(
                    self.iter()
                        .map(|value| value.apply_ip_policy_ref_for_formatting(mapper)),
                )
            }
        }
    };
}

impl_sequence!(Vec);
impl_sequence!(VecDeque);

impl<T, P, const N: usize> IpPolicyApplicable<P> for [T; N]
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.map(|value| value.apply_ip_policy(mapper))
    }
}

impl<T, P, const N: usize> IpPolicyApplicableRef<P> for [T; N]
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
{
    type Output = [T::Output; N];

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        self.each_ref()
            .map(|value| value.apply_ip_policy_ref(mapper))
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        let values = self
            .each_ref()
            .map(|value| value.apply_ip_policy_ref_for_formatting(mapper));
        if values
            .iter()
            .any(|value| matches!(value, PolicyFormattingOutput::Borrowed))
        {
            return PolicyFormattingOutput::Borrowed;
        }
        PolicyFormattingOutput::Value(values.map(|value| match value {
            PolicyFormattingOutput::Value(value) => value,
            PolicyFormattingOutput::Borrowed => unreachable!("checked above"),
        }))
    }
}

macro_rules! impl_pointer {
    ($pointer:ident) => {
        impl<T, P> IpPolicyApplicable<P> for $pointer<T>
        where
            P: RedactionPolicy<Kind = IpAddressPolicyKind>,
            T: IpPolicyApplicable<P> + Clone,
        {
            fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
                $pointer::new((*self).clone().apply_ip_policy(mapper))
            }
        }

        impl<T, P> IpPolicyApplicableRef<P> for $pointer<T>
        where
            P: RedactionPolicy<Kind = IpAddressPolicyKind>,
            T: IpPolicyApplicableRef<P>,
        {
            type Output = $pointer<T::Output>;

            fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
                $pointer::new((**self).apply_ip_policy_ref(mapper))
            }

            fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
                &self,
                mapper: &M,
            ) -> PolicyFormattingOutput<Self::Output> {
                (**self)
                    .apply_ip_policy_ref_for_formatting(mapper)
                    .map($pointer::new)
            }
        }
    };
}

impl<T, P> IpPolicyApplicable<P> for Box<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        Box::new((*self).apply_ip_policy(mapper))
    }
}

impl<T, P> IpPolicyApplicableRef<P> for Box<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
{
    type Output = Box<T::Output>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        Box::new((**self).apply_ip_policy_ref(mapper))
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        (**self)
            .apply_ip_policy_ref_for_formatting(mapper)
            .map(Box::new)
    }
}

impl_pointer!(Arc);
impl_pointer!(Rc);

impl<T, P> IpPolicyApplicable<P> for RefCell<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        RefCell::new(self.into_inner().apply_ip_policy(mapper))
    }
}

impl<T, P> IpPolicyApplicableRef<P> for RefCell<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
{
    type Output = RefCell<T::Output>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        RefCell::new(self.borrow().apply_ip_policy_ref(mapper))
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        self.try_borrow()
            .map_or(PolicyFormattingOutput::Borrowed, |value| {
                value
                    .apply_ip_policy_ref_for_formatting(mapper)
                    .map(RefCell::new)
            })
    }
}

impl<T, P> IpPolicyApplicable<P> for Cell<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P> + Copy,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        Cell::new(self.get().apply_ip_policy(mapper))
    }
}

impl<T, P> IpPolicyApplicableRef<P> for Cell<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P> + Copy,
    T::Output: Copy,
{
    type Output = Cell<T::Output>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        Cell::new(self.get().apply_ip_policy_ref(mapper))
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        self.get()
            .apply_ip_policy_ref_for_formatting(mapper)
            .map(Cell::new)
    }
}

impl<T, E, P> IpPolicyApplicable<P> for Result<T, E>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P>,
    E: IpPolicyApplicable<P>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        match self {
            Ok(value) => Ok(value.apply_ip_policy(mapper)),
            Err(error) => Err(error.apply_ip_policy(mapper)),
        }
    }
}

impl<T, E, P> IpPolicyApplicableRef<P> for Result<T, E>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
    E: IpPolicyApplicableRef<P>,
{
    type Output = Result<T::Output, E::Output>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        match self {
            Ok(value) => Ok(value.apply_ip_policy_ref(mapper)),
            Err(error) => Err(error.apply_ip_policy_ref(mapper)),
        }
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        match self {
            Ok(value) => value.apply_ip_policy_ref_for_formatting(mapper).map(Ok),
            Err(error) => error.apply_ip_policy_ref_for_formatting(mapper).map(Err),
        }
    }
}

impl<K, V, S, P> IpPolicyApplicable<P> for HashMap<K, V, S>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    K: IpMapKeySafe + Hash + Eq,
    V: IpPolicyApplicable<P>,
    S: BuildHasher + Clone,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        let hasher = self.hasher().clone();
        let mut result = HashMap::with_capacity_and_hasher(self.len(), hasher);
        result.extend(
            self.into_iter()
                .map(|(key, value)| (key, value.apply_ip_policy(mapper))),
        );
        result
    }
}

impl<K, V, S, P> IpPolicyApplicableRef<P> for HashMap<K, V, S>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    K: IpMapKeySafe + Hash + Eq + Clone,
    V: IpPolicyApplicableRef<P>,
    S: BuildHasher + Clone,
{
    type Output = HashMap<K, V::Output, S>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        let hasher = self.hasher().clone();
        let mut result = HashMap::with_capacity_and_hasher(self.len(), hasher);
        result.extend(
            self.iter()
                .map(|(key, value)| (key.clone(), value.apply_ip_policy_ref(mapper))),
        );
        result
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        let hasher = self.hasher().clone();
        let mut result = HashMap::with_capacity_and_hasher(self.len(), hasher);
        for (key, value) in self {
            match value.apply_ip_policy_ref_for_formatting(mapper) {
                PolicyFormattingOutput::Value(value) => {
                    result.insert(key.clone(), value);
                }
                PolicyFormattingOutput::Borrowed => return PolicyFormattingOutput::Borrowed,
            }
        }
        PolicyFormattingOutput::Value(result)
    }
}

impl<K, V, P> IpPolicyApplicable<P> for BTreeMap<K, V>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    K: IpMapKeySafe + Ord,
    V: IpPolicyApplicable<P>,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|(key, value)| (key, value.apply_ip_policy(mapper)))
            .collect()
    }
}

impl<K, V, P> IpPolicyApplicableRef<P> for BTreeMap<K, V>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    K: IpMapKeySafe + Ord + Clone,
    V: IpPolicyApplicableRef<P>,
{
    type Output = BTreeMap<K, V::Output>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        self.iter()
            .map(|(key, value)| (key.clone(), value.apply_ip_policy_ref(mapper)))
            .collect()
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        collect_formatting(self.iter().map(|(key, value)| {
            value
                .apply_ip_policy_ref_for_formatting(mapper)
                .map(|value| (key.clone(), value))
        }))
    }
}

impl<T, S, P> IpPolicyApplicable<P> for HashSet<T, S>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P> + Hash + Eq,
    S: BuildHasher + Clone,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_capacity_and_hasher(self.len(), hasher);
        result.extend(self.into_iter().map(|value| value.apply_ip_policy(mapper)));
        result
    }
}

impl<T, S, P> IpPolicyApplicableRef<P> for HashSet<T, S>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
    T::Output: Hash + Eq,
    S: BuildHasher + Clone,
{
    type Output = HashSet<T::Output, S>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_capacity_and_hasher(self.len(), hasher);
        result.extend(self.iter().map(|value| value.apply_ip_policy_ref(mapper)));
        result
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        let hasher = self.hasher().clone();
        let mut result = HashSet::with_capacity_and_hasher(self.len(), hasher);
        for value in self {
            match value.apply_ip_policy_ref_for_formatting(mapper) {
                PolicyFormattingOutput::Value(value) => {
                    result.insert(value);
                }
                PolicyFormattingOutput::Borrowed => return PolicyFormattingOutput::Borrowed,
            }
        }
        PolicyFormattingOutput::Value(result)
    }
}

impl<T, P> IpPolicyApplicable<P> for BTreeSet<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicable<P> + Ord,
{
    fn apply_ip_policy<M: RedactableMapper>(self, mapper: &M) -> Self {
        self.into_iter()
            .map(|value| value.apply_ip_policy(mapper))
            .collect()
    }
}

impl<T, P> IpPolicyApplicableRef<P> for BTreeSet<T>
where
    P: RedactionPolicy<Kind = IpAddressPolicyKind>,
    T: IpPolicyApplicableRef<P>,
    T::Output: Ord,
{
    type Output = BTreeSet<T::Output>;

    fn apply_ip_policy_ref<M: RedactableMapper>(&self, mapper: &M) -> Self::Output {
        self.iter()
            .map(|value| value.apply_ip_policy_ref(mapper))
            .collect()
    }

    fn apply_ip_policy_ref_for_formatting<M: RedactableMapper>(
        &self,
        mapper: &M,
    ) -> PolicyFormattingOutput<Self::Output> {
        collect_formatting(
            self.iter()
                .map(|value| value.apply_ip_policy_ref_for_formatting(mapper)),
        )
    }
}
