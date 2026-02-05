//! Passthrough `RedactableContainer` implementations for scalar-like types.

use std::{
    borrow::Cow,
    cmp::Ordering,
    marker::PhantomData,
    num::{
        NonZeroI8, NonZeroI16, NonZeroI32, NonZeroI64, NonZeroI128, NonZeroIsize, NonZeroU8,
        NonZeroU16, NonZeroU32, NonZeroU64, NonZeroU128, NonZeroUsize,
    },
    time::{Duration, Instant, SystemTime},
};

use super::impl_redactable_container_passthrough;
use crate::redaction::{redact::RedactableMapper, traits::RedactableContainer};

// =============================================================================
// Passthrough implementations (scalars and primitives)
// =============================================================================

impl_redactable_container_passthrough!(String);
impl_redactable_container_passthrough!(bool);
impl_redactable_container_passthrough!(char);

// Signed integers
impl_redactable_container_passthrough!(i8);
impl_redactable_container_passthrough!(i16);
impl_redactable_container_passthrough!(i32);
impl_redactable_container_passthrough!(i64);
impl_redactable_container_passthrough!(i128);
impl_redactable_container_passthrough!(isize);

// Unsigned integers
impl_redactable_container_passthrough!(u8);
impl_redactable_container_passthrough!(u16);
impl_redactable_container_passthrough!(u32);
impl_redactable_container_passthrough!(u64);
impl_redactable_container_passthrough!(u128);
impl_redactable_container_passthrough!(usize);

// Floating point
impl_redactable_container_passthrough!(f32);
impl_redactable_container_passthrough!(f64);

// Unit type
impl_redactable_container_passthrough!(());

// =============================================================================
// NonZero integer passthrough implementations
// =============================================================================

impl_redactable_container_passthrough!(NonZeroI8);
impl_redactable_container_passthrough!(NonZeroI16);
impl_redactable_container_passthrough!(NonZeroI32);
impl_redactable_container_passthrough!(NonZeroI64);
impl_redactable_container_passthrough!(NonZeroI128);
impl_redactable_container_passthrough!(NonZeroIsize);
impl_redactable_container_passthrough!(NonZeroU8);
impl_redactable_container_passthrough!(NonZeroU16);
impl_redactable_container_passthrough!(NonZeroU32);
impl_redactable_container_passthrough!(NonZeroU64);
impl_redactable_container_passthrough!(NonZeroU128);
impl_redactable_container_passthrough!(NonZeroUsize);

// =============================================================================
// std::time passthrough implementations
// =============================================================================

impl_redactable_container_passthrough!(Duration);
impl_redactable_container_passthrough!(Instant);
impl_redactable_container_passthrough!(SystemTime);

// =============================================================================
// Other std passthrough implementations
// =============================================================================

impl_redactable_container_passthrough!(Ordering);

impl<T> RedactableContainer for PhantomData<T> {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl RedactableContainer for Cow<'_, str> {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

// =============================================================================
// Date/time passthrough implementations (feature-gated)
// =============================================================================

#[cfg(feature = "chrono")]
mod chrono_passthrough {
    use chrono::{
        DateTime, Duration, FixedOffset, Local, Month, NaiveDate, NaiveDateTime, NaiveTime, Utc,
        Weekday,
    };

    use super::impl_redactable_container_passthrough;

    // DateTime variants
    impl_redactable_container_passthrough!(DateTime<Utc>);
    impl_redactable_container_passthrough!(DateTime<Local>);
    impl_redactable_container_passthrough!(DateTime<FixedOffset>);

    // Timezone marker
    impl_redactable_container_passthrough!(Utc);

    // Naive date/time types
    impl_redactable_container_passthrough!(NaiveDateTime);
    impl_redactable_container_passthrough!(NaiveDate);
    impl_redactable_container_passthrough!(NaiveTime);

    // Duration (TimeDelta is an alias for Duration)
    impl_redactable_container_passthrough!(Duration);

    // Calendar enums
    impl_redactable_container_passthrough!(Month);
    impl_redactable_container_passthrough!(Weekday);
}

#[cfg(feature = "time")]
mod time_passthrough {
    use time::{
        Date, Duration, Month, OffsetDateTime, PrimitiveDateTime, Time, UtcOffset, Weekday,
    };

    use super::impl_redactable_container_passthrough;

    // DateTime types
    impl_redactable_container_passthrough!(OffsetDateTime);
    impl_redactable_container_passthrough!(PrimitiveDateTime);

    // Date/time components
    impl_redactable_container_passthrough!(Date);
    impl_redactable_container_passthrough!(Time);

    // Duration
    impl_redactable_container_passthrough!(Duration);

    // Timezone offset
    impl_redactable_container_passthrough!(UtcOffset);

    // Calendar enums
    impl_redactable_container_passthrough!(Month);
    impl_redactable_container_passthrough!(Weekday);
}

// =============================================================================
// UUID passthrough implementations (feature-gated)
// =============================================================================

#[cfg(feature = "uuid")]
mod uuid_passthrough {
    use uuid::Uuid;

    use super::impl_redactable_container_passthrough;

    impl_redactable_container_passthrough!(Uuid);
}
