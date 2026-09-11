use redactable::__private::PolicyFieldRef;
use redactable::{PolicyDebug, PolicyDisplay, RedactableWithFormatter};
use std::boxed::Box as RenamedBox;
use std::net::Ipv4Addr as RenamedPeer;
use std::primitive::u32 as RenamedCount;
use std::{
    fmt::{Debug, Formatter, Result as FmtResult},
    marker::PhantomData,
    net::Ipv4Addr,
};

use redactable::__private::PolicyApplicableRefForFormatting as FormattingMarker;
use redactable::policy::RecursivePolicyKind;
use redactable::{PolicyApplicableRef, RedactableMapper, RedactionPolicy, SensitiveDisplay};

pub type Count = u32;
pub type Peer = Ipv4Addr;
pub type BoxAlias<T> = Box<T>;
pub type ConcreteBox = Box<String>;

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct GenericPolicyScalar<P: RedactionPolicy>
where
    u32: PolicyDisplay<P> + PolicyDebug<P>,
{
    #[sensitive(P)]
    pub value: u32,
    pub marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct GenericPolicyIp<P: RedactionPolicy>
where
    Ipv4Addr: PolicyDisplay<P> + PolicyDebug<P>,
{
    #[sensitive(P)]
    pub value: Ipv4Addr,
    pub marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct GenericPolicyBox<P: RedactionPolicy>
where
    Box<String>: PolicyDisplay<P> + PolicyDebug<P>,
{
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    pub value: Box<String>,
    pub marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct GenericPolicyBoxAlias<P: RedactionPolicy>
where
    BoxAlias<String>: PolicyDisplay<P> + PolicyDebug<P>,
{
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    pub value: BoxAlias<String>,
    pub marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct GenericPolicyConcreteBox<P: RedactionPolicy>
where
    ConcreteBox: PolicyDisplay<P> + PolicyDebug<P>,
{
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    pub value: ConcreteBox,
    pub marker: PhantomData<P>,
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct GenericPolicyRenamedBox<P: RedactionPolicy>
where
    RenamedBox<String>: PolicyDisplay<P> + PolicyDebug<P>,
{
    #[sensitive(P)]
    #[redactable(generated_formatting)]
    pub value: RenamedBox<String>,
    pub marker: PhantomData<P>,
}

pub struct LocalLeaf<T>(pub T);

impl PolicyApplicableRef for LocalLeaf<u8> {
    type Output = String;

    fn apply_policy_ref<P, M>(&self, _mapper: &M) -> Self::Output
    where
        P: RedactionPolicy,
        P::Kind: RecursivePolicyKind,
        M: RedactableMapper,
    {
        P::policy().apply_to(&self.0.to_string())
    }
}

impl FormattingMarker for LocalLeaf<u8> {}

impl Debug for LocalLeaf<u8> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> FmtResult {
        self.0.fmt(formatter)
    }
}

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
pub struct GenericPolicyLocalLeaf<P: RedactionPolicy>
where
    P::Kind: RecursivePolicyKind,
    LocalLeaf<u8>: PolicyFieldRef<P>,
    <LocalLeaf<u8> as PolicyFieldRef<P>>::Output: RedactableWithFormatter + Debug,
{
    #[sensitive(P)]
    #[redactable(legacy_formatting)]
    pub value: LocalLeaf<u8>,
    pub marker: PhantomData<P>,
}

macro_rules! generic_policy_scalar_shape {
    ($name:ident, $ty:ty) => {
        #[derive(SensitiveDisplay)]
        #[error("{value} {value:?}")]
        pub struct $name<P: RedactionPolicy>
        where
            $ty: PolicyDisplay<P> + PolicyDebug<P>,
        {
            #[sensitive(P)]
            pub value: $ty,
            pub marker: PhantomData<P>,
        }
    };
}

generic_policy_scalar_shape!(GenericPolicyScalarAlias, Count);
generic_policy_scalar_shape!(GenericPolicyScalarRenamed, RenamedCount);
generic_policy_scalar_shape!(GenericPolicyScalarQualified, std::primitive::u32);

macro_rules! generic_policy_ip_shape {
    ($name:ident, $ty:ty) => {
        #[derive(SensitiveDisplay)]
        #[error("{value} {value:?}")]
        pub struct $name<P: RedactionPolicy>
        where
            $ty: PolicyDisplay<P> + PolicyDebug<P>,
        {
            #[sensitive(P)]
            pub value: $ty,
            pub marker: PhantomData<P>,
        }
    };
}

generic_policy_ip_shape!(GenericPolicyIpAlias, Peer);
generic_policy_ip_shape!(GenericPolicyIpRenamed, RenamedPeer);
generic_policy_ip_shape!(GenericPolicyIpQualified, std::net::Ipv4Addr);

#[derive(SensitiveDisplay)]
pub enum GenericPolicyScalarEnum<P: RedactionPolicy>
where
    Count: PolicyDisplay<P> + PolicyDebug<P>,
{
    #[error("{value} {value:?}")]
    Alias {
        #[sensitive(P)]
        value: Count,
        marker: PhantomData<P>,
    },
    #[error("{0} {0:?}")]
    Renamed(#[sensitive(P)] RenamedCount, PhantomData<P>),
}

#[derive(SensitiveDisplay)]
pub enum GenericPolicyIpEnum<P: RedactionPolicy>
where
    Peer: PolicyDisplay<P> + PolicyDebug<P>,
{
    #[error("{value} {value:?}")]
    Alias {
        #[sensitive(P)]
        value: Peer,
        marker: PhantomData<P>,
    },
    #[error("{0} {0:?}")]
    Renamed(#[sensitive(P)] RenamedPeer, PhantomData<P>),
}
