//! IP address redaction implementations for std net types.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::{
    policy::IpAddress,
    redaction::{
        redact::RedactableMapper,
        traits::{RedactableWithMapper, SensitiveWithPolicy},
    },
};

// Preserve a valid address by zeroing all but the last segment.
fn redact_ipv4(addr: Ipv4Addr) -> Ipv4Addr {
    let octets = addr.octets();
    Ipv4Addr::new(0, 0, 0, octets[3])
}

fn redact_ipv6(addr: Ipv6Addr) -> Ipv6Addr {
    let segments = addr.segments();
    Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, segments[7])
}

impl SensitiveWithPolicy<IpAddress> for Ipv4Addr {
    fn redact_with_policy(self, _policy: &crate::policy::TextRedactionPolicy) -> Self {
        redact_ipv4(self)
    }

    fn redacted_string(&self, _policy: &crate::policy::TextRedactionPolicy) -> String {
        redact_ipv4(*self).to_string()
    }
}

impl SensitiveWithPolicy<IpAddress> for Ipv6Addr {
    fn redact_with_policy(self, _policy: &crate::policy::TextRedactionPolicy) -> Self {
        redact_ipv6(self)
    }

    fn redacted_string(&self, _policy: &crate::policy::TextRedactionPolicy) -> String {
        redact_ipv6(*self).to_string()
    }
}

impl SensitiveWithPolicy<IpAddress> for IpAddr {
    fn redact_with_policy(self, _policy: &crate::policy::TextRedactionPolicy) -> Self {
        match self {
            IpAddr::V4(addr) => IpAddr::V4(redact_ipv4(addr)),
            IpAddr::V6(addr) => IpAddr::V6(redact_ipv6(addr)),
        }
    }

    fn redacted_string(&self, _policy: &crate::policy::TextRedactionPolicy) -> String {
        match self {
            IpAddr::V4(addr) => redact_ipv4(*addr).to_string(),
            IpAddr::V6(addr) => redact_ipv6(*addr).to_string(),
        }
    }
}

impl SensitiveWithPolicy<IpAddress> for SocketAddr {
    fn redact_with_policy(self, _policy: &crate::policy::TextRedactionPolicy) -> Self {
        match self {
            SocketAddr::V4(addr) => {
                SocketAddr::V4(SocketAddrV4::new(redact_ipv4(*addr.ip()), addr.port()))
            }
            SocketAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(
                redact_ipv6(*addr.ip()),
                addr.port(),
                addr.flowinfo(),
                addr.scope_id(),
            )),
        }
    }

    fn redacted_string(&self, _policy: &crate::policy::TextRedactionPolicy) -> String {
        match self {
            SocketAddr::V4(addr) => {
                SocketAddr::V4(SocketAddrV4::new(redact_ipv4(*addr.ip()), addr.port())).to_string()
            }
            SocketAddr::V6(addr) => SocketAddr::V6(SocketAddrV6::new(
                redact_ipv6(*addr.ip()),
                addr.port(),
                addr.flowinfo(),
                addr.scope_id(),
            ))
            .to_string(),
        }
    }
}

impl RedactableWithMapper for Ipv4Addr {
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        mapper.map_sensitive::<Self, IpAddress>(self)
    }
}

impl RedactableWithMapper for Ipv6Addr {
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        mapper.map_sensitive::<Self, IpAddress>(self)
    }
}

impl RedactableWithMapper for IpAddr {
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        mapper.map_sensitive::<Self, IpAddress>(self)
    }
}

impl RedactableWithMapper for SocketAddr {
    fn redact_with<M: RedactableMapper>(self, mapper: &M) -> Self {
        mapper.map_sensitive::<Self, IpAddress>(self)
    }
}
