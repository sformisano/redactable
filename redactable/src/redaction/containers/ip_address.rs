//! IP address redaction implementations for std net types.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use crate::{
    policy::IpAddress,
    redaction::{
        display::RedactableWithFormatter,
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
    // Dual-stack listeners commonly observe IPv4 clients as IPv4-mapped IPv6
    // addresses (::ffff:a.b.c.d). The last 16-bit segment of those holds the
    // last TWO octets of the embedded IPv4, so redact the embedded address
    // with the IPv4 rule (keep only the final octet) instead.
    if let Some(v4) = addr.to_ipv4_mapped() {
        return redact_ipv4(v4).to_ipv6_mapped();
    }
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
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl RedactableWithMapper for Ipv6Addr {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl RedactableWithMapper for IpAddr {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl RedactableWithMapper for SocketAddr {
    fn redact_with<M: RedactableMapper>(self, _mapper: &M) -> Self {
        self
    }
}

impl RedactableWithFormatter for Ipv4Addr {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl RedactableWithFormatter for Ipv6Addr {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl RedactableWithFormatter for IpAddr {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

impl RedactableWithFormatter for SocketAddr {
    fn fmt_redacted(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    use super::*;
    use crate::policy::{IpAddress, RedactionPolicy};

    #[test]
    fn ipv4_keeps_only_last_octet() {
        let addr = Ipv4Addr::new(203, 0, 113, 77);
        let redacted = addr.redact_with_policy(&IpAddress::policy());
        assert_eq!(redacted, Ipv4Addr::new(0, 0, 0, 77));
    }

    #[test]
    fn ipv6_keeps_only_last_segment() {
        let addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0xabcd, 0x1234);
        let redacted = addr.redact_with_policy(&IpAddress::policy());
        assert_eq!(redacted, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0x1234));
    }

    #[test]
    fn ipv4_mapped_ipv6_redacts_like_ipv4() {
        // ::ffff:203.0.113.77 - the standard dual-stack representation of an
        // IPv4 client. The last v6 segment holds TWO IPv4 octets, so applying
        // the plain v6 rule would leak twice as much as the v4 rule.
        let addr = Ipv4Addr::new(203, 0, 113, 77).to_ipv6_mapped();
        let redacted = addr.redact_with_policy(&IpAddress::policy());
        assert_eq!(redacted, Ipv4Addr::new(0, 0, 0, 77).to_ipv6_mapped());
    }

    #[test]
    fn socket_addr_v6_redacts_mapped_ip_and_keeps_port() {
        let addr = SocketAddr::V6(SocketAddrV6::new(
            Ipv4Addr::new(203, 0, 113, 77).to_ipv6_mapped(),
            8443,
            0,
            0,
        ));
        let redacted = addr.redact_with_policy(&IpAddress::policy());
        let SocketAddr::V6(redacted) = redacted else {
            panic!("variant must be preserved");
        };
        assert_eq!(*redacted.ip(), Ipv4Addr::new(0, 0, 0, 77).to_ipv6_mapped());
        assert_eq!(redacted.port(), 8443);
    }
}
