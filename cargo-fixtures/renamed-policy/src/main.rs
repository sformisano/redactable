use std::net::{IpAddr, Ipv4Addr};

use safe::{Redactable, Sensitive};

type Amount = u64;

#[derive(Clone, Sensitive)]
struct RenamedPolicies {
    #[sensitive(safe::Secret)]
    amount: Amount,
    #[sensitive(safe::IpAddress)]
    address: IpAddr,
    #[sensitive(::safe::IpAddress)]
    v4: Ipv4Addr,
}

fn main() {
    let redacted = RenamedPolicies {
        amount: 42,
        address: "192.0.2.7".parse().unwrap(),
        v4: "192.0.2.8".parse().unwrap(),
    }
    .redact();

    assert_eq!(redacted.amount, 0);
    assert_eq!(redacted.address, "0.0.0.7".parse::<IpAddr>().unwrap());
    assert_eq!(redacted.v4, Ipv4Addr::new(0, 0, 0, 8));
}
