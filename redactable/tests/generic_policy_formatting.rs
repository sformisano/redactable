//! Generic policy capabilities preserve concrete scalar and IP output.
use redactable::{
    PolicyDebug, PolicyDisplay, RedactableWithFormatter, Secret, SensitiveDisplay, ToRedacted,
};

#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct Generic<T: PolicyDisplay<Secret> + PolicyDebug<Secret>> {
    #[sensitive(Secret)]
    value: T,
}
#[derive(SensitiveDisplay)]
#[error("{value} {value:?}")]
struct Concrete {
    #[sensitive(Secret)]
    value: u32,
}

#[test]
fn secret_scalar_matches_concrete() {
    assert_eq!(Generic { value: 42_u32 }.to_redacted().text(), "0 0");
    assert_eq!(
        Generic { value: 42_u32 }.redacted_display().to_string(),
        Concrete { value: 42 }.redacted_display().to_string()
    );
}

#[cfg(feature = "ip-address")]
mod ip {
    use redactable::__private::PolicyField;
    use redactable::{
        IpAddress, PolicyDebug, PolicyDisplay, Redactable, RedactableWithFormatter,
        SensitiveDisplay, SensitiveDual, ToRedacted,
    };
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

    #[derive(Clone, serde::Serialize, SensitiveDual)]
    #[error("{value} {value:?}")]
    struct Generic<T: PolicyField<IpAddress> + PolicyDisplay<IpAddress> + PolicyDebug<IpAddress>> {
        #[sensitive(IpAddress)]
        value: T,
    }

    macro_rules! compare_ip {
        ($name:ident, $ty:ty, $input:expr) => {
            #[test]
            fn $name() {
                #[derive(SensitiveDisplay)]
                #[error("{value} {value:?}")]
                struct Concrete {
                    #[sensitive(IpAddress)]
                    value: $ty,
                }
                let input: $ty = $input.parse().expect("valid address");
                let generic = Generic { value: input };
                let concrete = Concrete { value: input };
                let actual = generic.redacted_display().to_string();
                assert_eq!(actual, concrete.redacted_display().to_string());
                let output = generic.to_redacted();
                assert_eq!(output.text(), actual);
                assert_eq!(
                    output.json(),
                    serde_json::to_value(generic.redact()).unwrap()
                );
                assert!(!actual.contains($input));
            }
        };
    }
    compare_ip!(ipv4, Ipv4Addr, "203.0.113.71");
    compare_ip!(ipv6, Ipv6Addr, "2001:db8:abcd:1234::71");
    compare_ip!(ip_addr, IpAddr, "203.0.113.71");
    compare_ip!(socket_addr, SocketAddr, "203.0.113.71:8443");

    #[test]
    fn socket_redaction_preserves_port() {
        let source: SocketAddr = "203.0.113.71:8443".parse().unwrap();
        let generic = Generic { value: source };
        assert!(generic.redacted_display().to_string().contains(":8443"));
        assert_eq!(generic.redact().value.port(), 8443);
    }
}
