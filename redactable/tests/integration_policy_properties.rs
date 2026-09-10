//! Properties of the documented policy choices, including permitted empty outputs.

#![cfg(feature = "policy")]

use proptest::{
    arbitrary::any,
    collection::vec,
    prop_assert, prop_assert_eq, prop_oneof, proptest,
    strategy::{Just, Strategy},
    test_runner::Config,
};
use redactable::{KeepConfig, MaskConfig, TextRedactionPolicy};

fn spans() -> impl Strategy<Value = usize> {
    prop_oneof![0usize..80, Just(usize::MAX)]
}

proptest! {
    #![proptest_config(Config { cases: 128, failure_persistence: None, ..Config::default() })]

    #[test]
    fn keep_preserves_only_selected_unicode_scalar_positions(
        chars in vec(any::<char>(), 1..65), prefix in spans(), suffix in spans(), mask in any::<char>(),
    ) {
        let input: String = chars.iter().collect();
        let output = TextRedactionPolicy::keep_with(KeepConfig::both(prefix, suffix))
            .with_mask_char(mask).apply_to(&input);
        let rendered: Vec<char> = output.chars().collect();
        prop_assert_eq!(rendered.len(), chars.len());
        // Compare positions against the mathematical keep window, independent
        // of the implementation's mutable slices and saturating addition.
        let covers_all = prefix as u128 + suffix as u128 >= chars.len() as u128;
        for (index, original) in chars.iter().enumerate() {
            let retained = !covers_all && (index < prefix || chars.len() - index <= suffix);
            prop_assert_eq!(rendered[index], if retained { *original } else { mask });
        }
    }

    #[test]
    fn mask_changes_only_selected_unicode_scalar_positions(
        chars in vec(any::<char>(), 1..65), prefix in spans(), suffix in spans(), mask in any::<char>(),
    ) {
        let input: String = chars.iter().collect();
        let output = TextRedactionPolicy::mask_with(MaskConfig::both(prefix, suffix))
            .with_mask_char(mask).apply_to(&input);
        let rendered: Vec<char> = output.chars().collect();
        prop_assert_eq!(rendered.len(), chars.len());
        for (index, original) in chars.iter().enumerate() {
            let selected = index < prefix || chars.len() - index <= suffix;
            prop_assert_eq!(rendered[index], if selected { mask } else { *original });
        }
    }

    #[test]
    fn short_keep_windows_and_overflow_spans_fully_mask(
        chars in vec(any::<char>(), 1..33), extra in 0usize..80,
    ) {
        let input: String = chars.iter().collect();
        let expected = "*".repeat(chars.len());
        for policy in [
            TextRedactionPolicy::keep_first(chars.len() + extra),
            TextRedactionPolicy::keep_last(chars.len() + extra),
            TextRedactionPolicy::keep_with(KeepConfig::both(usize::MAX, usize::MAX)),
            TextRedactionPolicy::mask_with(MaskConfig::both(usize::MAX, usize::MAX)),
        ] {
            prop_assert_eq!(policy.apply_to(&input), expected.as_str());
        }
    }

    #[test]
    fn email_preserves_domain_after_last_separator_and_masks_local_scalars(
        local_chars in vec(any::<char>(), 0..40), domain in "[a-z]{0,12}", prefix in spans(),
    ) {
        let local: String = local_chars.iter().collect();
        let input = format!("{local}@{domain}");
        let output = TextRedactionPolicy::email_local(prefix).apply_to(&input);
        let expected_domain = format!("@{domain}");
        prop_assert!(output.ends_with(&expected_domain));
        let rendered: Vec<_> = output[..output.len() - expected_domain.len()].chars().collect();
        prop_assert_eq!(rendered.len(), local_chars.len());
        for (index, original) in local_chars.iter().enumerate() {
            let retained = prefix < local_chars.len() && index < prefix;
            prop_assert_eq!(rendered[index], if retained { *original } else { '*' });
        }
    }

    #[test]
    fn email_without_separator_uses_the_documented_prefix_window(
        chars in vec(any::<char>(), 0..40), prefix in spans(),
    ) {
        let chars: Vec<_> = chars.into_iter().filter(|ch| *ch != '@').collect();
        let input: String = chars.iter().collect();
        let output = TextRedactionPolicy::email_local(prefix).apply_to(&input);
        if chars.is_empty() {
            prop_assert_eq!(output, "[REDACTED]");
        } else {
            let rendered: Vec<_> = output.chars().collect();
            prop_assert_eq!(rendered.len(), chars.len());
            for (index, original) in chars.iter().enumerate() {
                let retained = prefix < chars.len() && index < prefix;
                prop_assert_eq!(rendered[index], if retained { *original } else { '*' });
            }
        }
    }

    #[test]
    fn custom_full_returns_exact_caller_placeholder_for_every_input(
        input in vec(any::<char>(), 0..50), placeholder in vec(any::<char>(), 0..50), mask in any::<char>(),
    ) {
        let input: String = input.into_iter().collect();
        let placeholder: String = placeholder.into_iter().collect();
        let policy = TextRedactionPolicy::full_with(placeholder.clone()).with_mask_char(mask);
        prop_assert_eq!(policy.apply_to(&input), placeholder);
    }
}

#[test]
fn unicode_short_email_and_custom_empty_boundaries_are_explicit() {
    assert_eq!(
        TextRedactionPolicy::keep_last(1).apply_to("e\u{301}"),
        "*\u{301}"
    );
    assert_eq!(
        TextRedactionPolicy::mask_first(1).apply_to("\u{1f469}\u{200d}\u{1f4bb}"),
        "*\u{200d}\u{1f4bb}"
    );
    assert_eq!(
        TextRedactionPolicy::email_local(2).apply_to("\"a@b\"@domain"),
        "\"a***@domain"
    );
    assert_eq!(
        TextRedactionPolicy::email_local(usize::MAX).apply_to("@domain"),
        "@domain"
    );
    assert_eq!(
        TextRedactionPolicy::email_local(2).apply_to("ab@domain"),
        "**@domain"
    );
    assert_eq!(TextRedactionPolicy::full_with("").apply_to("secret"), "");
    assert_eq!(TextRedactionPolicy::full_with("").apply_to(""), "");
    assert_eq!(
        TextRedactionPolicy::mask_first(0).apply_to("public"),
        "public"
    );
    for policy in [
        TextRedactionPolicy::keep_first(0),
        TextRedactionPolicy::mask_last(0),
        TextRedactionPolicy::email_local(0),
        TextRedactionPolicy::default_full(),
    ] {
        assert_eq!(policy.apply_to(""), "[REDACTED]");
    }
}

#[cfg(feature = "ip-address")]
mod ip {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};

    use proptest::{arbitrary::any, prop_assert_eq, proptest, test_runner::Config};
    use redactable::{IpAddress, RedactionPolicy, SensitiveWithPolicy};

    proptest! {
        #![proptest_config(Config { cases: 128, failure_persistence: None, ..Config::default() })]

        #[test]
        fn typed_ipv4_preserves_only_last_octet(octets in any::<[u8;4]>()) {
            let address = Ipv4Addr::from(octets);
            let redacted = address.redact_with_policy(&IpAddress::policy());
            prop_assert_eq!(redacted.octets(), [0,0,0,octets[3]]);
            prop_assert_eq!(address.redacted_string(&IpAddress::policy()), Ipv4Addr::new(0,0,0,octets[3]).to_string());
        }

        #[test]
        fn native_ipv6_preserves_only_final_segment(mut segments in any::<[u16;8]>()) {
            // A nonzero first segment makes this an ordinary, non-mapped address.
            segments[0] |= 1;
            let address = Ipv6Addr::from(segments);
            let redacted = address.redact_with_policy(&IpAddress::policy());
            prop_assert_eq!(redacted.segments(), [0,0,0,0,0,0,0,segments[7]]);
        }

        #[test]
        fn mapped_ipv6_uses_ipv4_rule_and_retains_socket_metadata(
            octets in any::<[u8;4]>(), port in any::<u16>(), flow in any::<u32>(), scope in any::<u32>(),
        ) {
            let address = Ipv4Addr::from(octets).to_ipv6_mapped();
            let socket = SocketAddr::V6(SocketAddrV6::new(address, port, flow, scope));
            let expected_ip = Ipv4Addr::new(0,0,0,octets[3]).to_ipv6_mapped();
            prop_assert_eq!(address.redact_with_policy(&IpAddress::policy()), expected_ip);
            let expected_socket = SocketAddr::V6(SocketAddrV6::new(expected_ip,port,flow,scope));
            prop_assert_eq!(socket.redact_with_policy(&IpAddress::policy()), expected_socket);
            prop_assert_eq!(socket.redacted_string(&IpAddress::policy()), expected_socket.to_string());
        }
    }
}
