use super::*;

#[test]
fn applies_custom_policy() {
    #[derive(Clone, Copy)]
    struct CustomCreditCard;

    impl RedactionPolicy for CustomCreditCard {
        type Kind = TextPolicyKind;

        fn policy() -> TextRedactionPolicy {
            TextRedactionPolicy::keep_last(4).with_mask_char('X')
        }
    }

    #[derive(Clone, Sensitive, Serialize)]
    struct Payment {
        #[sensitive(CustomCreditCard)]
        card_number: String,
        amount: f64,
    }

    let payment = Payment {
        card_number: "4111111111111111".into(),
        amount: 99.99,
    };

    let redacted = payment.slog_redacted_json();
    let mut serializer = CapturingSerializer::new();
    serialize_to_capture(&redacted, "payment", &mut serializer);

    if let Some(CapturedValue::Serde(json)) = serializer.get("payment") {
        let card = json["card_number"].as_str().unwrap();
        assert_eq!(card, "XXXXXXXXXXXX1111");
        assert_eq!(json["amount"], 99.99);
    } else {
        panic!("Expected Serde value");
    }
}
