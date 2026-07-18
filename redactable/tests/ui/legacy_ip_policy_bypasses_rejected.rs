use std::{collections::HashMap, net::IpAddr};

use redactable::{
    IpAddress, PolicyApplicable, PolicyApplicableRef,
    __private::PolicyMapper,
    apply_policy, apply_policy_ref,
};

type IpMap = HashMap<IpAddr, String>;

fn consuming_free_function(value: IpMap) {
    let _ = apply_policy::<IpAddress, _>(value);
}

fn reference_free_function(value: &IpMap) {
    let _ = apply_policy_ref::<IpAddress, _>(value);
}

fn consuming_direct_method(value: IpMap) {
    let _ = PolicyApplicable::apply_policy::<IpAddress, _>(value, &PolicyMapper);
}

fn reference_direct_method(value: &IpMap) {
    let _ = PolicyApplicableRef::apply_policy_ref::<IpAddress, _>(value, &PolicyMapper);
}

fn main() {}
