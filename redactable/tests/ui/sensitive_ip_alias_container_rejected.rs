use std::{collections::HashMap, net::IpAddr};

use redactable::{IpAddress, Sensitive};

type IpMap = HashMap<IpAddr, String>;

#[derive(serde::Serialize, Clone, Sensitive)]
struct Event {
    #[sensitive(IpAddress)]
    peers: IpMap,
}

fn main() {}
