use std::{collections::HashMap, net::IpAddr};

use redactable::{IpAddress, Sensitive};

type IpMap = HashMap<IpAddr, String>;

#[derive(Clone, Sensitive)]
struct Event {
    #[sensitive(IpAddress)]
    peers: IpMap,
}

fn main() {}
