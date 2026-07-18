//! Types supplied by a crate that has no dependency on `redactable`.

use std::{collections::HashMap, net::IpAddr};

pub type ClientIp = IpAddr;
pub type IpPeers = HashMap<IpAddr, String>;
