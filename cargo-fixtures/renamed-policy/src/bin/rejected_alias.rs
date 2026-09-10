use alias_provider::IpPeers;
use safe::Sensitive;

#[derive(serde::Serialize, Clone, Sensitive)]
struct Event {
    #[sensitive(safe::IpAddress)]
    peers: IpPeers,
}

fn main() {}
