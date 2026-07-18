use alias_provider::IpPeers;
use safe::Sensitive;

#[derive(Clone, Sensitive)]
struct Event {
    #[sensitive(safe::IpAddress)]
    peers: IpPeers,
}

fn main() {}
