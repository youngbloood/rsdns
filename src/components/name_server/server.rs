use super::zones::{zone::Zones, DefaultZones, ZonesOperation};
use crate::{dns::VecRcRf, DNS};
use std::{cell::RefCell, rc::Rc};

/**
  The domain system provides:
  - Standard formats for resource data.
  - Standard methods for querying the database.
  - Standard methods for name servers to refresh local data from
    foreign name servers.
*/
pub struct NameServer {
    protocol: String,
    port: String,
    zones: VecRcRf<Zones>,
}

impl NameServer {
    pub fn new() -> Self {
        let mut ns = NameServer {
            zones: vec![],
            protocol: "udp".to_string(),
            port: "53".to_string(),
        };

        let zones: Vec<Zones> = DefaultZones::new().calalog_zones();
        for zone in zones {
            ns.zones.push(Rc::new(RefCell::new(zone)));
        }

        ns
    }

    pub fn from(mut zoneser: Box<dyn ZonesOperation>) -> Self {
        let mut ns = NameServer {
            zones: vec![],
            protocol: String::new(),
            port: "53".to_string(),
        };
        let zones = zoneser.calalog_zones();
        for zone in zones {
            ns.zones.push(Rc::new(RefCell::new(zone)));
        }
        return ns;
    }

    pub async fn query(&self, dns_packet: &DNS) -> DNS {
        let mut new_dns = DNS::new();
        for ques in &dns_packet.ques().0 {
            new_dns.with_ques(
                ques.qname().encode_to_str().as_str(),
                ques.qtype(),
                ques.qclass(),
            )
        }

        let mut rrs = vec![];
        for zone in &self.zones {
            rrs.extend(zone.clone().borrow().get_rr(dns_packet.ques()))
        }
        for rr in rrs {
            new_dns.with_additional(rr.clone())
        }

        return new_dns;
    }
}

// impl NameServerOperation for NameServer {
//     fn find(&mut self, ques: &Question) -> Option<RcRf<RR>> {
//         for zone in &self.zones {
//             let rr = zone.borrow().get_rr(ques);
//             if rr.is_some() {
//                 return rr;
//             }
//         }

//         return None;
//     }
// }
