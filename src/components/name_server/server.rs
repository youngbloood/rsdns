use super::{
    zones::{zone::Zones, DefaultZones, ZonesOperation},
    NameServerOperation,
};
use crate::dns::{Question, RcRf, VecRcRf, RR};
use std::{cell::RefCell, rc::Rc};

/**
  The domain system provides:
  - Standard formats for resource data.
  - Standard methods for querying the database.
  - Standard methods for name servers to refresh local data from
    foreign name servers.
*/
pub struct NameServer {
    zones: VecRcRf<Zones>,
}

impl NameServer {
    pub fn new() -> Self {
        let mut ns = NameServer { zones: vec![] };
        let zones = DefaultZones::new().calalog_zones();
        for zone in zones {
            ns.zones.push(Rc::new(RefCell::new(zone)));
        }
        return ns;
    }

    pub fn from(mut zoneser: Box<dyn ZonesOperation>) -> Self {
        let mut ns = NameServer { zones: vec![] };
        let zones = zoneser.calalog_zones();
        for zone in zones {
            ns.zones.push(Rc::new(RefCell::new(zone)));
        }
        return ns;
    }
}

impl NameServerOperation for NameServer {
    fn find(&mut self, ques: &Question) -> Option<RcRf<RR>> {
        for zone in &self.zones {
            let rr = zone.borrow().get_rr(ques);
            if rr.is_some() {
                return rr;
            }
        }

        return None;
    }
}
