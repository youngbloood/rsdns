use super::zones::DomainTree;
use crate::dns::ResourceRecord;
use std::{cell::RefCell, rc::Rc};

/**
  The domain system provides:
  - Standard formats for resource data.
  - Standard methods for querying the database.
  - Standard methods for name servers to refresh local data from
    foreign name servers.
*/
struct NameServer {
    id: u8, // identifier of NameServer
    peers: Vec<Rc<RefCell<NameServer>>>,
    zones: Vec<Rc<RefCell<DomainTree>>>,
}

impl NameServer {
    pub fn find(&self, domain: &str, r: bool) -> Option<Rc<RefCell<ResourceRecord>>> {
        return self.find_cycle(domain, r, 0);
    }

    fn find_cycle(
        &self,
        domain: &str,
        r: bool,
        from_id: u8,
    ) -> Option<Rc<RefCell<ResourceRecord>>> {
        for zone in &self.zones {
            let rr = zone.borrow().get_rr(domain);
            if rr.is_some() {
                return rr;
            }
        }

        // avoid the cycle invoke
        if self.id == from_id {
            return None;
        }

        for peer in &self.peers {
            let rr = peer.borrow().find_cycle(domain, r, self.id);
            if rr.is_some() {
                return rr;
            }
        }

        return None;
    }
}
