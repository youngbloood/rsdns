use super::master_file::{MasterFileOperation, DMF};
use super::DomainTree;
use crate::dns::ResourceRecord;
use anyhow::{Error, Ok};
use std::collections::HashMap;
use std::{cell::RefCell, rc::Rc};

/**
- The definition of zone boundaries.

- Master files of data.

- Updates to master files.

- Statements of the refresh policies desired.
*/

pub struct Zones {
    domains: HashMap<String, Rc<RefCell<DomainTree>>>,
}

impl Zones {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    pub fn from(coder: Box<dyn MasterFileOperation>) -> Result<Self, Error> {
        let mut zones = Zones { domains: todo!() };
        let filenames = coder.calalog();
        for filename in filenames {
            let rrs = coder.decode(filename.as_str())?;
            let mut dt = DomainTree::new();
            for rr in rrs {
                dt.push(rr.name());
            }
            zones.domains.insert(filename, Rc::new(RefCell::new(dt)));
        }

        return Ok(zones);
    }

    pub fn parse_zone(&mut self) -> Result<(), Error> {
        let mut coder = DMF::new();
        let filenames = coder.calalog();
        for filename in filenames {
            let rrs = coder.decode(filename.as_str())?;
            let mut dt = DomainTree::new();
            for rr in rrs {
                dt.push(rr.name());
            }
            self.domains.insert(filename, Rc::new(RefCell::new(dt)));
        }

        Ok(())
    }

    pub fn get_rr(&self, domain: &str) -> Option<Rc<RefCell<ResourceRecord>>> {
        for (_, dt) in &self.domains {
            let rr = dt.borrow().get_rr(domain);
            if rr.is_some() {
                return rr;
            }
        }

        None
    }
}
