use super::domain_tree::ClassDomainTreeUnion;
use super::master_file::{MasterFileOperation, DMF};
use super::DomainTree;
use crate::dns::{Question, ResourceRecord};
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
    domains: HashMap<String, ClassDomainTreeUnion>,
}

impl Zones {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    pub fn from(mut coder: Box<dyn MasterFileOperation>) -> Result<Self, Error> {
        let mut zones = Zones {
            domains: HashMap::new(),
        };
        let filenames = coder.calalog();
        for filename in filenames {
            let (class, rrs) = coder.decode(filename.as_str())?;
            let mut dt = DomainTree::new();
            for rr in rrs {
                dt.push(rr.name());
            }

            zones
                .domains
                .insert(filename, (class, Rc::new(RefCell::new(dt))));
        }

        return Ok(zones);
    }

    pub fn parse_zone(&mut self) -> Result<(), Error> {
        let mut coder = DMF::new();
        let filenames = coder.calalog();
        for filename in filenames {
            let (class, rrs) = coder.decode(filename.as_str())?;
            let mut dt = DomainTree::new();
            for rr in rrs {
                dt.push(rr.name());
            }

            self.domains
                .insert(filename, (class, Rc::new(RefCell::new(dt))));
        }

        Ok(())
    }

    pub fn get_rr(&self, ques: &Question) -> Option<Rc<RefCell<ResourceRecord>>> {
        let domain = ques.qname().encode_to_str();

        for (_, (class, dt)) in &self.domains {
            if ques.qclass().ne(class) {
                continue;
            }
            let rr = dt.borrow().get_rr(domain.as_str());
            if rr.is_some() {
                return rr;
            }
        }

        None
    }
}
