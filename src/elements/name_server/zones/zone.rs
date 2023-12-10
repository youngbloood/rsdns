use super::domain_tree::ClassDomainTreeUnion;
use super::master_file::{MasterFileOperation, DMF};
use super::DomainTree;
use crate::dns::{Question, RcRf, ResourceRecord};
use anyhow::{Error, Ok};
use std::borrow::BorrowMut;
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
            let (class, mut _rrs) = coder.decode(filename.as_str())?;
            let mut dt = DomainTree::new();

            let mut rrs = _rrs.into_iter();
            let mut rr = rrs.next();
            while rr.is_some() {
                dt.push(rr.as_ref().unwrap().name());
                // TODO: set_rr
                // dt.set_rr(name, Rc::new(RefCell::new(rr.take().unwrap())));
                rr = rrs.next();
            }

            // for i in rrs.len() - 1..0 {
            //     let rr = rrs.as_mut_slice().get(i).unwrap();
            //     dt.push(&rr.name());
            //     dt.set_rr(&rr.name(), Rc::new(RefCell::new(rrs.pop().unwrap())));
            // }

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

    pub fn get_rr(&self, ques: &Question) -> Option<RcRf<ResourceRecord>> {
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
