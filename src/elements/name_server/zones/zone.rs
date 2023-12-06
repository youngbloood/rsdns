use std::collections::HashMap;
use std::vec;
use std::{cell::RefCell, rc::Rc};

use anyhow::{Error, Ok};

use super::master_file::{MasterFileCoder, DMF};
use super::DomainTree;
use crate::dns::ResourceRecord;

/**
- The definition of zone boundaries.

- Master files of data.

- Updates to master files.

- Statements of the refresh policies desired.
*/

struct Zones {
    domains: HashMap<String, Rc<RefCell<DomainTree>>>,
    coder: Box<dyn MasterFileCoder>,
}

impl Zones {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
            coder: Box::new(DMF::new()),
        }
    }

    pub fn set_coder(&mut self, coder: Box<dyn MasterFileCoder>) {
        self.coder = coder;
    }

    pub fn parse_zone(&mut self) -> Result<(), Error> {
        let filenames = self.coder.calalog();
        for filename in filenames {
            let rrs = self.coder.decode(filename.as_str())?;
            let mut dt = DomainTree::new();
            for rr in rrs {
                dt.push(rr.name());
            }
            self.domains.insert(filename, Rc::new(RefCell::new(dt)));
        }

        Ok(())
    }
}
