use crate::dns::ResourceRecord;
use anyhow::Error;
use std::{cell::RefCell, rc::Rc};

pub trait MasterFileCoder {
    /// get the master files
    fn calalog(&self) -> Vec<String>;

    /// decode the master files to ResourceRecord
    fn decode(&self, filename: &str) -> Result<Vec<ResourceRecord>, Error>;

    /// encode the ResourceRecords in to master file
    fn encode(&self, rrs: Vec<Rc<RefCell<ResourceRecord>>>, filename: &str) -> Result<(), Error>;
}

/**
 * Default Master Files
 */
pub struct DMF;

impl DMF {
    pub fn new() -> Self {
        Self {}
    }
}

impl MasterFileCoder for DMF {
    fn calalog(&self) -> Vec<String> {
        todo!()
    }

    fn decode(&self, filename: &str) -> Result<Vec<ResourceRecord>, Error> {
        todo!()
    }

    fn encode(&self, rrs: Vec<Rc<RefCell<ResourceRecord>>>, filename: &str) -> Result<(), Error> {
        todo!()
    }
}
