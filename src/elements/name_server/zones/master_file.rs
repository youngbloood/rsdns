use crate::dns::ResourceRecord;
use anyhow::Error;
use std::{cell::RefCell, rc::Rc};

pub trait MasterFileCoder {
    /// get the master files
    fn calalog(&mut self) -> Vec<String>;

    /// decode the master files to ResourceRecord
    fn decode(&mut self, filename: &str) -> Result<Vec<ResourceRecord>, Error>;

    /// encode the ResourceRecords in to master file
    fn encode(
        &mut self,
        rrs: Vec<Rc<RefCell<ResourceRecord>>>,
        filename: &str,
    ) -> Result<(), Error>;
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
    fn calalog(&mut self) -> Vec<String> {
        todo!()
    }

    fn decode(&mut self, filename: &str) -> Result<Vec<ResourceRecord>, Error> {
        todo!()
    }

    fn encode(
        &mut self,
        rrs: Vec<Rc<RefCell<ResourceRecord>>>,
        filename: &str,
    ) -> Result<(), Error> {
        todo!()
    }
}
