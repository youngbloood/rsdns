use crate::dns::ResourceRecord;
use anyhow::Error;
use std::{cell::RefCell, rc::Rc};

/**
 * The Operation of Master Files
 * calalog: list the Master Files
 * decode: read the Master File and decode the content to ResourceRecords
 * encode: encode vector ResourceRecords into a file
 */
pub trait MasterFileOperation {
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
pub struct DMF {
    mf: String,
}

impl DMF {
    pub fn new() -> Self {
        Self {
            mf: "master_file".to_string(),
        }
    }
}

impl MasterFileOperation for DMF {
    fn calalog(&mut self) -> Vec<String> {
        return vec![self.mf.to_string()];
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
