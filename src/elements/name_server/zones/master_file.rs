use crate::dns::{Class, ResourceRecord, VecRcRf};
use anyhow::Error;

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
    fn decode(&mut self, filename: &str) -> Result<(Class, Vec<ResourceRecord>), Error>;

    /// encode the ResourceRecords in to master file
    fn encode(
        &mut self,
        filename: &str,
        rrs: VecRcRf<ResourceRecord>,
        class: Class,
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
        todo!()
    }

    fn decode(&mut self, filename: &str) -> Result<(Class, Vec<ResourceRecord>), Error> {
        todo!()
    }

    fn encode(
        &mut self,
        filename: &str,
        rrs: VecRcRf<ResourceRecord>,
        class: Class,
    ) -> Result<(), Error> {
        todo!()
    }
}
