use super::master_file::DefaultMasterFiles;
use crate::dns::question::Questions;
use crate::dns::{Question, RcRf, VecRcRf, RR};
use crate::util;
use anyhow::{Error, Ok};
use std::collections::HashMap;

/**
- The definition of zone boundaries.

- Master files of data.

- Updates to master files.

- Statements of the refresh policies desired.
*/

pub struct Zones {
    domains: HashMap<String, DefaultMasterFiles>, // domain: MF
}

impl Zones {
    pub fn new() -> Self {
        Self {
            domains: HashMap::new(),
        }
    }

    pub fn from_dir(dir: &str) -> Result<Self, Error> {
        let mut zones = Self::new();

        let filenames = util::visit_dirs(dir)?;
        for filename in filenames {
            let mut mf = DefaultMasterFiles::new(filename.as_str());
            mf.decode()?;
            zones.domains.insert(filename, mf);
        }

        Ok(zones)
    }

    pub fn get_rr(&self, quess: &Questions) -> VecRcRf<RR> {
        let mut list = vec![];
        for ques in &quess.0 {
            let domain = ques.qname().encode_to_str();

            for (_, mf) in &self.domains {
                if let Some(rr) = mf.query(&domain) {
                    list.push(rr);
                }
            }
        }

        list
    }
}
