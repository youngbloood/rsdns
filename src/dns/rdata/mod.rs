pub mod cname;
use std::fmt::Debug;

use anyhow::Error;
pub use cname::CNAME;

use super::{Type, TYPE_A, TYPE_CNAME};

pub trait RDataOperation: Debug {
    fn decode(&self) -> Vec<String>;
    fn encode(&self) -> Vec<u8>;
}

#[derive(Debug)]
pub struct RData {
    raw: Vec<u8>,
    resource: Box<dyn RDataOperation>,
}

impl RData {
    pub fn new() -> Self {
        Self {
            raw: todo!(),
            resource: todo!(),
        }
    }

    pub fn with_resource(&mut self, resource: Box<dyn RDataOperation>) {
        self.resource = resource;
    }

    pub fn from(raw: Vec<u8>, typ: Type) -> Result<Self, Error> {
        let mut rdata = Self {
            raw,
            resource: todo!(),
        };

        match typ {
            TYPE_CNAME => {
                let cname = CNAME::from(&raw.to_vec());
                if cname.is_err() {
                    return Err(cname.err().unwrap());
                }
                rdata.resource = Box::new(cname.unwrap());
            }
            _ => todo!(),
        }

        Err(Error::msg("todo"))
    }

    pub fn encode(&self) -> Vec<u8> {
        return self.resource.encode();
    }
}
