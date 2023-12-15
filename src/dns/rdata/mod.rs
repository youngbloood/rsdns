pub mod cname;
use std::fmt::Debug;

use anyhow::Error;
pub use cname::CNAME;

use super::Type;

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
        Ok(Self {
            raw,
            resource: todo!(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        return self.resource.encode();
    }
}
