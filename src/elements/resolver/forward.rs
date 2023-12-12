use crate::DNS;
use anyhow::Error;

pub trait ForwardOperation {
    fn forward(&self, dns: &mut DNS) -> Result<(), Error>;
}

pub struct DF;

impl DF {
    pub fn new() -> Self {
        Self
    }
}

impl ForwardOperation for DF {
    fn forward(&self, dns: &mut DNS) -> Result<(), Error> {
        todo!()
    }
}
