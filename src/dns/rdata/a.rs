/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1

# A RDATA format

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

ADDRESS         A 32 bit Internet address.

Hosts that have multiple Internet addresses will have multiple A
records.

A records cause no additional section processing.  The RDATA section of
an A line in a master file is an Internet address expressed as four
decimal numbers separated by dots without any imbedded spaces (e.g.,
"10.2.0.52" or "192.0.5.6").
 */

use super::RDataOperation;
use crate::dns::rdata::ERR_RDATE_MSG;
use anyhow::{anyhow, Error, Ok};
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct A(pub Ipv4Addr);

impl A {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut a = Self {
            0: Ipv4Addr::new(127, 0, 0, 0),
        };
        a.decode(raw, rdata)?;

        Ok(a)
    }
}

impl RDataOperation for A {
    fn decode(&mut self, _raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        if rdata.len() < 4 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        self.0 = Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]);

        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        self.0.octets().to_vec()
    }
}
