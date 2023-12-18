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

use anyhow::{Error, Ok};

use super::RDataOperation;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct A(Ipv4Addr);

impl A {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        let a = A { 0: todo!() };
        Ok(a)
    }
}
impl RDataOperation for A {
    fn decode(&self) -> Vec<Vec<u8>> {
        return vec![self.0.octets().to_vec()];
    }

    fn encode(&self) -> Vec<u8> {
        return self.0.octets().to_vec();
    }
}
