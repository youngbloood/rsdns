/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.6

# MG RDATA format (EXPERIMENTAL)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MGMNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

MGMNAME         A <domain-name> which specifies a mailbox which is a
                member of the mail group specified by the domain name.

MG records cause no additional section processing.
 */

use super::RDataOperation;
use anyhow::Error;

#[derive(Debug)]
pub struct MG(String);

impl MG {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        Ok(MG {
            0: String::from_utf8(raw.to_vec())?,
        })
    }
}

impl RDataOperation for MG {
    fn decode(&self) -> Vec<Vec<u8>> {
        return vec![self.0.as_bytes().to_vec()];
    }

    fn encode(&self) -> Vec<u8> {
        return self.0.as_bytes().to_vec();
    }
}
