/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.3

# MB RDATA format (EXPERIMENTAL)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

MADNAME         A <domain-name> which specifies a host which has the
                specified mailbox.
 */

use super::RDataOperation;
use anyhow::Error;

#[derive(Debug)]
pub struct MB(String);

impl MB {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        Ok(MB {
            0: String::from_utf8(raw.to_vec())?,
        })
    }
}

impl RDataOperation for MB {
    fn decode(&self) -> Vec<Vec<u8>> {
        return vec![self.0.as_bytes().to_vec()];
    }

    fn encode(&self) -> Vec<u8> {
        return self.0.as_bytes().to_vec();
    }
}
