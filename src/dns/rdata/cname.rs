use anyhow::Error;

use super::RDataOperation;

/*！
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1

# CNAME RDATA format
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     CNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

CNAME           A <domain-name> which specifies the canonical or primary
                name for the owner.  The owner name is an alias.

CNAME RRs cause no additional section processing, but name servers may
choose to restart the query at the canonical name in certain cases.  See
the description of name server logic in [RFC-1034] for details.
*/

#[derive(Debug)]
pub struct CNAME(String);

impl CNAME {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        Ok(CNAME {
            0: String::from_utf8(raw.to_vec())?,
        })
    }
}

impl RDataOperation for CNAME {
    fn decode(&self) -> Vec<String> {
        return vec![self.0.clone()];
    }

    fn encode(&self) -> Vec<u8> {
        return self.0.clone().into_bytes();
    }
}
