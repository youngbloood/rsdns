/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.4

# MD RDATA format (Obsolete)
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

MADNAME         A <domain-name> which specifies a host which has a mail
                agent for the domain which should be able to deliver
                mail for the domain.

MD records cause additional section processing which looks up an A type
record corresponding to MADNAME.

MD is obsolete.  See the definition of MX and [RFC-974] for details of
the new scheme.  The recommended policy for dealing with MD RRs found in
a master file is to reject them, or to convert them to MX RRs with a
preference of 0.
 */

use super::RDataOperation;
use anyhow::Error;

#[derive(Debug)]
pub struct MD(String);

impl MD {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        Ok(MD {
            0: String::from_utf8(raw.to_vec())?,
        })
    }
}

impl RDataOperation for MD {
    fn decode(&self) -> Vec<Vec<u8>> {
        return vec![self.0.as_bytes().to_vec()];
    }

    fn encode(&self) -> Vec<u8> {
        return self.0.as_bytes().to_vec();
    }
}
