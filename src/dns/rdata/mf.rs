/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.5

# MF RDATA format (Obsolete)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

MADNAME         A <domain-name> which specifies a host which has a mail
                agent for the domain which will accept mail for
                forwarding to the domain.

MF records cause additional section processing which looks up an A type
record corresponding to MADNAME.

MF is obsolete.  See the definition of MX and [RFC-974] for details ofw
the new scheme.  The recommended policy for dealing with MD RRs found in
a master file is to reject them, or to convert them to MX RRs with a
preference of 10.
 */

use super::RDataOperation;
use anyhow::Error;

#[derive(Debug)]
pub struct MF(pub String);

impl MF {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        Ok(MF {
            0: String::from_utf8(raw.to_vec())?,
        })
    }
}

impl RDataOperation for MF {
    fn decode(&self) -> Vec<Vec<u8>> {
        return vec![self.0.as_bytes().to_vec()];
    }

    fn encode(&self) -> Vec<u8> {
        return self.0.as_bytes().to_vec();
    }
}
