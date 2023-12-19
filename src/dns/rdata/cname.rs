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

use super::{encode_domain_name_wrap, RDataOperation};
use crate::{dns::labels::Labels, util};
use anyhow::Error;

#[derive(Debug)]
pub struct CName(pub String);

impl CName {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut cname = Self { 0: "".to_string() };
        cname.decode(raw, rdata)?;

        Ok(cname)
    }
}

impl RDataOperation for CName {
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        let (mut compressed_offset, is_compressed) = util::is_compressed_wrap(rdata);
        let labels;
        if is_compressed {
            labels = Labels::from(raw, &mut compressed_offset)?;
        } else {
            let mut offset = 0_usize;
            labels = Labels::from(rdata, &mut offset)?;
        }
        self.0 = labels.encode_to_str();

        Ok(())
    }

    fn encode(&self, raw: &mut Vec<u8>, is_compressed: bool) -> Result<(), Error> {
        raw.extend_from_slice(
            &encode_domain_name_wrap(self.0.as_str(), raw, is_compressed).to_vec(),
        );

        Ok(())
    }
}
