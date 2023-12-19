/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12

# PTR RDATA format

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   PTRDNAME                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

PTRDNAME        A <domain-name> which points to some location in the
                domain name space.

PTR records cause no additional section processing.  These RRs are used
in special domains to point to some other location in the domain space.
These records are simple data, and don't imply any special processing
similar to that performed by CNAME, which identifies aliases.  See the
description of the IN-ADDR.ARPA domain for an example.
 */

use super::{encode_domain_name_wrap, RDataOperation};
use crate::{dns::labels::Labels, util};
use anyhow::Error;

#[derive(Debug)]
pub struct PTR(pub String);

impl PTR {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut cname = Self { 0: "".to_string() };
        cname.decode(raw, rdata)?;

        Ok(cname)
    }
}

impl RDataOperation for PTR {
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
