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

use super::{encode_domain_name_wrap, RDataOperation};
use crate::{dns::labels::Labels, util};
use anyhow::Error;

#[derive(Debug)]
pub struct MG(pub String);

impl MG {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut mg = Self { 0: "".to_string() };
        mg.decode(raw, rdata)?;

        Ok(mg)
    }
}

impl RDataOperation for MG {
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
