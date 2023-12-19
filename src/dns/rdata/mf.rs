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

use super::{encode_domain_name_wrap, RDataOperation};
use crate::{dns::labels::Labels, util};
use anyhow::Error;

#[derive(Debug)]
pub struct MF(pub String);

impl MF {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut mf = Self { 0: "".to_string() };
        mf.decode(raw, rdata)?;

        Ok(mf)
    }
}

impl RDataOperation for MF {
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
