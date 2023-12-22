/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.4

# MD RDATA format (Obsolete)
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
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

use super::{encode_domain_name_wrap, parse_domain_name, RDataOperation};
use crate::dns::compress_list::CompressList;
use anyhow::Error;

#[derive(Debug)]
pub struct MD(pub String);

impl MD {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut md = Self { 0: "".to_string() };
        md.decode(raw, rdata)?;

        Ok(md)
    }
}

impl RDataOperation for MD {
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        self.0 = parse_domain_name(raw, rdata)?
            .get(0)
            .unwrap()
            .encode_to_str();

        Ok(())
    }

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        cl: &mut CompressList,
        is_compressed: bool,
    ) -> Result<(), Error> {
        raw.extend_from_slice(&encode_domain_name_wrap(
            self.0.as_str(),
            cl,
            is_compressed,
            raw.len(),
        )?);

        Ok(())
    }
}
