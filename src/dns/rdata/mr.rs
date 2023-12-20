/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.8

# MR RDATA format (EXPERIMENTAL)
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   NEWNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

NEWNAME         A <domain-name> which specifies a mailbox which is the
                proper rename of the specified mailbox.

MR records cause no additional section processing.  The main use for MR
is as a forwarding entry for a user who has moved to a different
mailbox.
 */

use super::{encode_domain_name_wrap, parse_domain_name, RDataOperation};
use anyhow::Error;

#[derive(Debug)]
pub struct MR(pub String);

impl MR {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut mr = Self { 0: "".to_string() };
        mr.decode(raw, rdata)?;

        Ok(mr)
    }
}

impl RDataOperation for MR {
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        self.0 = parse_domain_name(raw, rdata)?
            .get(0)
            .unwrap()
            .encode_to_str();

        Ok(())
    }

    fn encode(&self, raw: &mut Vec<u8>, is_compressed: bool) -> Result<(), Error> {
        raw.extend_from_slice(
            &encode_domain_name_wrap(self.0.as_str(), raw, is_compressed).to_vec(),
        );

        Ok(())
    }
}
