/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.6

# MG RDATA format (EXPERIMENTAL)
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MGMNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

MGMNAME         A <domain-name> which specifies a mailbox which is a
                member of the mail group specified by the domain name.

MG records cause no additional section processing.
 */

use super::{encode_domain_name_wrap, parse_domain_name, RDataOperation};
use crate::dns::compress_list::CompressList;
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
