/*！
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1

# CNAME RDATA format
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     CNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

CNAME           A <domain-name> which specifies the canonical or primary
                name for the owner.  The owner name is an alias.

CNAME RRs cause no additional section processing, but name servers may
choose to restart the query at the canonical name in certain cases.  See
the description of name server logic in [RFC-1034] for details.
*/

use super::{encode_domain_name_wrap, parse_domain_name, RDataOperation};
use crate::dns::compress_list::CompressList;
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
