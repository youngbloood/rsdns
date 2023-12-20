/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.3

# MB RDATA format (EXPERIMENTAL)
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   MADNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

MADNAME         A <domain-name> which specifies a host which has the
                specified mailbox.
 */

use super::{encode_domain_name_wrap, parse_domain_name, RDataOperation};
use anyhow::Error;

#[derive(Debug)]
pub struct MB(pub String);

impl MB {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut mb = Self { 0: "".to_string() };
        mb.decode(raw, rdata)?;

        Ok(mb)
    }
}

impl RDataOperation for MB {
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
