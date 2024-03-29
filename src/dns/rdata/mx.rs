/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9

# MX RDATA format
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                  PREFERENCE                   |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   EXCHANGE                    /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

PREFERENCE      A 16 bit integer which specifies the preference given to
                this RR among others at the same owner.  Lower values
                are preferred.

EXCHANGE        A <domain-name> which specifies a host willing to act as
                a mail exchange for the owner name.

MX records cause type A additional section processing for the host
specified by EXCHANGE.  The use of MX RRs is explained in detail in
[RFC-974].
 */

use super::{encode_domain_name_wrap, parse_domain_name_without_len, RDataOperation};
use crate::dns::compress_list::CompressList;
use anyhow::Error;

#[derive(Debug, PartialEq, Eq)]
pub struct MX {
    pub preference: u16,
    pub exchange: String,
}

impl MX {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut mr = Self {
            preference: 0,
            exchange: "".to_string(),
        };
        mr.decode(raw, rdata)?;

        Ok(mr)
    }
}

impl RDataOperation for MX {
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        self.preference = u16::from_be_bytes(rdata[..2].try_into().expect("get preference failed"));
        self.exchange = parse_domain_name_without_len(raw, &rdata[2..])?
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
    ) -> Result<usize, Error> {
        raw.extend_from_slice(&self.preference.to_be_bytes());
        let encoded_exchange =
            encode_domain_name_wrap(self.exchange.as_str(), cl, is_compressed, raw.len())?;
        raw.extend_from_slice(&encoded_exchange);

        Ok(2 + encoded_exchange.len())
    }
}
