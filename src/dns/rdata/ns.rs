/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11

# NS RDATA format
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   NSDNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

NSDNAME         A <domain-name> which specifies a host which should be
                authoritative for the specified class and domain.

NS records cause both the usual additional section processing to locate
a type A record, and, when used in a referral, a special search of the
zone in which they reside for glue information.

The NS RR states that the named host should be expected to have a zone
starting at owner name of the specified class.  Note that the class may
not indicate the protocol family which should be used to communicate
with the host, although it is typically a strong hint.  For example,
hosts which are name servers for either Internet (IN) or Hesiod (HS)
class information are normally queried using IN class protocols.
 */

use super::{encode_domain_name_wrap, parse_domain_name, RDataOperation};
use crate::dns::compress_list::CompressList;
use anyhow::Error;

#[derive(Debug)]
pub struct NS(pub String);

impl NS {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut cname = Self { 0: "".to_string() };
        cname.decode(raw, rdata)?;

        Ok(cname)
    }
}

impl RDataOperation for NS {
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
