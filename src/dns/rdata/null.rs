/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.10

#  NULL RDATA format (EXPERIMENTAL)
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                  <anything>                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
Anything at all may be in the RDATA field so long as it is 65535 octets
or less.

NULL records cause no additional section processing.  NULL RRs are not
allowed in master files.  NULLs are used as placeholders in some
experimental extensions of the DNS.
 */

use super::RDataOperation;
use crate::dns::compress_list::CompressList;
use anyhow::Error;

#[derive(Debug)]
pub struct Null(Vec<u8>);

impl Null {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut mr = Self { 0: vec![] };
        mr.decode(raw, rdata)?;

        Ok(mr)
    }
}

impl RDataOperation for Null {
    fn decode(&mut self, _raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        self.0 = rdata.to_vec();

        Ok(())
    }

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        _hm: &mut CompressList,
        _is_compressed: bool,
    ) -> Result<(), Error> {
        raw.extend_from_slice(&self.0.to_vec());

        Ok(())
    }
}
