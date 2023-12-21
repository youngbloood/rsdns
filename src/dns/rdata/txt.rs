/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14

# TXT RDATA format
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                   TXT-DATA                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

TXT-DATA        One or more <character-string>s.

TXT RRs are used to hold descriptive text.  The semantics of the text
depends on the domain where it is found.
 */

use super::RDataOperation;
use anyhow::Error;
use std::collections::HashMap;

#[derive(Debug)]
pub struct TXT(pub String);

impl TXT {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut cname = Self { 0: "".to_string() };
        cname.decode(raw, rdata)?;

        Ok(cname)
    }
}

impl RDataOperation for TXT {
    fn decode(&mut self, _raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        self.0 = String::from_utf8(rdata.to_vec())?;

        Ok(())
    }

    fn encode(&self, _hm: &HashMap<String, usize>, _is_compressed: bool) -> Result<Vec<u8>, Error> {
        Ok(self.0.as_bytes().to_vec())
    }
}
