/*!
ref: https://www.rfc-editor.org/rfc/rfc2671#section-4.4

# The variable part of an OPT RR is encoded in its RDATA and is
structured as zero or more of the following:
```shell
                +0 (MSB)                            +1 (LSB)
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  0: |                          OPTION-CODE                          |
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  2: |                         OPTION-LENGTH                         |
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
  4: |                                                               |
     /                          OPTION-DATA                          /
     /                                                               /
     +---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+---+
```

   OPTION-CODE    (Assigned by IANA.)

   OPTION-LENGTH  Size (in octets) of OPTION-DATA.

   OPTION-DATA    Varies per OPTION-CODE.
 */

use super::RDataOperation;
use crate::dns::compress_list::CompressList;
use crate::dns::rdata::ERR_RDATE_MSG;
use anyhow::anyhow;
use anyhow::Error;
use anyhow::Ok;

#[derive(Debug)]
pub struct OPT {
    pub code: u16,
    pub length: u16,
    pub data: Vec<u8>,
}

impl OPT {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut opt = Self {
            code: 0,
            length: 0,
            data: Vec::new(),
        };
        opt.decode(raw, rdata)?;

        Ok(opt)
    }
}

impl RDataOperation for OPT {
    fn decode(&mut self, _raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        if rdata.len() < 4 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        self.code = u16::from_be_bytes(rdata[..2].try_into().unwrap());
        self.length = u16::from_be_bytes(rdata[2..4].try_into().unwrap());
        self.data = rdata[4..].to_vec();

        Ok(())
    }

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        _hm: &mut CompressList,
        _is_compressed: bool,
    ) -> Result<usize, Error> {
        raw.extend(self.code.to_be_bytes());
        raw.extend(self.length.to_be_bytes());
        raw.extend(&self.data);

        Ok(2 + 2 + self.data.len())
    }
}
