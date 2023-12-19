/*！
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.2

# HINFO RDATA format
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                      CPU                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                       OS                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

CPU             A <character-string> which specifies the CPU type.

OS              A <character-string> which specifies the operating
                system type.

Standard values for CPU and OS can be found in [RFC-1010](https://www.rfc-editor.org/rfc/rfc1010).

HINFO records are used to acquire general information about a host.  The
main use is for protocols such as FTP that can use special procedures
when talking between machines or operating systems of the same type.
*/

use super::RDataOperation;
use crate::dns::rdata::{parse_charactor_string, ERR_RDATE_MSG};
use anyhow::{anyhow, Error};

#[derive(Debug)]
pub struct HInfo {
    /// A <character-string> which specifies the CPU type.
    pub cpu: String,

    /// A <character-string> which specifies the operatins system type.
    pub os: String,
}

impl HInfo {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut hinfo = Self {
            cpu: "".to_string(),
            os: "".to_string(),
        };
        hinfo.decode(raw, rdata)?;

        Ok(hinfo)
    }
}

impl RDataOperation for HInfo {
    fn decode(&mut self, _raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        let list = parse_charactor_string(rdata)?;
        if list.len() < 2 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        self.cpu = String::from_utf8(list.get(0).unwrap().to_vec())?;
        self.os = String::from_utf8(list.get(1).unwrap().to_vec())?;

        Ok(())
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = self.cpu.as_bytes().to_vec();
        v.extend_from_slice(self.os.as_bytes());

        v
    }
}
