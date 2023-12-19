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

use anyhow::Error;

use crate::dns::rdata::parse_charactor_string;

use super::RDataOperation;

#[derive(Debug)]
pub struct HInfo {
    /// A <character-string> which specifies the CPU type.
    pub cpu: String,

    /// A <character-string> which specifies the operatins system type.
    pub os: String,
}

impl HInfo {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        let list = parse_charactor_string(raw)?;
        let mut hinfo = HInfo {
            cpu: "".to_string(),
            os: "".to_string(),
        };
        if list.len() < 2 {
            return Err(Error::msg("not completed hinfo"));
        }
        hinfo.cpu = String::from_utf8(list.get(0).unwrap().to_vec())?;
        hinfo.os = String::from_utf8(list.get(1).unwrap().to_vec())?;

        return Ok(hinfo);
    }
}

impl RDataOperation for HInfo {
    fn decode(&self) -> Vec<Vec<u8>> {
        return vec![self.cpu.as_bytes().to_vec(), self.os.as_bytes().to_vec()];
    }

    fn encode(&self) -> Vec<u8> {
        let mut v = self.cpu.as_bytes().to_vec();
        v.extend_from_slice(self.os.as_bytes());
        return v;
    }
}
