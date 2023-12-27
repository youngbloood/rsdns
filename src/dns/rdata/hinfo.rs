/*！
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.2

# HINFO RDATA format
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                      CPU                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                       OS                      /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
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
use crate::dns::{compress_list::CompressList, rdata::parse_charactor_string};
use anyhow::Error;

// adapt RFC8482
// ref: https://www.rfc-editor.org/rfc/rfc8482#section-4.2
#[derive(Debug)]
pub struct HInfo {
    /// weather the HInfo is synthesized.
    ///
    /// ref: https://www.rfc-editor.org/rfc/rfc8482#section-4.2
    pub synthesized: bool,

    /// A <character-string> which specifies the CPU type.
    pub cpu: String,

    /// A <character-string> which specifies the operatins system type.
    pub os: String,
}

impl HInfo {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut hinfo = Self {
            synthesized: false,
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
        if list.len() >= 1 {
            self.synthesized = true;
            self.cpu = String::from_utf8(list.get(0).unwrap().to_vec())?;
        }
        if list.len() >= 2 {
            self.synthesized = false;
            self.os = String::from_utf8(list.get(1).unwrap().to_vec())?;
        }

        Ok(())
    }

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        _hm: &mut CompressList,
        _is_compressed: bool,
    ) -> Result<usize, Error> {
        raw.push(self.cpu.len() as u8);
        let encoded_cpu = self.cpu.as_bytes();
        raw.extend_from_slice(encoded_cpu);
        raw.push(self.os.len() as u8);
        let encoded_os = self.os.as_bytes();
        raw.extend_from_slice(encoded_os);

        Ok(1 + encoded_cpu.len() + 1 + encoded_os.len())
    }
}
