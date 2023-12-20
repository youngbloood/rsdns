/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13

# SOA RDATA format
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     MNAME                     /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                     RNAME                     /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    SERIAL                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    REFRESH                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                     RETRY                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    EXPIRE                     |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    MINIMUM                    |
    |                                               |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

MNAME           The <domain-name> of the name server that was the
                original or primary source of data for this zone.

RNAME           A <domain-name> which specifies the mailbox of the
                person responsible for this zone.

SERIAL          The unsigned 32 bit version number of the original copy
                of the zone.  Zone transfers preserve this value.  This
                value wraps and should be compared using sequence space
                arithmetic.

REFRESH         A 32 bit time interval before the zone should be
                refreshed.

RETRY           A 32 bit time interval that should elapse before a
                failed refresh should be retried.

EXPIRE          A 32 bit time value that specifies the upper limit on
                the time interval that can elapse before the zone is no
                longer authoritative.


MINIMUM         The unsigned 32 bit minimum TTL field that should be
                exported with any RR from this zone.

SOA records cause no additional section processing.

All times are in units of seconds.

Most of these fields are pertinent only for name server maintenance
operations.  However, MINIMUM is used in all query operations that
retrieve RRs from a zone.  Whenever a RR is sent in a response to a
query, the TTL field is set to the maximum of the TTL field from the RR
and the MINIMUM field in the appropriate SOA.  Thus MINIMUM is a lower
bound on the TTL field for all RRs in a zone.  Note that this use of
MINIMUM should occur when the RRs are copied into the response and not
when the zone is loaded from a master file or via a zone transfer.  The
reason for this provison is to allow future dynamic update facilities to
change the SOA RR with known semantics.
 */

use super::{encode_domain_name_wrap, parse_domain_name, RDataOperation};
use crate::dns::rdata::ERR_RDATE_MSG;
use anyhow::{anyhow, Error, Ok};

#[derive(Debug)]
pub struct SOA {
    /// The <domain-name> of the name server that was the original or primary source of data for this zone.
    pub mname: String,

    /// A <domain-name> which specifies the mailbox of the person responsible for this zone.
    pub rname: String,

    /// The unsigned 32 bit version number of the original copy of the zone.  
    /// Zone transfers preserve this value.
    /// This value wraps and should be compared using sequence space arithmetic.
    pub serial: u32,

    /// A 32 bit time interval before the zone should be refreshed.
    pub refresh: u32,

    /// A 32 bit time interval that should elapse before a failed refresh should be retried.
    pub retry: u32,

    /// A 32 bit time value that specifies the upper limit on the time interval that can elapse before the zone is no longer authoritative.
    pub expire: u32,

    ///  The unsigned 32 bit minimum TTL field that should be exported with any RR from this zone.
    pub minimum: u32,
}

impl SOA {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut soa = Self {
            mname: "".to_string(),
            rname: "".to_string(),
            serial: 0,
            refresh: 0,
            retry: 0,
            expire: 0,
            minimum: 0,
        };
        soa.decode(raw, rdata)?;

        Ok(soa)
    }
}

impl RDataOperation for SOA {
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        let list = parse_domain_name(raw, &rdata[..rdata.len() - 20])?;
        if list.len() < 2 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        self.mname = list.get(0).unwrap().encode_to_str();
        self.rname = list.get(1).unwrap().encode_to_str();

        let getu32 = |offset: &mut usize| -> Result<u32, Error> {
            if *offset + 4 > rdata.len() {
                return Err(anyhow!(ERR_RDATE_MSG));
            }
            let v = u32::from_be_bytes(
                rdata[*offset..*offset + 4]
                    .try_into()
                    .expect("failed to get serial"),
            );
            *offset += 4;

            return Ok(v);
        };
        let mut offset = rdata.len() - 20;
        self.serial = getu32(&mut offset)?;
        self.refresh = getu32(&mut offset)?;
        self.retry = getu32(&mut offset)?;
        self.expire = getu32(&mut offset)?;
        self.minimum = getu32(&mut offset)?;

        Ok(())
    }

    fn encode(&self, raw: &mut Vec<u8>, is_compressed: bool) -> Result<(), Error> {
        raw.extend_from_slice(
            &encode_domain_name_wrap(self.mname.as_str(), raw, is_compressed).to_vec(),
        );
        raw.extend_from_slice(
            &encode_domain_name_wrap(self.rname.as_str(), raw, is_compressed).to_vec(),
        );
        raw.extend_from_slice(&self.serial.to_be_bytes());
        raw.extend_from_slice(&self.refresh.to_be_bytes());
        raw.extend_from_slice(&self.retry.to_be_bytes());
        raw.extend_from_slice(&self.expire.to_be_bytes());
        raw.extend_from_slice(&self.minimum.to_be_bytes());

        Ok(())
    }
}
