use crate::{
    dns::rdata::{RDataOperation, ERR_RDATE_MSG},
    util::BASE64_ENGINE,
};
use anyhow::{anyhow, Error};
use base64::Engine as _;
use rsbit::BitOperation;

use super::algo::DNSSecAlgorithm;

const ZONE_KEY_FLAG: u8 = 0b0000_0001;
const ZONE_KEY_POS: u8 = 0;
const SECURE_ENTRY_POINT: u8 = 0b0000_0001;
const SECURE_ENTRY_POINT_POS: u8 = 0;

/**
  The RDATA for a DNSKEY RR consists of a 2 octet Flags Field, a 1
  octet Protocol Field, a 1 octet Algorithm Field, and the Public Key
  Field.
  ```shell

                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |              Flags            |    Protocol   |   Algorithm   |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /                                                               /
  /                            Public Key                         /
  /                                                               /
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ```
*/
#[derive(Debug, PartialEq, Eq)]
pub struct DNSKEY {
    /**
    Bit 7 of the Flags field is the Zone Key flag.  If bit 7 has value 1,
    then the DNSKEY record holds a DNS zone key, and the DNSKEY RR's
    owner name MUST be the name of a zone.  If bit 7 has value 0, then
    the DNSKEY record holds some other type of DNS public key and MUST
    NOT be used to verify RRSIGs that cover RRsets.

    Bit 15 of the Flags field is the Secure Entry Point flag, described
    in [RFC3757](https://www.rfc-editor.org/rfc/rfc3757).  If bit 15 has value 1, then the DNSKEY record holds a
    key intended for use as a secure entry point.  This flag is only
    intended to be a hint to zone signing or debugging software as to the
    intended use of this DNSKEY record; validators MUST NOT alter their
    behavior during the signature validation process in any way based on
    the setting of this bit.  This also means that a DNSKEY RR with the
    SEP bit set would also need the Zone Key flag set in order to be able
    to generate signatures legally.  A DNSKEY RR with the SEP set and the
    Zone Key flag not set MUST NOT be used to verify RRSIGs that cover
    RRsets.

    Bits 0-6 and 8-14 are reserved: these bits MUST have value 0 upon
    creation of the DNSKEY RR and MUST be ignored upon receipt.
    */
    pub flags: u16,

    /**
    The Protocol Field MUST have value 3, and the DNSKEY RR MUST be
    treated as invalid during signature verification if it is found to be
    some value other than 3.
    */
    pub protocol: u8,

    /**
    The Algorithm field identifies the public key's cryptographic
    algorithm and determines the format of the Public Key field.  A list
    of DNSSEC algorithm types can be found in [Appendix A.1](https://www.rfc-editor.org/rfc/rfc4034#appendix-A.1)
    */
    pub algorithm: DNSSecAlgorithm,

    /**
    The Public Key Field holds the public key material.  The format
    depends on the algorithm of the key being stored and is described in
    separate documents.
    */
    pub pub_key: Vec<u8>,
}

impl DNSKEY {
    pub fn new() -> Self {
        Self {
            flags: 0,
            protocol: 3,
            algorithm: 0,
            pub_key: Vec::new(),
        }
    }

    pub fn all_len(&self) -> usize {
        4 + self.pub_key.len()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut r = vec![];
        r.extend(self.flags.to_be_bytes());
        r.push(self.protocol);
        r.push(self.algorithm);
        r.extend(&self.pub_key);

        r
    }

    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut dnskey = Self::new();
        dnskey.decode(raw, rdata)?;

        Ok(dnskey)
    }

    pub fn flag_zone_key(&self) -> bool {
        self.flags.to_be_bytes()[0] & ZONE_KEY_FLAG == ZONE_KEY_FLAG
    }

    pub fn with_flag_zone_key(&mut self, zone_key: bool) -> &mut Self {
        let mut flags = self.flags.to_be_bytes();
        if zone_key {
            (&mut flags[0]).set_1(ZONE_KEY_POS);
        } else {
            (&mut flags[0]).set_0(ZONE_KEY_POS);
        }
        self.flags = u16::from_be_bytes(flags);

        self
    }

    pub fn flag_sec_entry_point(&self) -> bool {
        self.flags.to_be_bytes()[1] & SECURE_ENTRY_POINT == SECURE_ENTRY_POINT
    }

    pub fn with_flag_sec_entry_point(&mut self, sec_entry_point: bool) -> &mut Self {
        let mut flags = self.flags.to_be_bytes();
        if sec_entry_point {
            (&mut flags[1]).set_1(SECURE_ENTRY_POINT_POS);
        } else {
            (&mut flags[1]).set_0(SECURE_ENTRY_POINT_POS);
        }
        self.flags = u16::from_be_bytes(flags);

        self
    }
}

impl RDataOperation for DNSKEY {
    fn decode(&mut self, _raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        if rdata.len() < 4 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        self.flags = u16::from_be_bytes(rdata[..2].try_into().unwrap());
        self.protocol = rdata[2];
        self.algorithm = rdata[3];
        self.pub_key = BASE64_ENGINE.decode(rdata[4..].to_vec())?;
        Ok(())
    }

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        _cl: &mut crate::dns::compress_list::CompressList,
        _is_compressed: bool,
    ) -> Result<usize, Error> {
        raw.extend(self.flags.to_be_bytes());
        raw.push(self.protocol);
        raw.push(self.algorithm);
        raw.extend(BASE64_ENGINE.encode(&self.pub_key).as_bytes());

        Ok(4 + self.pub_key.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_with_flag_zone_key() {
        let mut dnskey: DNSKEY = DNSKEY::new();
        dnskey.with_flag_zone_key(true);
        assert_eq!(256, dnskey.flags);

        dnskey.with_flag_zone_key(false);
        assert_eq!(0, dnskey.flags);
    }

    #[test]
    fn test_with_flag_sec_entry_point() {
        let mut dnskey: DNSKEY = DNSKEY::new();
        dnskey.with_flag_sec_entry_point(true);
        assert_eq!(1, dnskey.flags);

        dnskey.with_flag_sec_entry_point(false);
        assert_eq!(0, dnskey.flags);
    }

    #[test]
    fn test_dnskey_decode() {
        let pub_key = "AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w==";
        let mut rdata = vec![16_u8, 11, 3, 1];
        rdata.extend(pub_key.as_bytes());

        let mut dnskey = DNSKEY::new();
        let result = dnskey.decode(&rdata, &rdata);
        assert_eq!(false, result.is_err());
    }
}
