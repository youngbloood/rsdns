use std::net::Ipv4Addr;

use anyhow::Error;

use super::{labels::Labels, RcRf, VecRcRf};

/// The answer, authority, and additional sections all share the same
/// format: a variable number of resource records, where the number of
/// records is specified in the corresponding count field in the header.
/// Each resource record has the following format:
/// # Examples:
/// ```shell
///       0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                                               |
///     /                                               /
///     /                      NAME                     /
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TYPE                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                     CLASS                     |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                      TTL                      |
///     |                                               |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
///     |                   RDLENGTH                    |
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
///     /                     RDATA                     /
///     /                                               /
///     +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug)]
pub struct ResourceRecord {
    all_length: usize,

    /// a domain name to which this resource record pertains.
    name: String,

    /// two octets containing one of the RR type codes.  This
    /// field specifies the meaning of the data in the RDATA
    /// field.
    typ: u16,

    /// two octets which specify the class of the data in the
    /// RDATA field.
    class: u16,

    /// a 32 bit unsigned integer that specifies the time
    /// interval (in seconds) that the resource record may be
    /// cached before it should be discarded.  Zero values are
    /// interpreted to mean that the RR can only be used for the
    /// transaction in progress, and should not be cached.
    ttl: u32,

    /// an unsigned 16 bit integer that specifies the length in
    /// octets of the RDATA field.
    rdlength: u16,

    /// a variable length string of octets that describes the
    /// resource.  The format of this information varies
    /// according to the TYPE and CLASS of the resource record.
    /// For example, the if the TYPE is A and the CLASS is IN,
    /// the RDATA field is a 4 octet ARPA Internet address.
    rdata: Vec<u8>,
}

impl ResourceRecord {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            typ: 0,
            class: 0,
            ttl: 0,
            rdlength: 0,
            rdata: vec![],
            all_length: 0,
        }
    }

    pub fn from(raw: &[u8], offset: &mut usize) -> Result<Self, Error> {
        let mut rr = Self::new();
        let packet_err = Error::msg("parse rr failed cause the raw not completed");

        if *offset + 2 > raw.len() {
            return Err(packet_err);
        }
        let (compressed_offset, is_compressed) = Self::is_compressed(
            raw[*offset..*offset + 2]
                .try_into()
                .expect("judge the compressed failed"),
        );

        if is_compressed {
            // parse domain_name from the pointer position, that point a labels start position
            *offset += 2;
            let mut domain_name_offset = compressed_offset;
            let labels = Labels::from(raw, &mut domain_name_offset)?;
            rr.name = labels.encode_to_str();
        } else {
            // parse domain_name from labels directly
            let labels = Labels::from(raw, offset)?;
            rr.name = labels.encode_to_str();
        }

        // parse type
        rr.typ = u16::from_be_bytes(
            raw[*offset..*offset + 2]
                .try_into()
                .expect("slice with incorrent length"),
        );
        *offset += 2;

        // parse class
        rr.class = u16::from_be_bytes(
            raw[*offset..*offset + 2]
                .try_into()
                .expect("slice with incorrent length"),
        );
        *offset += 2;

        // parse ttl
        rr.ttl = u32::from_be_bytes(
            raw[*offset..*offset + 4]
                .try_into()
                .expect("slice with incorrent length"),
        );
        *offset += 4;

        // parse rdlength
        rr.rdlength = u16::from_be_bytes(
            raw[*offset..*offset + 2]
                .try_into()
                .expect("slice with incorrent length"),
        );
        *offset += 2;

        if *offset + rr.rdlength as usize > raw.len() {
            return Err(packet_err);
        }

        // parse rdata
        rr.rdata = raw[*offset..*offset + rr.rdlength as usize].to_vec();
        *offset += rr.rdlength as usize;

        Ok(rr)
    }

    /// is_compressed judge the rrs weather use the compress.
    /// if the third byte is zero and the first byte's first and second bit is 1, it represent compressed. or not
    /// ref: https://www.rfc-editor.org/rfc/rfc1035#section-4.1.4
    fn is_compressed(pointer: [u8; 2]) -> (usize, bool) {
        let mut off = [pointer[0], pointer[1]];
        off[0] &= 0b0011_1111;
        return (
            u16::from_be_bytes(off) as usize,
            pointer[0] & 0b1100_0000 == 0b1100_0000,
        );
    }

    pub fn all_length(&self) -> usize {
        return self.all_length;
    }

    pub fn name(&self) -> &str {
        return &self.name;
    }

    pub fn with_name(&mut self, name: &str) -> &mut Self {
        self.name = name.to_string();
        return self;
    }

    pub fn typ(&self) -> u16 {
        return self.typ;
    }

    pub fn with_type(&mut self, typ: u16) -> &mut Self {
        self.typ = typ;
        return self;
    }

    pub fn class(&self) -> u16 {
        return self.class;
    }

    pub fn with_class(&mut self, class: u16) -> &mut Self {
        self.class = class;
        return self;
    }

    pub fn ttl(&self) -> u32 {
        return self.ttl;
    }

    pub fn with_ttl(&mut self, ttl: u32) -> &mut Self {
        self.ttl = ttl;
        return self;
    }

    // pub fn rdata(&self) -> Ipv4Addr {
    //     return Ipv4Addr::from(&self.rdata);
    // }

    pub fn with_rdata(&mut self, ip: Ipv4Addr) -> &mut Self {
        self.rdata = ip.octets().to_vec();
        return self;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();
        // encode names
        for v in self.name.as_bytes() {
            result.push(*v);
        }
        result.push(b'\x00');

        // encode type
        result.extend_from_slice(&self.typ.to_be_bytes());
        // encode class
        result.extend_from_slice(&self.class.to_be_bytes());
        // encode class
        result.extend_from_slice(&self.ttl.to_be_bytes());
        // encode length
        result.extend_from_slice(&self.rdlength.to_be_bytes());
        // encode data
        result.extend_from_slice(&self.rdata);

        result
    }
}

#[derive(Debug)]
pub struct RRs(pub VecRcRf<ResourceRecord>);

impl RRs {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }

    pub fn extend(&mut self, rr: RcRf<ResourceRecord>) {
        self.0.push(rr);
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        for rr in &self.0 {
            // encode names
            result.extend_from_slice(&rr.clone().borrow().encode());
        }

        return result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    pub fn test_rr_with_name() {
        let mut rr = ResourceRecord::new();
        rr.with_name("google.com");
        assert_eq!(&"google.com", &rr.name.as_str());

        rr.with_name("amazon.com");
        assert_eq!(&"amazon.com", &rr.name.as_str());
    }

    #[test]
    pub fn test_rr_with_typ() {
        let mut rr = ResourceRecord::new();
        rr.with_type(1);
        assert_eq!(1, rr.typ);

        rr.with_type(2);
        assert_eq!(2, rr.typ);
    }

    #[test]
    pub fn test_rr_with_class() {
        let mut rr = ResourceRecord::new();
        rr.with_class(1);
        assert_eq!(1, rr.class);

        rr.with_class(2);
        assert_eq!(2, rr.class);
    }

    #[test]
    pub fn test_rr_with_ttl() {
        let mut rr = ResourceRecord::new();
        rr.with_ttl(1);
        assert_eq!(1, rr.ttl);

        rr.with_ttl(2);
        assert_eq!(2, rr.ttl);
    }

    #[test]
    pub fn test_rr_with_rdata() {
        let mut rr = ResourceRecord::new();
        rr.with_rdata(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(vec![10_u8, 0, 0, 1], rr.rdata);

        rr.with_rdata(Ipv4Addr::new(10, 0, 0, 2));
        assert_eq!(vec![10_u8, 0, 0, 2], rr.rdata);
    }

    #[test]
    pub fn test_rr_is_compressed() {
        let cases = [([192_u8, 12], true, 12), ([6_u8, 13], false, 0)];

        for cs in cases {
            let (offset, is_compressed) = ResourceRecord::is_compressed(cs.0);
            assert_eq!(cs.1, is_compressed);
            if is_compressed {
                assert_eq!(cs.2, offset);
            }
        }
    }
}
