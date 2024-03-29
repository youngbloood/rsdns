use super::{
    compress_list::CompressList,
    labels::Labels,
    meta_rr::MetaRR,
    rdata::{encode_domain_name_wrap, RDataOperation, RDataType},
    Class, RcRf, Type, VecRcRf, TYPE_OPT,
};
use crate::util;
use anyhow::{anyhow, Error};

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
#[derive(Debug, PartialEq, Eq)]
pub struct RR {
    all_length: usize,

    /// a domain name to which this resource record pertains.
    ///
    /// RFC2671(EDNS0): empty (root domain)
    name: String,

    /// two octets containing one of the RR type codes.  This
    /// field specifies the meaning of the data in the RDATA
    /// field.
    ///
    /// RFC2671(EDNS0): OPT
    typ: Type,

    /// two octets which specify the class of the data in the
    /// RDATA field.
    ///
    /// RFC2671(EDNS0): sender's UDP payload size
    class: Class,

    /// a 32 bit unsigned integer that specifies the time
    /// interval (in seconds) that the resource record may be
    /// cached before it should be discarded.  Zero values are
    /// interpreted to mean that the RR can only be used for the
    /// transaction in progress, and should not be cached.
    ///
    /// RFC2671(EDNS0): extended RCODE and flags
    ttl: u32,

    /// an unsigned 16 bit integer that specifies the length in
    /// octets of the RDATA field.
    rdlength: u16,

    /// a variable length string of octets that describes the
    /// resource.  The format of this information varies
    /// according to the TYPE and CLASS of the resource record.
    /// For example, the if the TYPE is A and the CLASS is IN,
    /// the RDATA field is a 4 octet ARPA Internet address.
    rdata: RDataType,
}

impl RR {
    pub fn new() -> Self {
        Self {
            name: "".to_string(),
            typ: 0,
            class: 0,
            ttl: 0,
            rdlength: 0,
            rdata: RDataType::new(),
            all_length: 0,
        }
    }

    pub fn from(raw: &[u8], offset: &mut usize, is_compressed: &mut bool) -> Result<Self, Error> {
        let mut rr = Self::new();
        let packet_err = Error::msg("parse rr failed cause the raw not completed");

        if *offset + 2 > raw.len() {
            return Err(packet_err);
        }

        let (compressed_offset, _is_compressed) = util::is_compressed_wrap(&raw[*offset..]);
        if _is_compressed {
            *is_compressed = _is_compressed;
            // parse domain_name from the pointer position, that point a labels start position
            *offset += 2;
            let mut domain_name_offset = compressed_offset;
            let labels = Labels::parse(raw, &mut domain_name_offset)?;
            rr.name = labels.encode_to_str();
        } else {
            // parse domain_name from labels directly
            let labels = Labels::parse(raw, offset)?;
            rr.name = labels.encode_to_str();
        }

        // validate the rr length
        if *offset + 10 > raw.len() {
            return Err(packet_err);
        }
        // parse type
        rr.typ = u16::from_be_bytes(raw[*offset..*offset + 2].try_into().unwrap());
        *offset += 2;

        // parse class
        rr.class = u16::from_be_bytes(raw[*offset..*offset + 2].try_into().unwrap());
        *offset += 2;

        // parse ttl
        rr.ttl = u32::from_be_bytes(raw[*offset..*offset + 4].try_into().unwrap());
        *offset += 4;

        // parse rdlength
        rr.rdlength = u16::from_be_bytes(raw[*offset..*offset + 2].try_into().unwrap());
        *offset += 2;
        if *offset + rr.rdlength as usize > raw.len() {
            return Err(packet_err);
        }

        // parse rdata
        // rr.rdata = raw[*offset..*offset + rr.rdlength as usize].to_vec();
        rr.rdata = RDataType::from(raw, &raw[*offset..*offset + rr.rdlength as usize], rr.typ)?;
        *offset += rr.rdlength as usize;

        Ok(rr)
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

    pub fn typ(&self) -> Type {
        return self.typ;
    }

    pub fn with_type(&mut self, typ: Type) -> &mut Self {
        self.typ = typ;
        return self;
    }

    pub fn class(&self) -> Class {
        return self.class;
    }

    pub fn with_class(&mut self, class: Class) -> &mut Self {
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

    pub fn rdata(&self) -> &RDataType {
        &self.rdata
    }

    pub fn rdata_mut(&mut self) -> &mut RDataType {
        &mut self.rdata
    }

    pub fn with_rdata(&mut self, resource: RDataType) -> &mut Self {
        self.rdata = resource;
        return self;
    }

    pub fn encode(
        &mut self,
        raw: &mut Vec<u8>,
        cl: &mut CompressList,
        is_compressed: bool,
    ) -> Result<(), Error> {
        // encode names
        raw.extend_from_slice(&encode_domain_name_wrap(
            self.name.as_str(),
            cl,
            is_compressed,
            raw.len(),
        )?);

        // encode type
        raw.extend_from_slice(&self.typ.to_be_bytes());
        // encode class
        raw.extend_from_slice(&self.class.to_be_bytes());
        // encode class
        raw.extend_from_slice(&self.ttl.to_be_bytes());
        let rdlength_offset = raw.len();
        // encode length ( with zero placeholder)
        raw.extend_from_slice(&[0, 0]);
        // encode rdata
        self.rdlength = self.rdata.encode(raw, cl, is_compressed)? as u16;
        println!("rdlength = {}", self.rdlength);
        // encode the truly rdlength
        let encoded_len = self.rdlength.to_be_bytes();
        (raw[rdlength_offset], raw[rdlength_offset + 1]) = (encoded_len[0], encoded_len[1]);

        Ok(())
    }

    pub fn convert_pseudo(&mut self) -> Result<MetaRR, Error> {
        if self.typ != TYPE_OPT {
            return Err(anyhow!("not pseudo rr"));
        }
        match &self.rdata {
            RDataType::OPT(_) => Ok(MetaRR::from(self)),
            _ => Err(anyhow!("not pseudo rr")),
        }
    }
}

/// RRs, RR sets
#[derive(Debug)]
pub struct RRs(pub VecRcRf<RR>);

impl RRs {
    pub fn new() -> Self {
        Self(vec![])
    }

    pub fn len(&self) -> usize {
        return self.0.len();
    }

    pub fn extend(&mut self, rr: RcRf<RR>) {
        self.0.push(rr);
    }

    /**
    ref: https://www.rfc-editor.org/rfc/rfc4034#section-6.1

    ## Canonical DNS Name Order

    For the purposes of DNS security, owner names are ordered by treating
    individual labels as unsigned left-justified octet strings.  The
    absence of a octet sorts before a zero value octet, and uppercase
    US-ASCII letters are treated as if they were lowercase US-ASCII
    letters.

    To compute the canonical ordering of a set of DNS names, start by
    sorting the names according to their most significant (rightmost)
    labels.  For names in which the most significant label is identical,
    continue sorting according to their next most significant label, and
    so forth.

    For example, the following names are sorted in canonical DNS name
    order.  The most significant label is "example".  At this level,
    "example" sorts first, followed by names ending in "a.example", then
    by names ending "z.example".  The names within each level are sorted
    in the same way.
    ```shell
            example
            a.example
            yljkjljk.a.example
            Z.a.example
            zABC.a.EXAMPLE
            z.example
            \001.z.example
            *.z.example
            \200.z.example
    ```
    */
    pub fn sort(&mut self) {
        self.0.sort_by(|a, b| {
            let abrw = a.borrow();
            let anamev: Vec<&str> = abrw.name.rsplit('.').collect();

            let bbrw = b.borrow();
            let bnamev: Vec<&str> = bbrw.name.rsplit('.').collect();

            let aname = anamev.join(".");
            let bname = bnamev.join(".");

            aname.cmp(&bname)
        })
    }

    pub fn encode(
        &mut self,
        raw: &mut Vec<u8>,
        cl: &mut CompressList,
        is_compressed: bool,
    ) -> Result<(), Error> {
        for rr in &self.0 {
            // encode names
            rr.borrow_mut().encode(raw, cl, is_compressed)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    pub fn test_rr_with_name() {
        let mut rr = RR::new();
        rr.with_name("google.com");
        assert_eq!(&"google.com", &rr.name.as_str());

        rr.with_name("amazon.com");
        assert_eq!(&"amazon.com", &rr.name.as_str());
    }

    #[test]
    pub fn test_rr_with_typ() {
        let mut rr = RR::new();
        rr.with_type(1);
        assert_eq!(1, rr.typ);

        rr.with_type(2);
        assert_eq!(2, rr.typ);
    }

    #[test]
    pub fn test_rr_with_class() {
        let mut rr = RR::new();
        rr.with_class(1);
        assert_eq!(1, rr.class);

        rr.with_class(2);
        assert_eq!(2, rr.class);
    }

    #[test]
    pub fn test_rr_with_ttl() {
        let mut rr = RR::new();
        rr.with_ttl(1);
        assert_eq!(1, rr.ttl);

        rr.with_ttl(2);
        assert_eq!(2, rr.ttl);
    }

    // #[test]
    // pub fn test_rr_with_rdata() {
    //     let mut rr = ResourceRecord::new();
    //     rr.with_rdata(Ipv4Addr::new(10, 0, 0, 1));
    //     assert_eq!(vec![10_u8, 0, 0, 1], rr.rdata);

    //     rr.with_rdata(Ipv4Addr::new(10, 0, 0, 2));
    //     assert_eq!(vec![10_u8, 0, 0, 2], rr.rdata);
    // }

    #[test]
    pub fn test_rr_is_compressed() {
        let cases = [([192_u8, 12], true, 12), ([6_u8, 13], false, 0)];

        for cs in cases {
            let (offset, is_compressed) = util::is_compressed(cs.0);
            assert_eq!(cs.1, is_compressed);
            if is_compressed {
                assert_eq!(cs.2, offset);
            }
        }
    }

    #[test]
    pub fn test_rr_is_equal() {
        let new_rr = |name, typ, class, ttl, _rdlen| {
            let mut rr = RR::new();
            rr.with_name(name)
                .with_type(typ)
                .with_class(class)
                .with_ttl(ttl);
            rr
        };

        let rr1 = new_rr("baidu.com", 1, 1, 32, 32);
        let rr2 = new_rr("baidu.com", 1, 1, 32, 32);
        let rr3 = new_rr("baidu.com", 1, 1, 33, 32);
        assert_eq!(true, rr1 == rr2);
        assert_eq!(false, rr1 == rr3);
    }
}
