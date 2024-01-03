use super::{compress_list::CompressList, ResourceRecord, TYPE_OPT};
use anyhow::Error;
use rsbit::BitOperation;

/**
# The fixed part of an OPT RR is structured as follows:
```shell
   Field Name   Field Type     Description
   ------------------------------------------------------
   NAME         domain name    empty (root domain)
   TYPE         u_int16_t      OPT
   CLASS        u_int16_t      sender's UDP payload size
   TTL          u_int32_t      extended RCODE and flags
   RDLEN        u_int16_t      describes RDATA
   RDATA        octet stream   {attribute,value} pairs
```
*/
#[derive(Debug)]
pub struct PseudoRR<'a>(&'a mut ResourceRecord);

impl<'a> PseudoRR<'a> {
    pub fn from(rr: &'a mut ResourceRecord) -> Self {
        Self { 0: rr }
    }

    pub fn rr(&mut self) -> &mut ResourceRecord {
        self.0
    }

    /// Sender's UDP payload size
    pub fn udp_payload(&self) -> u16 {
        if self.0.typ() != TYPE_OPT {
            return 0;
        }

        self.0.class()
    }

    /// Set sender's UDP payload size
    pub fn with_udp_payload(&mut self, payload: u16) -> &mut Self {
        if self.0.typ() != TYPE_OPT {
            return self;
        }

        self.0.with_class(payload);
        self
    }

    /// Forms upper 8 bits of extended 12-bit RCODE.  Note
    /// that EXTENDED-RCODE value "0" indicates that an
    /// unextended RCODE is in use (values "0" through "15").
    pub fn rcode(&self, head_rcode: u8) -> u16 {
        if self.0.typ() != TYPE_OPT {
            return 0;
        }

        let ext_rcode = self.0.ttl().to_be_bytes()[0];
        let lower4_ext_rcode = ext_rcode & 0b0000_1111;
        let new_head_rcode = head_rcode | lower4_ext_rcode << 4;
        let new_extend_rcode = ext_rcode >> 4;
        let erc = [new_extend_rcode, new_head_rcode];

        u16::from_be_bytes(erc)
    }

    /// returns: header_rcode
    pub fn with_rcode(&mut self, rcode: u16) -> u8 {
        let codes = rcode.to_be_bytes();
        let head_rcode = codes[1];
        let high4_head_rcode = head_rcode & 0b1111_0000;
        let low4_ext_rcode = codes[0] << 4;
        let new_ext_rcode = low4_ext_rcode | high4_head_rcode >> 4;

        let mut ttls = self.0.ttl().to_be_bytes();
        ttls[0] = new_ext_rcode;
        self.0.with_ttl(u32::from_be_bytes(ttls));

        head_rcode & 0b0000_1111
    }

    /**
    Indicates the implementation level of whoever sets
    it.  Full conformance with this specification is
    indicated by version "0."  Requestors are encouraged
    to set this to the lowest implemented level capable
    of expressing a transaction, to minimize the
    responder and network load of discovering the
    greatest common implementation level between
    requestor and responder.  A requestor's version
    numbering strategy should ideally be a run time
    configuration option.

    If a responder does not implement the VERSION level
    of the request, then it answers with RCODE=BADVERS.
    All responses will be limited in format to the
    VERSION level of the request, but the VERSION of each
    response will be the highest implementation level of
    the responder.  In this way a requestor will learn
    the implementation level of a responder as a side
    effect of every response, including error responses,
    including RCODE=BADVERS.
    */
    pub fn version(&self) -> u8 {
        if self.0.typ() != TYPE_OPT {
            return 0;
        }

        self.0.ttl().to_be_bytes()[1]
    }

    pub fn with_version(&mut self, v: u8) -> &mut Self {
        if self.0.typ() != TYPE_OPT {
            return self;
        }

        let mut ttl = self.0.ttl().to_be_bytes();
        ttl[1] = v;
        self.0.with_ttl(u32::from_be_bytes(ttl));

        self
    }

    /// Set to zero by senders and ignored by receivers,
    /// unless modified in a subsequent specification.
    pub fn z(&self) -> u16 {
        if self.0.typ() != TYPE_OPT {
            return 0;
        }
        // ignore the DO bit
        let mut zs: [u8; 2] = self.0.ttl().to_be_bytes()[2..].try_into().unwrap();
        zs[0] = zs[0] & 0b0111_1111;

        u16::from_be_bytes(zs)
    }

    pub fn with_z(&mut self, z: u16) -> &mut Self {
        if self.0.typ() != TYPE_OPT {
            return self;
        }
        if z > u16::MAX / 2 {
            return self;
        }

        let mut ttl = self.0.ttl().to_be_bytes();
        let zs = z.to_be_bytes();
        // ignore the DO bit
        (ttl[2], ttl[3]) = (zs[0] & 0b0111_1111, zs[1]);
        self.0.with_ttl(u32::from_be_bytes(ttl));

        self
    }

    /**
    The mechanism chosen for the explicit notification of the ability of
    the client to accept (if not understand) DNSSEC security RRs is using
    the most significant bit of the Z field on the EDNS0 OPT header in
    the query.  This bit is referred to as the "DNSSEC OK" (DO) bit.  In
    the context of the EDNS0 OPT meta-RR, the DO bit is the first bit of
    the third and fourth bytes of the "extended RCODE and flags" portion
    of the EDNS0 OPT meta-RR, structured as follows:
    ```shell
                    +0 (MSB)                +1 (LSB)
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        0: |   EXTENDED-RCODE      |       VERSION         |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
        2: |DO|                    Z                       |
           +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    ```
    Setting the DO bit to one in a query indicates to the server that the
    resolver is able to accept DNSSEC security RRs.  The DO bit cleared
    (set to zero) indicates the resolver is unprepared to handle DNSSEC
    security RRs and those RRs MUST NOT be returned in the response
    (unless DNSSEC security RRs are explicitly queried for).  The DO bit
    of the query MUST be copied in the response.

    More explicitly, DNSSEC-aware nameservers MUST NOT insert SIG, KEY,
    or NXT RRs to authenticate a response as specified in [RFC2535]
    unless the DO bit was set on the request.  Security records that
    match an explicit SIG, KEY, NXT, or ANY query, or are part of the
    zone data for an AXFR or IXFR query, are included whether or not the
    DO bit was set.

    A recursive DNSSEC-aware server MUST set the DO bit on recursive
    requests, regardless of the status of the DO bit on the initiating
    resolver request.  If the initiating resolver request does not have
    the DO bit set, the recursive DNSSEC-aware server MUST remove DNSSEC
    security RRs before returning the data to the client, however cached
    data MUST NOT be modified.

    In the event a server returns a NOTIMP, FORMERR or SERVFAIL response
    to a query that has the DO bit set, the resolver SHOULD NOT expect
    DNSSEC security RRs and SHOULD retry the query without EDNS0 in
    accordance with [section 5.3 of RFC2671](https://www.rfc-editor.org/rfc/rfc2671#section-5.3).
     */
    pub fn dnssec_ok(&self) -> bool {
        let flag = 0b1000_0000 as u8;

        self.0.ttl().to_be_bytes()[2] & flag == flag
    }

    /// Set the DO bit flag
    pub fn with_dnssec_ok(&mut self, ok: bool) -> &mut Self {
        let mut ttl = self.0.ttl().to_be_bytes();
        if ok {
            (&mut ttl[2]).set_1(7);
        } else {
            (&mut ttl[2]).set_0(7);
        }

        self.0.with_ttl(u32::from_be_bytes(ttl));

        self
    }

    pub fn encode(
        &mut self,
        raw: &mut Vec<u8>,
        cl: &mut CompressList,
        is_compressed: bool,
    ) -> Result<(), Error> {
        self.0.encode(raw, cl, is_compressed)
    }
}

#[cfg(test)]
mod tests {
    use super::PseudoRR;
    use crate::dns::{ResourceRecord, TYPE_OPT};
    use once_cell::sync::Lazy;

    static mut RR: Lazy<ResourceRecord> = Lazy::new(|| ResourceRecord::new());

    fn new_persudo_rr() -> PseudoRR<'static> {
        unsafe { RR.with_type(TYPE_OPT) };
        PseudoRR::from(unsafe { &mut RR })
    }

    #[test]
    fn test_pseudo_rr_udp_payload() {
        let prr = new_persudo_rr();
        prr.0.with_class(512);
        assert_eq!(512, prr.udp_payload());

        prr.0.with_class(1024);
        assert_eq!(1024, prr.udp_payload());
    }

    #[test]
    fn test_pseudo_rr_with_udp_payload() {
        let mut prr = new_persudo_rr();
        prr.with_udp_payload(512);
        assert_eq!(512, prr.udp_payload());

        prr.with_udp_payload(1024);
        assert_eq!(1024, prr.udp_payload());
    }

    #[test]
    fn test_pseudo_rr_rcode() {
        let prr = new_persudo_rr();
        prr.0.with_ttl(u32::MAX / 2);
        assert_eq!(2044, prr.rcode(12));

        prr.0.with_ttl(u32::MAX);
        assert_eq!(4092, prr.rcode(12));
    }

    #[test]
    fn test_pseudo_rr_with_rcode() {
        let mut prr = new_persudo_rr();
        prr.0.with_ttl(u32::MAX / 2);
        assert_eq!(12, prr.with_rcode(2044));
        assert_eq!(2044, prr.rcode(12));

        prr.0.with_ttl(u32::MAX);
        assert_eq!(12, prr.with_rcode(4092));
        assert_eq!(4092, prr.rcode(12));
    }

    #[test]
    fn test_pseudo_rr_version() {
        let prr = new_persudo_rr();
        prr.0.with_ttl(u32::MAX / 2);
        assert_eq!(255, prr.version());

        prr.0.with_ttl(u32::MAX / (2_i32.pow(15) as u32));
        assert_eq!(1, prr.version());
        prr.0.with_ttl(u32::MAX / (2_i32.pow(14) as u32));
        assert_eq!(3, prr.version());
        prr.0.with_ttl(u32::MAX / (2_i32.pow(13) as u32));
        assert_eq!(7, prr.version());
    }

    #[test]
    fn test_pseudo_rr_with_version() {
        let mut prr = new_persudo_rr();
        prr.with_version(155);
        assert_eq!(155, prr.version());

        prr.with_version(180);
        assert_eq!(180, prr.version());
    }

    #[test]
    fn test_pseudo_rr_z() {
        let prr = new_persudo_rr();
        prr.0.with_ttl(u32::MAX / 2);
        assert_eq!(u16::MAX, prr.z());
    }

    #[test]
    fn test_pseudo_rr_with_z() {
        let mut prr = new_persudo_rr();
        prr.with_z(u16::MAX / 4);
        assert_eq!(u16::MAX / 4, prr.z());

        prr.with_z(u16::MAX / 2);
        assert_eq!(u16::MAX / 2, prr.z());

        prr.with_z(u16::MAX); // not process
        assert_eq!(u16::MAX / 2, prr.z());
    }

    #[test]
    fn test_pseudo_rr_dnssec_ok() {
        let prr = new_persudo_rr();
        assert_eq!(false, prr.dnssec_ok());
    }

    #[test]
    fn test_pseudo_rr_with_dnssec_ok() {
        let mut prr = new_persudo_rr();
        assert_eq!(false, prr.dnssec_ok());

        prr.with_dnssec_ok(true);
        assert_eq!(true, prr.dnssec_ok());
        prr.with_dnssec_ok(false);
        assert_eq!(false, prr.dnssec_ok());
    }
}
