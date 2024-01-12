use super::{algo::DNSSecAlgorithm, key_tag::KeyTag};
use crate::{
    dns::rdata::{RDataOperation, ERR_RDATE_MSG},
    util::BASE64_ENGINE,
};
use anyhow::{anyhow, Error};
use base64::Engine as _;

/**
    The RDATA for an RRSIG RR consists of a 2 octet Type Covered field, a
    1 octet Algorithm field, a 1 octet Labels field, a 4 octet Original
    TTL field, a 4 octet Signature Expiration field, a 4 octet Signature
    Inception field, a 2 octet Key tag, the Signer's Name field, and the
    Signature field.
    ```shell
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |        Type Covered           |  Algorithm    |     Labels    |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                         Original TTL                          |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Signature Expiration                     |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |                      Signature Inception                      |
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    |            Key Tag            |                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+         Signer's Name         /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    /                                                               /
    /                            Signature                          /
    /                                                               /
    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    ```
*/
#[derive(Debug, PartialEq, Eq)]
pub struct RRSig {
    /**
    The Type Covered field identifies the type of the RRset that is
    covered by this RRSIG record.
    */
    pub type_covered: u16,

    /**
    The Algorithm Number field identifies the cryptographic algorithm
    used to create the signature.  A list of DNSSEC algorithm types can
    be found in [Appendix A.1](https://www.rfc-editor.org/rfc/rfc4034#appendix-A.1)
    */
    pub algorithm: DNSSecAlgorithm,

    /**
    The Labels field specifies the number of labels in the original RRSIG
    RR owner name.  The significance of this field is that a validator
    uses it to determine whether the answer was synthesized from a
    wildcard.  If so, it can be used to determine what owner name was
    used in generating the signature.

    To validate a signature, the validator needs the original owner name
    that was used to create the signature.  If the original owner name
    contains a wildcard label ("*"), the owner name may have been
    expanded by the server during the response process, in which case the
    validator will have to reconstruct the original owner name in order
    to validate the signature.  [RFC4035](https://www.rfc-editor.org/rfc/rfc4035) describes how to use the Labels
    field to reconstruct the original owner name.

    The value of the Labels field MUST NOT count either the null (root)
    label that terminates the owner name or the wildcard label (if
    present).  The value of the Labels field MUST be less than or equal
    to the number of labels in the RRSIG owner name.  For example,
    "www.example.com." has a Labels field value of 3, and
    "*.example.com." has a Labels field value of 2.  Root (".") has a
    Labels field value of 0.

    Although the wildcard label is not included in the count stored in
    the Labels field of the RRSIG RR, the wildcard label is part of the
    RRset's owner name when the signature is generated or verified.
    */
    pub labels: u8,

    /**
    The Original TTL field specifies the TTL of the covered RRset as it
    appears in the authoritative zone.

    The Original TTL field is necessary because a caching resolver
    decrements the TTL value of a cached RRset.  In order to validate a
    signature, a validator requires the original TTL.  [RFC4035](https://www.rfc-editor.org/rfc/rfc4035)
    describes how to use the Original TTL field value to reconstruct the
    original TTL.
    */
    pub origin_ttl: u32,

    /**
    The Signature Expiration and Inception fields specify a validity
    period for the signature.  The RRSIG record MUST NOT be used for
    authentication prior to the inception date and MUST NOT be used for
    authentication after the expiration date.

    The Signature Expiration and Inception field values specify a date
    and time in the form of a 32-bit unsigned number of seconds elapsed
    since 1 January 1970 00:00:00 UTC, ignoring leap seconds, in network
    byte order.  The longest interval that can be expressed by this
    format without wrapping is approximately 136 years.  An RRSIG RR can
    have an Expiration field value that is numerically smaller than the
    Inception field value if the expiration field value is near the
    32-bit wrap-around point or if the signature is long lived.  Because
    of this, all comparisons involving these fields MUST use "Serial
    number arithmetic", as defined in [RFC1982].  As a direct
    consequence, the values contained in these fields cannot refer to
    dates more than 68 years in either the past or the future.
    */
    pub sig_expiration: u32,

    /**
    The Signature Expiration and Inception fields specify a validity
    period for the signature.  The RRSIG record MUST NOT be used for
    authentication prior to the inception date and MUST NOT be used for
    authentication after the expiration date.

    The Signature Expiration and Inception field values specify a date
    and time in the form of a 32-bit unsigned number of seconds elapsed
    since 1 January 1970 00:00:00 UTC, ignoring leap seconds, in network
    byte order.  The longest interval that can be expressed by this
    format without wrapping is approximately 136 years.  An RRSIG RR can
    have an Expiration field value that is numerically smaller than the
    Inception field value if the expiration field value is near the
    32-bit wrap-around point or if the signature is long lived.  Because
    of this, all comparisons involving these fields MUST use "Serial
    number arithmetic", as defined in [RFC1982].  As a direct
    consequence, the values contained in these fields cannot refer to
    dates more than 68 years in either the past or the future.
    */
    pub sig_inception: u32,

    /**
    The Key Tag field contains the key tag value of the DNSKEY RR that
    validates this signature, in network byte order.  [Appendix B](https://www.rfc-editor.org/rfc/rfc4034#appendix-B) explains
    how to calculate Key Tag values.
    */
    pub key_tag: KeyTag,

    /**
    The Signer's Name field value identifies the owner name of the DNSKEY
    RR that a validator is supposed to use to validate this signature.
    The Signer's Name field MUST contain the name of the zone of the
    covered RRset.  A sender MUST NOT use DNS name compression on the
    Signer's Name field when transmitting a RRSIG RR.

    NOTE: not compression
    */
    pub signer_name: Vec<u8>,

    /**
     The Signature field contains the cryptographic signature that covers
     the RRSIG RDATA (excluding the Signature field) and the RRset
     specified by the RRSIG owner name, RRSIG class, and RRSIG Type
     Covered field.  The format of this field depends on the algorithm in
     use, and these formats are described in separate companion documents.

     # ref: [Signature Calculation](https://www.rfc-editor.org/rfc/rfc4034#section-3.1.8.1)
     A signature covers the RRSIG RDATA (excluding the Signature Field)
     and covers the data RRset specified by the RRSIG owner name, RRSIG
     class, and RRSIG Type Covered fields.  The RRset is in canonical form
     (see Section 6), and the set RR(1),...RR(n) is signed as follows:

         signature = sign(RRSIG_RDATA | RR(1) | RR(2)... ) where

             "|" denotes concatenation;

             RRSIG_RDATA is the wire format of the RRSIG RDATA fields
                with the Signer's Name field in canonical form and
                the Signature field excluded;

             RR(i) = owner | type | class | TTL | RDATA length | RDATA

                "owner" is the fully qualified owner name of the RRset in
                canonical form (for RRs with wildcard owner names, the
                wildcard label is included in the owner name);

                Each RR MUST have the same owner name as the RRSIG RR;

                Each RR MUST have the same class as the RRSIG RR;

                Each RR in the RRset MUST have the RR type listed in the
                RRSIG RR's Type Covered field;

                Each RR in the RRset MUST have the TTL listed in the
                RRSIG Original TTL Field;

                Any DNS names in the RDATA field of each RR MUST be in
                canonical form; and

                The RRset MUST be sorted in canonical order.

    See Sections 6.2 and 6.3 for details on canonical form and ordering
    of RRsets.
     */
    pub signature: Vec<u8>,
}

impl RRSig {
    pub fn new() -> Self {
        Self {
            type_covered: 0,
            algorithm: DNSSecAlgorithm::new(0),
            labels: 0,
            origin_ttl: 0,
            sig_expiration: 0,
            sig_inception: 0,
            key_tag: KeyTag::new(0),
            signer_name: Vec::new(),
            signature: Vec::new(),
        }
    }

    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut rrsig = Self::new();
        rrsig.decode(raw, rdata)?;

        Ok(rrsig)
    }
}

impl RDataOperation for RRSig {
    fn decode(&mut self, _raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        if rdata.len() < 18 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        self.type_covered = u16::from_be_bytes(rdata[..2].try_into().unwrap());
        self.algorithm = DNSSecAlgorithm::new(rdata[2]);
        self.labels = rdata[3];
        self.origin_ttl = u32::from_be_bytes(rdata[4..8].try_into().unwrap());
        self.sig_expiration = u32::from_be_bytes(rdata[8..12].try_into().unwrap());
        self.sig_inception = u32::from_be_bytes(rdata[12..16].try_into().unwrap());
        self.key_tag = KeyTag::new(u16::from_be_bytes(rdata[16..18].try_into().unwrap()));

        todo!("signer_name and signature");

        Ok(())
    }

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        _cl: &mut crate::dns::compress_list::CompressList,
        _is_compressed: bool,
    ) -> Result<usize, Error> {
        raw.extend(self.type_covered.to_be_bytes());
        raw.push(self.algorithm.algo());
        raw.push(self.labels);
        raw.extend(self.origin_ttl.to_be_bytes());
        raw.extend(self.sig_expiration.to_be_bytes());
        raw.extend(self.sig_inception.to_be_bytes());
        raw.extend(self.key_tag.key_tag().to_be_bytes());
        raw.extend(&self.signer_name);
        raw.extend(BASE64_ENGINE.encode(&self.signature).as_bytes());

        Ok(18 + self.signer_name.len() + self.signature.len())
    }
}
