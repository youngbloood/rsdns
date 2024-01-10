/*!
The NSEC resource record lists two separate things: the next owner
   name (in the canonical ordering of the zone) that contains
   authoritative data or a delegation point NS RRset, and the set of RR
   types present at the NSEC RR's owner name [RFC3845].  The complete
   set of NSEC RRs in a zone indicates which authoritative RRsets exist
   in a zone and also form a chain of authoritative owner names in the
   zone.  This information is used to provide authenticated denial of
   existence for DNS data, as described in [RFC4035].

   Because every authoritative name in a zone must be part of the NSEC
   chain, NSEC RRs must be present for names containing a CNAME RR.
   This is a change to the traditional DNS specification [RFC1034],
   which stated that if a CNAME is present for a name, it is the only
   type allowed at that name.  An RRSIG (see Section 3) and NSEC MUST
   exist for the same name as does a CNAME resource record in a signed
   zone.

   See [RFC4035] for discussion of how a zone signer determines
   precisely which NSEC RRs it has to include in a zone.

   The type value for the NSEC RR is 47.

   The NSEC RR is class independent.

   The NSEC RR SHOULD have the same TTL value as the SOA minimum TTL
   field.  This is in the spirit of negative caching ([RFC2308]).
 */

use crate::dns::rdata::{parse_domain_name, RDataOperation, ERR_RDATE_MSG};
use anyhow::{anyhow, Error};

/**
The RDATA of the NSEC RR is as shown below:

```shell
                        1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                      Next Domain Name                         /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   /                       Type Bit Maps                           /
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```
  */
#[derive(Debug, PartialEq, Eq)]
pub struct NSEC {
    /**
    The Next Domain field contains the next owner name (in the canonical
    ordering of the zone) that has authoritative data or contains a
    delegation point NS RRset; see Section 6.1 for an explanation of
    canonical ordering.  The value of the Next Domain Name field in the
    last NSEC record in the zone is the name of the zone apex (the owner
    name of the zone's SOA RR).  This indicates that the owner name of
    the NSEC RR is the last name in the canonical ordering of the zone.

    A sender MUST NOT use DNS name compression on the Next Domain Name
    field when transmitting an NSEC RR.

    Owner names of RRsets for which the given zone is not authoritative
    (such as glue records) MUST NOT be listed in the Next Domain Name
    unless at least one authoritative RRset exists at the same owner
    name.

    NOTE: not compression
    */
    pub next_domain_name: String,

    /**
    The Type Bit Maps field identifies the RRset types that exist at the
    NSEC RR's owner name.

    The RR type space is split into 256 window blocks, each representing
    the low-order 8 bits of the 16-bit RR type space.  Each block that
    has at least one active RR type is encoded using a single octet
    window number (from 0 to 255), a single octet bitmap length (from 1
    to 32) indicating the number of octets used for the window block's
    bitmap, and up to 32 octets (256 bits) of bitmap.

    Blocks are present in the NSEC RR RDATA in increasing numerical
    order.

      Type Bit Maps Field = ( Window Block # | Bitmap Length | Bitmap )+

      where "|" denotes concatenation.

    Each bitmap encodes the low-order 8 bits of RR types within the
    window block, in network bit order.  The first bit is bit 0.  For
    window block 0, bit 1 corresponds to RR type 1 (A), bit 2 corresponds
    to RR type 2 (NS), and so forth.  For window block 1, bit 1
    corresponds to RR type 257, and bit 2 to RR type 258.  If a bit is
    set, it indicates that an RRset of that type is present for the NSEC
    RR's owner name.  If a bit is clear, it indicates that no RRset of
    that type is present for the NSEC RR's owner name.

    Bits representing pseudo-types MUST be clear, as they do not appear
    in zone data.  If encountered, they MUST be ignored upon being read.

    Blocks with no types present MUST NOT be included.  Trailing zero
    octets in the bitmap MUST be omitted.  The length of each block's
    bitmap is determined by the type code with the largest numerical
    value, within that block, among the set of RR types present at the
    NSEC RR's owner name.  Trailing zero octets not specified MUST be
    interpreted as zero octets.

    The bitmap for the NSEC RR at a delegation point requires special
    attention.  Bits corresponding to the delegation NS RRset and the RR
    types for which the parent zone has authoritative data MUST be set;
    bits corresponding to any non-NS RRset for which the parent is not
    authoritative MUST be clear.

    A zone MUST NOT include an NSEC RR for any domain name that only
    holds glue records.
    */
    pub type_bit_maps: u32,
}

impl NSEC {
    pub fn new() -> Self {
        Self {
            next_domain_name: "".to_string(),
            type_bit_maps: 0,
        }
    }
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut nsec = Self::new();
        nsec.decode(raw, rdata)?;

        Ok(nsec)
    }
}
impl RDataOperation for NSEC {
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        if rdata.len() < 8 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        let (domain_names, length) = parse_domain_name(raw, rdata)?;
        self.next_domain_name = domain_names.get(0).unwrap().encode_to_str();
        self.type_bit_maps = u32::from_be_bytes(rdata[length..].try_into().unwrap());

        Ok(())
    }

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        _cl: &mut crate::dns::compress_list::CompressList,
        _is_compressed: bool,
    ) -> Result<usize, anyhow::Error> {
        raw.extend(self.next_domain_name.as_bytes());
        raw.extend(self.type_bit_maps.to_be_bytes());

        Ok(4 + 4)
    }
}
