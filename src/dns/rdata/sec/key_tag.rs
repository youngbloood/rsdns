use super::{algo::DNSSEC_ALGORITHM1, dnskey::DNSKEY};

/**
    The Key Tag field in the RRSIG and DS resource record types provides
    a mechanism for selecting a public key efficiently.  In most cases, a
    combination of owner name, algorithm, and key tag can efficiently
    identify a DNSKEY record.  Both the RRSIG and DS resource records
    have corresponding DNSKEY records.  The Key Tag field in the RRSIG
    and DS records can be used to help select the corresponding DNSKEY RR
    efficiently when more than one candidate DNSKEY RR is available.

    However, it is essential to note that the key tag is not a unique
    identifier.  It is theoretically possible for two distinct DNSKEY RRs
    to have the same owner name, the same algorithm, and the same key
    tag.  The key tag is used to limit the possible candidate keys, but
    it does not uniquely identify a DNSKEY record.  Implementations MUST
    NOT assume that the key tag uniquely identifies a DNSKEY RR.

    The key tag is the same for all DNSKEY algorithm types except
    algorithm 1 (please see [Appendix B.1](https://www.rfc-editor.org/rfc/rfc4034#appendix-B.1) for the definition of the key
    tag for algorithm 1).  The key tag algorithm is the sum of the wire
    format of the DNSKEY RDATA broken into 2 octet groups.  First, the
    RDATA (in wire format) is treated as a series of 2 octet groups.
    These groups are then added together, ignoring any carry bits.

    A reference implementation of the key tag algorithm is as an ANSI C
    function is given below, with the RDATA portion of the DNSKEY RR is
    used as input.  It is not necessary to use the following reference
    code verbatim, but the numerical value of the Key Tag MUST be
    identical to what the reference implementation would generate for the
    same input.

    Please note that the algorithm for calculating the Key Tag is almost
    but not completely identical to the familiar ones-complement checksum
    used in many other Internet protocols.  Key Tags MUST be calculated
    using the algorithm described here rather than the ones complement
    checksum.

    The following ANSI C reference implementation calculates the value of
    a Key Tag.  This reference implementation applies to all algorithm
    types except algorithm 1 (see [Appendix B.1](https://www.rfc-editor.org/rfc/rfc4034#appendix-B.1)).  The input is the wire
    format of the RDATA portion of the DNSKEY RR.  The code is written
    for clarity, not efficiency.
*/
pub type KeyTag = u16;

/**
   Assumes that int is at least 16 bits.
   First octet of the key tag is the most significant 8 bits of the
   return value;
   Second octet of the key tag is the least significant 8 bits of the
   return value.

   ## C Code Impl
   ```C
    unsigned int
    keytag (
        unsigned char key[],  /* the RDATA part of the DNSKEY RR */
        unsigned int keysize  /* the RDLENGTH */
    )
    {
        unsigned long ac;     /* assumed to be 32 bits or larger */
        int i;                /* loop index */

        for ( ac = 0, i = 0; i < keysize; ++i )
                ac += (i & 1) ? key[i] : key[i] << 8;
        ac += (ac >> 16) & 0xFFFF;
        return ac & 0xFFFF;
    }
    ```
*/
pub fn calc_key_tag(dnskey: &DNSKEY) -> KeyTag {
    if dnskey.algorithm == DNSSEC_ALGORITHM1 {
        return calc_key_tag_for_1(dnskey);
    }

    let key = dnskey.as_bytes();
    let keysize = dnskey.all_len(); /* the RDLENGTH */

    let mut ac: usize = 0; /* assumed to be 32 bits or larger */
    let mut i = 0; /* loop index */
    while i < keysize {
        if i & 1 > 0 {
            ac += *key.get(i).unwrap() as usize;
        } else {
            ac += (*key.get(i).unwrap() << 8) as usize;
        }
        i += 1;
    }
    ac += (ac >> 16) & 0xFFFF;

    (ac & 0xFFFF) as KeyTag
}

/**
## Key Tag for Algorithm 1 (RSA/MD5)

  The key tag for algorithm 1 (RSA/MD5) is defined differently from the
  key tag for all other algorithms, for historical reasons.  For a
  DNSKEY RR with algorithm 1, the key tag is defined to be the most
  significant 16 bits of the least significant 24 bits in the public
  key modulus (in other words, the 4th to last and 3rd to last octets
  of the public key modulus).

  Please note that Algorithm 1 is NOT RECOMMENDED.
*/
fn calc_key_tag_for_1(dnskey: &DNSKEY) -> KeyTag {
    let len = dnskey.pub_key.len();
    let kt = [dnskey.pub_key[len - 3], dnskey.pub_key[len - 2]];

    u16::from_be_bytes(kt)
}
