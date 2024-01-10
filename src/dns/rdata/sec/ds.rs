/*!
   The DS Resource Record refers to a DNSKEY RR and is used in the DNS
   DNSKEY authentication process.  A DS RR refers to a DNSKEY RR by
   storing the key tag, algorithm number, and a digest of the DNSKEY RR.
   Note that while the digest should be sufficient to identify the
   public key, storing the key tag and key algorithm helps make the
   identification process more efficient.  By authenticating the DS
   record, a resolver can authenticate the DNSKEY RR to which the DS
   record points.  The key authentication process is described in
   [RFC4035].

   The DS RR and its corresponding DNSKEY RR have the same owner name,
   but they are stored in different locations.  The DS RR appears only
   on the upper (parental) side of a delegation, and is authoritative
   data in the parent zone.  For example, the DS RR for "example.com" is
   stored in the "com" zone (the parent zone) rather than in the
   "example.com" zone (the child zone).  The corresponding DNSKEY RR is
   stored in the "example.com" zone (the child zone).  This simplifies
   DNS zone management and zone signing but introduces special response
   processing requirements for the DS RR; these are described in
   [RFC4035](https://www.rfc-editor.org/rfc/rfc4035).

   The type number for the DS record is 43.

   The DS resource record is class independent.

   The DS RR has no special TTL requirements.
*/

use super::{algo::DigestAlgorithm, key_tag::KeyTag};
use crate::dns::rdata::{RDataOperation, ERR_RDATE_MSG};
use anyhow::{anyhow, Error};

/**
  The RDATA for a DS RR consists of a 2 octet Key Tag field, a 1 octet
  Algorithm field, a 1 octet Digest Type field, and a Digest field.
  ```shell
                       1 1 1 1 1 1 1 1 1 1 2 2 2 2 2 2 2 2 2 2 3 3
   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  |           Key Tag             |  Algorithm    |  Digest Type  |
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  /                                                               /
  /                            Digest                             /
  /                                                               /
  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  ```
*/
#[derive(Debug, PartialEq, Eq)]
pub struct DS {
    /**
    The Key Tag field lists the key tag of the DNSKEY RR referred to by
    the DS record, in network byte order.

    The Key Tag used by the DS RR is identical to the Key Tag used by
    RRSIG RRs.  [Appendix B](https://www.rfc-editor.org/rfc/rfc4034#appendix-B) describes how to compute a Key Tag.
    */
    pub key_tag: KeyTag,

    /**
    The Algorithm field lists the algorithm number of the DNSKEY RR
    referred to by the DS record.

    The algorithm number used by the DS RR is identical to the algorithm
    number used by RRSIG and DNSKEY RRs.  [Appendix A.1](https://www.rfc-editor.org/rfc/rfc4034#appendix-A.1) lists the
    algorithm number types.
    */
    pub algorithm: DigestAlgorithm,

    /**
    The DS RR refers to a DNSKEY RR by including a digest of that DNSKEY
    RR.  The Digest Type field identifies the algorithm used to construct
    the digest.  [Appendix A.2](https://www.rfc-editor.org/rfc/rfc4034#appendix-A.2) lists the possible digest algorithm types.
    */
    pub digest_type: u8,

    /**
    The DS record refers to a DNSKEY RR by including a digest of that
    DNSKEY RR.

    The digest is calculated by concatenating the canonical form of the
    fully qualified owner name of the DNSKEY RR with the DNSKEY RDATA,
    and then applying the digest algorithm.

      digest = digest_algorithm( DNSKEY owner name | DNSKEY RDATA);

       "|" denotes concatenation

      DNSKEY RDATA = Flags | Protocol | Algorithm | Public Key.

    The size of the digest may vary depending on the digest algorithm and
    DNSKEY RR size.  As of the time of this writing, the only defined
    digest algorithm is SHA-1, which produces a 20 octet digest.
    */
    pub digest: Vec<u8>,
}

impl DS {
    pub fn new() -> Self {
        Self {
            key_tag: 0,
            algorithm: 0,
            digest_type: 0,
            digest: Vec::new(),
        }
    }

    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut ds = Self::new();
        ds.decode(raw, rdata)?;

        Ok(ds)
    }
}

impl RDataOperation for DS {
    fn decode(&mut self, _raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        if rdata.len() < 4 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        self.key_tag = u16::from_be_bytes(rdata[..2].try_into().unwrap());
        self.algorithm = rdata[2];
        self.digest_type = rdata[3];
        self.digest = rdata[4..].to_vec();

        Ok(())
    }

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        _cl: &mut crate::dns::compress_list::CompressList,
        _is_compressed: bool,
    ) -> Result<usize, anyhow::Error> {
        raw.extend(self.key_tag.to_be_bytes());
        raw.push(self.algorithm);
        raw.push(self.digest_type);
        raw.extend(&self.digest);

        Ok(2 + 1 + 1 + self.digest.len())
    }
}
