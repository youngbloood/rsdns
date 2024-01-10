/**
Ref: https://www.iana.org/assignments/dns-sec-alg-numbers/dns-sec-alg-numbers.xhtml

# DNS Security Algorithm Numbers
## Registration Procedure(s)
RFC Required
## Reference
[RFC4034][RFC3755][RFC6014][RFC6944]
## Note
The KEY, SIG, DNSKEY, RRSIG, DS, and CERT RRs use an 8-bit number used
to identify the security algorithm being used.

All algorithm numbers in this registry may be used in CERT RRs. Zone
signing (DNSSEC) and transaction security mechanisms (SIG(0) and TSIG)
make use of particular subsets of these algorithms. Only algorithms
usable for zone signing may appear in DNSKEY, RRSIG, and DS RRs.
Only those usable for SIG(0) and TSIG may appear in SIG and KEY RRs.

* There has been no determination of standardization of the use of this
algorithm with Transaction Security.

## Available Formats

|Number|Description|Mnemonic|ZoneSigning|Trans.Sec.|Reference|
|----|----|----|----|----|----|
|0|Delete DS|DELETE|N|N|[RFC4034][RFC4034],[RFC4398][RFC4398],[RFC8078][RFC8078]|
|1|RSA/MD5<br>(deprecated, see 5)|RSAMD5|N|Y|[RFC3110][RFC3110],[RFC4034][RFC4034]|
|2|Diffie-Hellman|DH|N|Y|[RFC2539][RFC2539]|
|3|DSA/SHA1|DSA|Y|Y|[RFC3755][RFC3755],[RFC2536][RFC2536],(Federal Information Processing Standards Publication (FIPS PUB) 186, Digital Signature Standard, 18 May 1994.][Federal Information Processing Standards Publication (FIPS PUB) 180-1, Secure Hash Standard, 17 April 1995. (Supersedes FIPS PUB 180 dated 11 May 1993.))|
|4|Reserved||||[RFC6725][RFC6725]|
|5|RSA/SHA-1|RSASHA1|Y|Y|[RFC3110][RFC3110],[RFC4034][RFC4034]|
|6|DSA-NSEC3-SHA1|DSA-NSEC3-SHA1|Y|Y|[RFC5155][RFC5155]|
|7|RSASHA1-NSEC3-SHA1|RSASHA1-NSEC3-SHA1|Y|Y|[RFC5155][RFC5155]|
|8|RSA/SHA-256|RSASHA256|Y|*|[RFC5702][RFC5702]|
|9|Reserved||||[RFC6725][RFC6725]|
|10|RSA/SHA-512|RSASHA512|Y|*|[RFC5702][RFC5702]|
|11|Reserved||||[RFC6725][RFC6725]|
|12|GOST R 34.10-2001|ECC-GOST|Y|*|[RFC5933][RFC5933]|
|13|ECDSA Curve P-256 with SHA-256|ECDSAP256SHA256|Y|*|[RFC6605][RFC6605]|
|14|ECDSA Curve P-384 with SHA-384|ECDSAP384SHA384|Y|*|[RFC6605][RFC6605]|
|15|Ed25519|ED25519|Y|*|[RFC8080][RFC8080]|
|16|Ed448|ED448|Y|*|[RFC8080][RFC8080]|
|17-122|Unassigned|||||
|123-251|Reserved||||[RFC4034][RFC4034],[RFC6014][RFC6014]|
|252|Reserved for Indirect Keys|INDIRECT|N|N|[RFC4034][RFC4034]|
|253|private algorithm|PRIVATEDNS|Y|Y|[RFC4034][RFC4034]|
|254|private algorithm OID|PRIVATEOID|Y|Y|[RFC4034][RFC4034]|
|255|Reserved||||[RFC4034][RFC4034]|

[RFC2536]: https://www.rfc-editor.org/rfc/rfc2536.html
[RFC2539]: https://www.rfc-editor.org/rfc/rfc2539.html
[RFC3110]: https://www.rfc-editor.org/rfc/rfc3110.html
[RFC3755]: https://www.rfc-editor.org/rfc/rfc3755.html
[RFC4034]: https://www.rfc-editor.org/rfc/rfc4034.html
[RFC4398]: https://www.rfc-editor.org/rfc/rfc4398.html
[RFC5155]: https://www.rfc-editor.org/rfc/rfc5155.html
[RFC5702]: https://www.rfc-editor.org/rfc/rfc5702.html
[RFC5933]: https://www.rfc-editor.org/rfc/rfc5933.html
[RFC6014]: https://www.rfc-editor.org/rfc/rfc6014.html
[RFC6605]: https://www.rfc-editor.org/rfc/rfc6605.html
[RFC6725]: https://www.rfc-editor.org/rfc/rfc6725.html
[RFC8078]: https://www.rfc-editor.org/rfc/rfc8078.html
[RFC8080]: https://www.rfc-editor.org/rfc/rfc8080.html
 */
pub type DNSSecAlgorithm = u8;

/// RSA/MD5
///
/// ref: https://www.rfc-editor.org/rfc/rfc2537.html
pub const DNSSEC_ALGORITHM1: DNSSecAlgorithm = 1;
pub trait DNSSecAlgorithmEncode {
    fn encode(&self, src: &[u8]) -> Vec<u8>;
}

impl DNSSecAlgorithmEncode for DNSSecAlgorithm {
    fn encode(&self, src: &[u8]) -> Vec<u8> {
        match *self {
            DNSSEC_ALGORITHM1 => todo!(),
            _ => todo!(),
        }
    }
}
/**
# Digest Algorithms
## Registration Procedure(s)
RFC Required
## Reference
[RFC3658][RFC3658],[RFC4034][RFC4034],[RFC4035][RFC4035],[RFC9157][RFC9157]
## Available Formats

|Value|Description|Status|Reference|
|-----|-----------|------|---------|
|0	  |Reserved	  |  -   |[RFC3658][RFC3658]|
|1	  |SHA-1	  |MANDATORY|[RFC3658][RFC3658]|
|2	  |SHA-256    |MANDATORY|[RFC4509][RFC4509]|
|3	  |GOST R 34.11-94|OPTIONAL|[RFC5933][RFC5933]|
|4	  |SHA-384	  |OPTIONAL|[RFC6605][RFC6605]|
|5-255|Unassigned|-||

[RFC3658]: https://www.rfc-editor.org/rfc/rfc3658.html
[RFC4034]: https://www.rfc-editor.org/rfc/rfc4034.html
[RFC4035]: https://www.rfc-editor.org/rfc/rfc4035.html
[RFC4509]: https://www.rfc-editor.org/rfc/rfc4059.html
[RFC5933]: https://www.rfc-editor.org/rfc/rfc5933.html
[RFC6605]: https://www.rfc-editor.org/rfc/rfc6605.html
[RFC9157]: https://www.rfc-editor.org/rfc/rfc9157.html
 */
pub type DigestAlgorithm = u8;

pub trait DigestAlgorithmEncode {
    fn encode(&self, src: &[u8]) -> Vec<u8>;
}

impl DigestAlgorithmEncode for DigestAlgorithm {
    fn encode(&self, src: &[u8]) -> Vec<u8> {
        vec![]
    }
}
