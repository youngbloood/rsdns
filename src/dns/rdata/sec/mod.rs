pub mod dnskey;
pub mod ds;
pub mod nsec;
pub mod rrsig;

type DNSKeyAlgorithm = u8;

/// RSA/MD5
///
/// [RFC2537](https://www.rfc-editor.org/rfc/rfc2537)
///
/// NOT RECOMMENDED
const ALGO_RSAMD5: DNSKeyAlgorithm = 1;

/// Diffie-Hellman
///
/// [RFC2539](https://www.rfc-editor.org/rfc/rfc2539)
const ALGO_DH: DNSKeyAlgorithm = 2;

/// DSA/SHA-1
///
/// [RFC2536](https://www.rfc-editor.org/rfc/rfc2536)
///
/// OPTIONAL
const ALGO_DSA: DNSKeyAlgorithm = 3;

/// Elliptic Curve
///
/// TBA
const ALGO_ECC: DNSKeyAlgorithm = 4;

/// RSA/SHA-1
///
/// [RFC3110](https://www.rfc-editor.org/rfc/rfc3110)
///
/// MANDATORY
const ALGO_RSASHA1: DNSKeyAlgorithm = 5;

/// Indirect
const ALGO_INDIRECT: DNSKeyAlgorithm = 252;

/// Private
///
/// OPTIONAL
const ALGO_PRIVATEDNS: DNSKeyAlgorithm = 253;

/// Private
///
/// OPTIONAL
const ALGO_PRIVATEOID: DNSKeyAlgorithm = 254;
