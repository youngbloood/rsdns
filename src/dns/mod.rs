pub mod dns;
pub mod header;
pub mod labels;
pub mod question;
pub mod rr;

pub use dns::DNS;
pub use header::Header;
pub use question::Question;
pub use rr::{RRs, ResourceRecord};

/// a host address
const TYPE_A: u16 = 1;

/// an authoritative name server
const TYPE_NS: u16 = 2;

/// a mail destination (Obsolete - use MX)
const TYPE_MD: u16 = 3;

/// a mail forwarder (Obsolete - use MX)
const TYPE_MF: u16 = 4;

/// the canonical name for an alias
const TYPE_CNAME: u16 = 5;

/// marks the start of a zone of authority
const TYPE_SOA: u16 = 6;

/// a mailbox domain name (EXPERIMENTAL)
const TYPE_MB: u16 = 7;

/// a mail group member (EXPERIMENTAL)
const TYPE_MG: u16 = 8;

/// a mail rename domain name (EXPERIMENTAL)
const TYPE_MR: u16 = 9;

/// a null RR (EXPERIMENTAL)
const TYPE_NULL: u16 = 10;

/// a well known service description
const TYPE_WKS: u16 = 11;

/// a domain name pointer
const TYPE_PTR: u16 = 12;

/// host information
const TYPE_HINFO: u16 = 13;

/// mailbox or mail list information
const TYPE_MINFO: u16 = 14;

/// mail exchange
const TYPE_MX: u16 = 15;

/// text strings
const TYPE_TXT: u16 = 16;

/// for QType
const TYPE_AXFR: u16 = 252;
/// for QType
const TYPE_MAILB: u16 = 253;
/// for QType
const TYPE_MAILA: u16 = 254;
/// for QType
const TYPE_ALL: u16 = 255;

///  the Internet
const CLASS_IN: u16 = 1;
/// the CSNET class (Obsolete - used only for examples in  some obsolete RFCs)
const CLASS_CS: u16 = 2;
/// the CHAOS class
const CLASS_CH: u16 = 3;
/// Hesiod [Dyer 87]
const CLASS_HS: u16 = 4;

/// for QClass
const CLASS_ALL: u16 = 255;
