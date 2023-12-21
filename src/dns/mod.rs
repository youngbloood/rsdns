pub mod dns;
pub mod header;
mod labels;
pub mod question;
mod rdata;
mod rr;

pub use dns::DNS;
pub use header::Header;
pub use question::Question;
pub use rr::ResourceRecord;
use std::{cell::RefCell, rc::Rc};

pub type Type = u16;
pub type Class = u16;

/// a host address
pub const TYPE_A: Type = 1;

/// an authoritative name server
pub const TYPE_NS: Type = 2;

/// a mail destination (Obsolete - use MX)
pub const TYPE_MD: Type = 3;

/// a mail forwarder (Obsolete - use MX)
pub const TYPE_MF: Type = 4;

/// the canonical name for an alias
pub const TYPE_CNAME: Type = 5;

/// marks the start of a zone of authority
pub const TYPE_SOA: Type = 6;

/// a mailbox domain name (EXPERIMENTAL)
pub const TYPE_MB: Type = 7;

/// a mail group member (EXPERIMENTAL)
pub const TYPE_MG: Type = 8;

/// a mail rename domain name (EXPERIMENTAL)
pub const TYPE_MR: Type = 9;

/// a null RR (EXPERIMENTAL)
pub const TYPE_NULL: Type = 10;

/// a well known service description
pub const TYPE_WKS: Type = 11;

/// a domain name pointer
pub const TYPE_PTR: Type = 12;

/// host information
pub const TYPE_HINFO: Type = 13;

/// mailbox or mail list information
pub const TYPE_MINFO: Type = 14;

/// mail exchange
pub const TYPE_MX: Type = 15;

/// text strings
pub const TYPE_TXT: Type = 16;

/// for QType
pub const TYPE_AXFR: Type = 252;

/// for QType
pub const TYPE_MAILB: Type = 253;

/// for QType
pub const TYPE_MAILA: Type = 254;

/// for QType
pub const TYPE_WILDCARDS: Type = 255;

///  the Internet
pub const CLASS_IN: Class = 1;
/// the CSNET class (Obsolete - used only for examples in  some obsolete RFCs)
pub const CLASS_CS: Class = 2;
/// the CHAOS class
pub const CLASS_CH: Class = 3;
/// Hesiod [Dyer 87]
pub const CLASS_HS: Class = 4;

/// for QClass
pub const CLASS_WILDCARDS: Class = 255;

pub type RcRf<T> = Rc<RefCell<T>>;

pub type VecRcRf<T> = Vec<RcRf<T>>;
