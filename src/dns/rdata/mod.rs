/*!
The following RR definitions are expected to occur, at least
potentially, in all classes.  In particular, NS, SOA, CNAME, and PTR
will be used in all classes, and have the same format in all classes.
Because their RDATA format is known, all domain names in the RDATA
section of these RRs may be compressed.

<domain-name> is a domain name represented as a series of labels, and
terminated by a label with zero length.  <character-string> is a single
length octet followed by that number of characters.  <character-string>
is treated as binary information, and can be up to 256 characters in
length (including the length octet).
 */

mod a;
pub mod cname;
mod hinfo;
mod mb;
mod md;
mod mf;
mod mg;
mod minfo;
mod mr;
mod mx;
mod ns;
mod null;
mod ptr;
mod soa;
mod txt;
mod wks;

use self::{
    a::A, cname::CName, hinfo::HInfo, mb::MB, md::MD, mf::MF, mg::MG, minfo::MInfo, mr::MR, mx::MX,
    ns::NS, null::Null, ptr::PTR, soa::SOA, txt::TXT, wks::WKS,
};
use super::{
    labels::Labels, Type, TYPE_A, TYPE_CNAME, TYPE_HINFO, TYPE_MB, TYPE_MD, TYPE_MF, TYPE_MG,
    TYPE_MINFO, TYPE_MR, TYPE_MX, TYPE_NS, TYPE_NULL, TYPE_PTR, TYPE_SOA, TYPE_TXT, TYPE_WKS,
};
use crate::util;
use anyhow::{bail, Error};
use std::fmt::Debug;

const ERR_RDATE_MSG: &str = "not completed rdate";
const ERR_RDATE_TYPE: &str = "not standard rdata type";

/**
   RDateOperation contains decode and encod
   decode: decode the radate that u8 slice to the concrete rdata object.
   encode: encode the concrete rdata object to u8 slice.
*/
pub trait RDataOperation: Debug {
    /// decode: decode the radate that u8 slice to the concrete rdata object.
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error>;

    /// encode: encode the concrete rdata object to u8 slice.
    fn encode(&self) -> Vec<u8>;
}

/**
RDateType union all the Object that impl the RDataOperation
 */
#[derive(Debug)]
pub enum RDataType {
    None,
    CName(CName),
    HInfo(HInfo),
    MB(MB),
    MD(MD),
    MF(MF),
    MG(MG),
    MInfo(MInfo),
    MR(MR),
    MX(MX),
    Null(Null),
    NS(NS),
    PTR(PTR),
    SOA(SOA),
    TXT(TXT),
    A(A),
    WKS(WKS),
}

impl RDataType {
    pub fn new() -> Self {
        RDataType::None
    }

    pub fn from(raw: &[u8], _rdata: &[u8], typ: Type) -> Result<Self, Error> {
        match typ {
            TYPE_CNAME => Ok(RDataType::CName(CName::from(raw, _rdata)?)),
            TYPE_HINFO => Ok(RDataType::HInfo(HInfo::from(raw, _rdata)?)),
            TYPE_MB => Ok(RDataType::MB(MB::from(raw, _rdata)?)),
            TYPE_MD => Ok(RDataType::MD(MD::from(raw, _rdata)?)),
            TYPE_MF => Ok(RDataType::MF(MF::from(raw, _rdata)?)),
            TYPE_MG => Ok(RDataType::MG(MG::from(raw, _rdata)?)),
            TYPE_MINFO => Ok(RDataType::MG(MG::from(raw, _rdata)?)),
            TYPE_MR => Ok(RDataType::MR(MR::from(raw, _rdata)?)),
            TYPE_MX => Ok(RDataType::MX(MX::from(raw, _rdata)?)),
            TYPE_NULL => Ok(RDataType::Null(Null::from(raw, _rdata)?)),
            TYPE_NS => Ok(RDataType::NS(NS::from(raw, _rdata)?)),
            TYPE_PTR => Ok(RDataType::PTR(PTR::from(raw, _rdata)?)),
            TYPE_SOA => Ok(RDataType::SOA(SOA::from(raw, _rdata)?)),
            TYPE_TXT => Ok(RDataType::TXT(TXT::from(raw, _rdata)?)),
            TYPE_A => Ok(RDataType::A(A::from(raw, _rdata)?)),
            TYPE_WKS => Ok(RDataType::WKS(WKS::from(raw, _rdata)?)),
            _ => bail!(ERR_RDATE_TYPE),
        }
    }
}

impl RDataOperation for RDataType {
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        match self {
            RDataType::CName(cname) => cname.decode(raw, rdata),
            RDataType::HInfo(hinfo) => hinfo.decode(raw, rdata),
            RDataType::MB(mb) => mb.decode(raw, rdata),
            RDataType::MD(md) => md.decode(raw, rdata),
            RDataType::MF(mf) => mf.decode(raw, rdata),
            RDataType::MG(mg) => mg.decode(raw, rdata),
            RDataType::MInfo(minfo) => minfo.decode(raw, rdata),
            RDataType::MR(mr) => mr.decode(raw, rdata),
            RDataType::MX(mx) => mx.decode(raw, rdata),
            RDataType::Null(null) => null.decode(raw, rdata),
            RDataType::NS(ns) => ns.decode(raw, rdata),
            RDataType::PTR(ptr) => ptr.decode(raw, rdata),
            RDataType::SOA(soa) => soa.decode(raw, rdata),
            RDataType::TXT(txt) => txt.decode(raw, rdata),
            RDataType::A(a) => a.decode(raw, rdata),
            RDataType::WKS(wks) => wks.decode(raw, rdata),
            _ => bail!(ERR_RDATE_TYPE),
        }
    }

    fn encode(&self) -> Vec<u8> {
        todo!()
    }
}

pub fn parse_charactor_string(_rdata: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let mut iter: std::slice::Iter<'_, u8> = _rdata.iter();
    let mut next = iter.next();
    let mut start = 0_usize;
    let mut list = vec![];
    while next.is_some() {
        let length = *next.unwrap() as usize;
        start += 1;
        if start + length > _rdata.len() {
            return Err(Error::msg("not completed charactor string"));
        }
        list.push(_rdata[start..start + length].to_vec());
        next = iter.clone().skip(length).next();
    }
    return Ok(list);
}

///  all domain names in the RDATA section of these RRs may be compressed, so we will check weather it compressed.
pub fn parse_domain_name(raw: &[u8], _rdata: &[u8]) -> Result<Labels, Error> {
    let (mut compressed_offset, is_compressed) = util::is_compressed_wrap(&_rdata);
    if is_compressed {
        return Ok(Labels::from(raw, &mut compressed_offset)?);
    }
    let mut offset = 0;

    Ok(Labels::from(_rdata, &mut offset)?)
}
// /**
// RDate define the RDate structure
//  */
// #[derive(Debug)]
// pub struct RData {
//     pub raw: Vec<u8>,
//     pub rdata: Vec<u8>,
//     pub typ: Type,
//     resource: RDataType,
// }

// impl RData {
//     pub fn new() -> Self {
//         Self {
//             raw: todo!(),
//             resource: todo!(),
//             typ: todo!(),
//             rdata: todo!(),
//         }
//     }

//     pub fn with_resource(&mut self, resource: RDataType) {
//         self.resource = resource;
//     }

//     pub fn from(raw: &[u8], _rdata: &[u8], typ: Type) -> Result<Self, Error> {
//         let mut rdata = Self {
//             raw: raw.to_vec(),
//             rdata: _rdata.to_vec(),
//             typ: todo!(),
//             resource: todo!(),
//         };

//         match typ {
//             TYPE_CNAME => {
//                 let cname = CName::from(&raw.to_vec());
//                 if cname.is_err() {
//                     return Err(cname.err().unwrap());
//                 }
//                 rdata.resource = RDataType::CName(cname.unwrap());
//             }
//             _ => todo!(),
//         }

//         Err(Error::msg("todo"))
//     }

//     pub fn encode(&self) -> Vec<u8> {
//         return self.resource.encode();
//     }
// }
