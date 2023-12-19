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
mod wks;
use crate::util;

use self::{a::A, cname::CName, hinfo::HInfo, mb::MB, md::MD, mf::MF, mg::MG, minfo::MInfo};
use super::{labels::Labels, Type, TYPE_CNAME, TYPE_HINFO, TYPE_MB, TYPE_MD, TYPE_MINFO};
use anyhow::Error;
use std::fmt::Debug;

pub trait RDataOperation: Debug {
    fn decode(&self) -> Vec<Vec<u8>>;
    fn encode(&self) -> Vec<u8>;
}

/**
RDateType union all the Object that impl the RDataOperation
 */
#[derive(Debug)]
pub enum RDataType {
    None,
    A(A),
    CName(CName),
    HInfo(HInfo),
    MB(MB),
    MD(MD),
    MF(MF),
    MG(MG),
    MInfo(MInfo),
}

impl RDataType {
    pub fn new() -> Self {
        RDataType::None
    }

    pub fn from(raw: &[u8], _rdata: &[u8], typ: Type) -> Result<Self, Error> {
        match typ {
            TYPE_A => {
                return Ok(RDataType::A(A::from(_rdata)?));
            }

            TYPE_CNAME => {
                let labels = parse_domain_name(raw, _rdata)?;
                return Ok(RDataType::CName(CName::from(
                    labels.encode_to_str().as_bytes(),
                )?));
            }

            TYPE_HINFO => Ok(RDataType::HInfo(HInfo::from(_rdata)?)),

            TYPE_MB => {
                let labels = parse_domain_name(raw, _rdata)?;
                return Ok(RDataType::MB(MB::from(labels.encode_to_str().as_bytes())?));
            }

            TYPE_MD => {
                let labels = parse_domain_name(raw, _rdata)?;
                return Ok(RDataType::MD(MD::from(labels.encode_to_str().as_bytes())?));
            }

            TYPE_MF => {
                let labels = parse_domain_name(raw, _rdata)?;
                return Ok(RDataType::MF(MF::from(labels.encode_to_str().as_bytes())?));
            }

            TYPE_MG => {
                let labels = parse_domain_name(raw, _rdata)?;
                return Ok(RDataType::MG(MG::from(labels.encode_to_str().as_bytes())?));
            }

            TYPE_MINFO => {
                let labels = parse_domain_name(raw, _rdata)?;
                return Ok(RDataType::MG(MG::from(labels.encode_to_str().as_bytes())?));
            }
        }
    }
}

impl RDataOperation for RDataType {
    fn decode(&self) -> Vec<Vec<u8>> {
        match self {
            RDataType::None => vec![],
            RDataType::A(a) => a.decode(),
            RDataType::CName(cname) => cname.decode(),
            RDataType::HInfo(hinfo) => hinfo.decode(),
            RDataType::MB(mb) => mb.decode(),
            RDataType::MD(md) => md.decode(),
            RDataType::MF(mf) => mf.decode(),
            RDataType::MG(mg) => mg.decode(),
            RDataType::MInfo(minfo) => minfo.decode(),
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
