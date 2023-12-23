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
    compress_list::CompressList, labels::Labels, Type, TYPE_A, TYPE_CNAME, TYPE_HINFO, TYPE_MB,
    TYPE_MD, TYPE_MF, TYPE_MG, TYPE_MINFO, TYPE_MR, TYPE_MX, TYPE_NS, TYPE_NULL, TYPE_PTR,
    TYPE_SOA, TYPE_TXT, TYPE_WKS,
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
    fn encode(
        &self,
        raw: &mut Vec<u8>,
        cl: &mut CompressList,
        is_compressed: bool,
    ) -> Result<(), Error>;
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

    fn encode(
        &self,
        raw: &mut Vec<u8>,
        cl: &mut CompressList,
        is_compressed: bool,
    ) -> Result<(), Error> {
        match self {
            RDataType::CName(cname) => cname.encode(raw, cl, is_compressed),
            RDataType::HInfo(hinfo) => hinfo.encode(raw, cl, is_compressed),
            RDataType::MB(mb) => mb.encode(raw, cl, is_compressed),
            RDataType::MD(md) => md.encode(raw, cl, is_compressed),
            RDataType::MF(mf) => mf.encode(raw, cl, is_compressed),
            RDataType::MG(mg) => mg.encode(raw, cl, is_compressed),
            RDataType::MInfo(minfo) => minfo.encode(raw, cl, is_compressed),
            RDataType::MR(mr) => mr.encode(raw, cl, is_compressed),
            RDataType::MX(mx) => mx.encode(raw, cl, is_compressed),
            RDataType::Null(null) => null.encode(raw, cl, is_compressed),
            RDataType::NS(ns) => ns.encode(raw, cl, is_compressed),
            RDataType::PTR(ptr) => ptr.encode(raw, cl, is_compressed),
            RDataType::SOA(soa) => soa.encode(raw, cl, is_compressed),
            RDataType::TXT(txt) => txt.encode(raw, cl, is_compressed),
            RDataType::A(a) => a.encode(raw, cl, is_compressed),
            RDataType::WKS(wks) => wks.encode(raw, cl, is_compressed),
            _ => bail!(ERR_RDATE_TYPE),
        }
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
pub fn parse_domain_name(raw: &[u8], rdata: &[u8]) -> Result<Vec<Labels>, Error> {
    let mut list = vec![];
    let mut offset = 0;
    while offset < rdata.len() {
        let mut labels = Labels::new();
        loop {
            if rdata[offset] == b'\x00' {
                offset += 1;
                break;
            }
            let (mut compressed_offset, is_compressed) = util::is_compressed_wrap(&rdata[offset..]);
            if is_compressed {
                offset += 2;
                labels.extend(Labels::parse(raw, &mut compressed_offset)?);
                break;
            } else {
                let len = rdata[offset];
                let start = offset + 1;
                labels.extend(Labels::from(
                    String::from_utf8(rdata[start..start + len as usize].to_vec())?.as_str(),
                )?);
                offset += 1 + len as usize;
            }
            if offset >= rdata.len() {
                return Err(Error::msg(ERR_RDATE_MSG));
            }
        }
        list.push(labels)
    }

    Ok(list)
}

/// encode domain name
pub fn encode_domain_name(domain_name: &str) -> Vec<u8> {
    let mut r: Vec<u8> = vec![];

    let mut names = domain_name.split(".").into_iter();
    let mut iter = names.next();
    while iter.is_some() {
        r.push(iter.unwrap().len() as u8);
        r.extend_from_slice(&iter.unwrap().as_bytes().to_vec());
        iter = names.next();
    }
    r.push(b'\x00');

    r
}

pub fn encode_domain_name_wrap(
    domain_name: &str,
    cl: &mut CompressList,
    is_compressed: bool,
    raw_offset: usize,
) -> Result<Vec<u8>, Error> {
    if !is_compressed {
        return Ok(encode_domain_name(domain_name));
    }
    let encode = |domain: &str| -> Vec<u8> {
        let mut r: Vec<u8> = vec![];
        let mut names = domain.split(".").into_iter();
        let mut iter = names.next();
        while iter.is_some() && iter.unwrap().len() != 0 {
            r.push(iter.unwrap().len() as u8);
            r.extend_from_slice(&iter.unwrap().as_bytes().to_vec());
            iter = names.next();
        }

        r
    };

    for (domain, offset) in cl.get_0() {
        match domain_name.find(&*domain) {
            Some(pos) => {
                // don't need compress this domain, cause the length equal the compressed length
                if domain.len() <= 2 {
                    continue;
                }

                // guarant the side of the domain in domain_name is dot
                // Example:
                // domain_name is "dns.Facebook.com"
                // but domain in CompressList is "ns.Facebook.com", maybe it is a substring of "a.ns.Facebook.com" add to CompressList
                // then will match domain_name.find(&*domain) to Some(_) branch
                // but this should not matched and don't compress
                // so we will check over the domain's side weather is dot
                if (pos != 0 && domain_name.as_bytes()[pos - 1] != b'.')
                    || pos + domain.len() + 1 < domain_name.len()
                        && domain_name.as_bytes()[pos + domain.len() + 1] != b'.'
                {
                    continue;
                }

                let mut list = vec![];
                // encode the preffix str exclude the domain in domain_name
                if domain_name[..pos].len() != 0 {
                    list.extend_from_slice(&encode(&domain_name[..pos]));
                }
                // pointer: offset
                let mut compressed_unit = (*offset as u16).to_be_bytes();
                // pointer: compressed flag
                compressed_unit[0] |= 0b1100_0000;
                list.extend(compressed_unit);

                // encode the suffix str exclude the domain in domain_name
                if domain_name[pos + domain.len()..].len() != 0 {
                    list.extend_from_slice(&encode(&domain_name[pos + domain.len()..]));
                    list.push(b'\x00');
                }

                // update the exist domain_name in CompressList
                cl.push(domain_name, raw_offset);
                return Ok(list);
            }
            None => continue,
        }
    }

    // update the exist domain_name in CompressList
    cl.push(domain_name, raw_offset);

    Ok(encode_domain_name(domain_name))
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

#[cfg(test)]
mod tests {
    use super::parse_domain_name;

    #[test]
    fn test_parse_domain_name_without_raw() {
        let rdatas: &[(&[u8], bool)] = &[
            (
                &[3, 100, 110, 115, 1, 115, 0, 3, 97, 98, 99, 1, 116, 0],
                true,
            ),
            (&[3, 100, 110, 115, 1, 115, 0, 3, 97, 98, 99, 1, 116], false),
        ];

        for rdata in rdatas {
            let labels = parse_domain_name(&[], rdata.0);
            assert_eq!(rdata.1, labels.is_ok());
            if labels.is_ok() {
                println!("labels = {:?}", labels);
            }
        }
    }
}
