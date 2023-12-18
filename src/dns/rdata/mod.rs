mod a;
pub mod cname;
mod hinfo;
mod wks;
use self::{a::A, cname::CName, hinfo::HInfo};
use super::{Type, TYPE_CNAME, TYPE_HINFO};
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
}

impl RDataType {
    pub fn new() -> Self {
        RDataType::None
    }

    pub fn from(raw: &[u8], _rdata: &[u8], typ: Type) -> Result<Self, Error> {
        match typ {
            TYPE_A => Ok(RDataType::A(A::from(raw)?)),
            TYPE_CNAME => Ok(RDataType::CName(CName::from(raw)?)),
            TYPE_HINFO => Ok(RDataType::HInfo(HInfo::from(raw)?)),
        }
    }
}

impl RDataOperation for RDataType {
    fn decode(&self) -> Vec<Vec<u8>> {
        match self {
            RDataType::None => todo!(),
            RDataType::A(a) => a.decode(),
            RDataType::CName(cname) => cname.decode(),
            RDataType::HInfo(hinfo) => hinfo.decode(),
        }
    }

    fn encode(&self) -> Vec<u8> {
        todo!()
    }
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
