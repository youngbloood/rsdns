use crate::dns::{
    rdata::{a::A, RDataType},
    RcRf, RR, TYPE_A,
};
use anyhow::{anyhow, Error};
use std::{
    fs::{self},
    net::Ipv4Addr,
    str::FromStr,
};

/**
 * The Operation of Master Files
 * calalog: list the Master Files
 * decode: read the Master File and decode the content to ResourceRecords
 * encode: encode vector ResourceRecords into a file
 */
pub trait MasterFileOperation {
    type Item;

    /// new with master file
    fn new(mf: &str) -> Self::Item;

    /// get the master files
    fn calalog(&mut self) -> Vec<String>;

    /// decode the master files to ResourceRecord
    fn decode(&mut self) -> Result<(), Error>;

    /// encode the ResourceRecords in to master file
    fn encode(&mut self) -> Result<(), Error>;

    fn update(&mut self, index: usize, rr: RcRf<RR>) -> Result<(), Error>;
}

/**
 * Default Master Files
 */
pub struct DefaultMasterFiles {
    mf: String,
    rrs: Vec<RR>,
}

impl MasterFileOperation for DefaultMasterFiles {
    type Item = DefaultMasterFiles;

    fn new(mf: &str) -> Self {
        Self {
            mf: mf.to_string(),
            rrs: vec![],
        }
    }

    fn calalog(&mut self) -> Vec<String> {
        let mf = String::from_str(self.mf.as_str()).unwrap();
        return vec![mf];
    }

    fn decode(&mut self) -> Result<(), Error> {
        let content = fs::read_to_string(self.mf.as_str())?;
        let mut line_iter = content.split('\n').into_iter();
        let mut line = line_iter.next();

        let parse_line = |line_data: &str| -> Result<RR, Error> {
            let sigment: Vec<&str> = line_data.split(' ').collect();
            let name = sigment.get(0).unwrap().to_string();
            let typ = sigment.get(1).unwrap().to_string().parse::<u16>()?;
            let class = sigment.get(2).unwrap().to_string().parse::<u16>()?;
            let ttl: u32 = sigment.get(3).unwrap().to_string().parse::<u32>()?;

            let mut rr = RR::new();
            rr.with_name(name.as_str())
                .with_type(typ)
                .with_class(class)
                .with_ttl(ttl);

            match typ {
                TYPE_A => {
                    let ipv4 = Ipv4Addr::from_str(sigment.get(4).unwrap())?;
                    let a = A::new(ipv4);
                    rr.with_rdata(RDataType::A(a));

                    return Ok(rr);
                }
                _ => Err(anyhow!("not support master file type")),
            }
        };

        while line.is_some() {
            self.rrs.push(parse_line(line.unwrap())?);
            line = line_iter.next();
        }

        Ok(())
    }

    fn encode(&mut self) -> Result<(), Error> {
        let mut content = "".to_owned();
        for rr in &self.rrs {
            content.push_str(rr.name());
            content.push_str(&format!(" {}", rr.typ()));
            content.push_str(&format!(" {}", rr.class()));
            content.push_str(&format!(" {}", rr.ttl()));
            content.push_str(&format!(" {}", rr.rdata().as_str()));
        }
        fs::write(self.mf.as_str(), content)?;

        Ok(())
    }

    fn update(&mut self, index: usize, rr: RcRf<RR>) -> Result<(), Error> {
        let src_rr = self.rrs.get_mut(index).unwrap();
        if rr.borrow().name().len() != 0 {
            src_rr.with_name(rr.borrow().name());
        }
        if rr.borrow().typ() != 0 {
            src_rr.with_type(rr.borrow().typ());
        }
        if rr.borrow().class() != 0 {
            src_rr.with_class(rr.borrow().class());
        }
        if rr.borrow().ttl() != 0 {
            src_rr.with_ttl(rr.borrow().ttl());
        }
        if *rr.borrow().rdata() != RDataType::None {
            src_rr.rdata_mut().update(rr.borrow().rdata())?;
        }

        Ok(())
    }
}
