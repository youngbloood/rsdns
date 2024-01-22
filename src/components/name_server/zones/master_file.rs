use super::DomainTree;
use crate::{
    dns::{
        rdata::{a::A, RDataType},
        RcRf, RR, TYPE_A,
    },
    util::{decode_name, encode_name},
};
use anyhow::{anyhow, Error};
use std::{
    cell::RefCell,
    fs::{self},
    net::Ipv4Addr,
    rc::Rc,
    str::FromStr,
};

/**
 * Default Master Files
 */
pub struct DefaultMasterFiles {
    mf: String,
    tree: DomainTree,
}

impl DefaultMasterFiles {
    pub fn new(mf: &str) -> Self {
        Self {
            mf: mf.to_string(),
            tree: DomainTree::new(),
        }
    }

    pub fn calalog(&mut self) -> Vec<String> {
        let mf = String::from_str(self.mf.as_str()).unwrap();
        return vec![mf];
    }

    pub fn decode(&mut self) -> Result<(), Error> {
        let content = fs::read_to_string(self.mf.as_str())?;
        let mut line_iter = content.split('\n').into_iter();

        let parse_line = |line_data: &str| -> Result<RR, Error> {
            let sigment: Vec<&str> = line_data.split(' ').collect();
            let name = sigment.get(0).unwrap().to_string();
            let typ = sigment.get(1).unwrap().to_string().parse::<u16>()?;
            let class = sigment.get(2).unwrap().to_string().parse::<u16>()?;
            let ttl: u32 = sigment.get(3).unwrap().to_string().parse::<u32>()?;

            let mut rr = RR::new();
            rr.with_name(decode_name(name.as_str()))
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

        while let Some(line) = line_iter.next() {
            let rr = parse_line(line)?;
            let name = rr.name().to_string();
            self.tree.set_rr(name.as_str(), Rc::new(RefCell::new(rr)));
        }

        Ok(())
    }

    pub fn encode(&mut self) -> Result<(), Error> {
        let mut content = "".to_owned();
        for rrc in &self.tree.get_all_rrs() {
            let rr = rrc.as_ref().borrow();
            content.push_str(encode_name(rr.name()));
            content.push_str(&format!(" {}", rr.typ()));
            content.push_str(&format!(" {}", rr.class()));
            content.push_str(&format!(" {}", rr.ttl()));
            content.push_str(&format!(" {}", rr.rdata().as_str()));
        }
        fs::write(self.mf.as_str(), content)?;

        Ok(())
    }

    pub fn update(&mut self, domain: &str, rr: RcRf<RR>) -> Result<(), Error> {
        self.tree.set_rr(domain, rr);

        Ok(())
    }

    pub fn query(&self, domain: &str) -> Option<RcRf<RR>> {
        self.tree.get_rr(domain)
    }
}
