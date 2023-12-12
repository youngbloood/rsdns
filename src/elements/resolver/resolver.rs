use std::{cell::RefCell, fs::OpenOptions, rc::Rc};

use anyhow::Error;
use nom::Err;

use crate::dns::RcRf;

use super::{
    forward::{ForwardOperation, DF},
    NameServerQuery, NameServersQuery, ResolveOperation, ResolvePeer,
};

// struct ResolverWrapper {
//     resolver: RcRf<Resolver>,
// }

// impl ResolverWrapper {
//     fn new(resolver: RcRf<Resolver>) -> Self {
//         Self { resolver }
//     }
// }

// impl ResolveOperation for ResolverWrapper {
//     fn resolve(&self, dns: &mut crate::DNS, recursive: bool) -> Result<(), Error> {
//         self.resolver.borrow_mut().resolve(dns, recursive)
//     }
// }

// impl ResolvePeer for ResolverWrapper {
//     fn calalog(&self) -> Vec<Box<dyn ResolveOperation>> {
//         let r = self.resolver.clone();
//         Box::from(r.borrow());
//         let l: Box<dyn ResolveOperation> = Box::new();
//         Box::from(r.as_ref().into_inner() as dyn ResolveOperation);
//         return vec![l];
//     }
// }
pub struct Resolver {
    name_servers: Vec<Box<dyn NameServerQuery>>,
    peers: Vec<Box<dyn ResolveOperation>>,
    forward: Option<Box<dyn ForwardOperation>>,
}

impl Resolver {
    pub fn new() -> Self {
        Self {
            name_servers: vec![],
            peers: vec![],
            forward: Some(Box::new(DF::new())),
        }
    }

    pub fn from(
        nsq: Option<Box<dyn NameServersQuery>>,
        peer: Option<Box<dyn ResolvePeer>>,
        forward: Option<Box<dyn ForwardOperation>>,
    ) -> Self {
        let mut r = Self {
            name_servers: vec![],
            peers: vec![],
            forward: None,
        };

        if nsq.is_some() {
            r.name_servers = nsq.unwrap().calalog();
        }
        if peer.is_some() {
            r.peers = peer.unwrap().calalog();
        }
        r.forward = forward;

        return r;
    }
}

impl ResolveOperation for Resolver {
    fn resolve(&self, dns: &mut crate::DNS, recursive: bool, from_id: u32) -> Result<(), Error> {
        for ns in &self.name_servers {
            let rr = ns.find(&dns.ques());
            // TODO: 判断是否满足resolve条件
            if rr.is_some() {
                // let _rr = rr.unwrap().into_inner();
                // dns.with_answer(rr.unwrap().into_inner());
                return Ok(());
            }
        }

        for peer in &self.peers {
            peer.resolve(dns, recursive, from_id)?;
        }

        Ok(())
    }

    fn receive_register(&self, metadate: super::ResolverMetadata) -> Result<(), Error> {
        todo!()
    }

    fn heartbeat(&self, metadate: super::ResolverMetadata) -> Result<(), Error> {
        todo!()
    }
}
