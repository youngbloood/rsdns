/*!
# The system administrators provide:

- The definition of zone boundaries.

- Master files of data.

- Updates to master files.

- Statements of the refresh policies desired.



Resolver Structure:
```shell
+-------------------------------------------------------+
|                     Resolver                          |
+---------------+--------------------+------------------+
|   NameServers  |    peer_resolver1  |   peer_resolvern |
+---------------+--------------------+------------------+
```

Request Topology:


```shell
                                client
                                  |
                                  | dns packet
                                  |
                                  V        query local
                                Resolver  -------------> NameServers
                              /   |    \
                            /     |     \
       NameServers <-- Resolver --+---- Resolver --> NameServers
                            \     |     /
                             \    |    /
                               Resolver
                                  |
                                  V
                              NameServers

```
1. Then  client dns packet request the Resolver, the Resolver first step query from the local NameServers, if not found the rr, then forward the dns quest to the other.
2. The next Resolver receive a dns request, perform the same logic like the step 1.
*/

mod forward;
mod resolver;

use crate::{
    dns::{Question, RR},
    DNS,
};
use anyhow::Error;
use std::{cell::RefCell, rc::Rc};

/**
 * calalog of the NameServers
 */
pub trait NameServersQuery {
    fn calalog(&self) -> Vec<Box<dyn NameServerQuery>>;
}

/**
 * find rr by question in a NameServer
 */
pub trait NameServerQuery {
    fn find(&self, ques: &Question) -> Option<Rc<RefCell<RR>>>;
}

/**
 * the peer resolver of now resolver
 */
pub trait ResolvePeer {
    fn calalog(&self) -> Vec<Box<dyn ResolveOperation>>;
}

/**
 * Resolver Service trait
 * from_id: avoid the recursive invoke the 'resolve' or 'receive_register'
 */
pub trait ResolveOperation {
    /// resolve a dns packat
    fn resolve(&self, dns: &mut DNS, recursive: bool, from_id: u32) -> Result<(), Error>;
    /// register receive a Resolver info to register to local
    fn receive_register(&self, metadate: ResolverMetadata) -> Result<(), Error>;
    /// keep the heartbeat with the target Resolver that had registered in local
    fn heartbeat(&self, metadate: ResolverMetadata) -> Result<(), Error>;
}

pub struct ResolverMetadata {
    pub id: u32,
    pub src_addr: String,
    pub recursive: bool,
}
