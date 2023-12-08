/*!
# The system administrators provide:

- The definition of zone boundaries.

- Master files of data.

- Updates to master files.

- Statements of the refresh policies desired.




+-----------------------------------------+
|               Resolver                  |


*/

mod resolver;
use std::{cell::RefCell, rc::Rc};

use anyhow::Error;

use crate::{
    dns::{Question, ResourceRecord},
    DNS,
};

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
    fn find(&self, ques: &Question) -> Option<Rc<RefCell<ResourceRecord>>>;
}

/**
 * the peer resolver of now resolver
 */
pub trait ResolvePeer {
    fn calalog(&self) -> Vec<Box<dyn ResolveOperation>>;
}

/**
 * now Resolver trait
 */
pub trait ResolveOperation {
    fn resolve(&self, dns: &mut DNS, recursive: bool) -> Result<(), Error>;
}
