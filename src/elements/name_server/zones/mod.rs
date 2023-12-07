pub mod domain_tree;
mod master_file;
pub mod zone;
use self::zone::Zones;
pub use domain_tree::DomainTree;

/**
 * The trait that list the zones for NameServer
 */
pub trait ZonesOperation {
    fn calalog_zones(&mut self) -> Vec<Zones>;
}

/** Default Zones */
pub struct DZS;

impl DZS {
    pub fn new() -> Self {
        Self
    }
}

impl ZonesOperation for DZS {
    fn calalog_zones(&mut self) -> Vec<Zones> {
        todo!()
    }
}
