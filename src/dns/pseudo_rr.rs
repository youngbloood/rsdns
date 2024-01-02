use super::{ResourceRecord, TYPE_OPT};

#[derive(Debug)]
pub struct PseudoRR(pub ResourceRecord);

impl PseudoRR {
    pub fn new(rr: ResourceRecord) -> Self {
        Self { 0: rr }
    }

    fn udp_payload(&self) -> usize {
        if self.0.typ() != TYPE_OPT {
            return 0;
        }

        self.0.class() as usize
    }

    fn rcode(&self, head_rcode: u8) -> u16 {
        if self.0.typ() != TYPE_OPT {
            return 0;
        }

        let ttl = self.0.ttl();
        let rc = [head_rcode, ttl.to_be_bytes()[0]];

        u16::from_be_bytes(rc)
    }

    fn version(&self) -> u8 {
        if self.0.typ() != TYPE_OPT {
            return 0;
        }

        self.0.ttl().to_be_bytes()[1]
    }

    fn z(&self) -> u16 {
        if self.0.typ() != TYPE_OPT {
            return 0;
        }

        u16::from_be_bytes(self.0.ttl().to_be_bytes()[2..].try_into().expect("111"))
    }
}
