use rand::Rng;
use std::ops;

use rsbit::BitOperation;

/**
The header contains the following fields:
# Header Structure:
```shell
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                      ID                       |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    QDCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ANCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    NSCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                    ARCOUNT                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
 */

#[derive(Debug)]
pub struct Header([u8; 12]);

impl Header {
    pub fn new() -> Self {
        let mut hd = Header([0; 12]);
        let mut rng: rand::prelude::ThreadRng = rand::thread_rng();
        let id: u16 = rng.gen();
        let ids = id.to_be_bytes();
        hd.0[0] = ids[0];
        hd.0[1] = ids[1];
        return hd;
    }

    pub fn from(raw: [u8; 12]) -> Self {
        return Header(raw);
    }

    fn set_bit(&mut self, index: usize, pos: u8, val: u8) -> &mut Self {
        if index > self.0.len() || pos >= 8 || val > 1 {
            return self;
        }
        let mut b = &mut self.0[index];
        if val == 1 {
            b.set_1(pos);
        } else {
            b.set_0(pos);
        }
        self.0[index] = *b;

        return self;
    }

    /**
    A 16 bit identifier assigned by the program that
    generates any kind of query.  This identifier is copied
    the corresponding reply and can be used by the requester
    to match up replies to outstanding queries.
    */
    pub fn id(&self) -> u16 {
        let id = [self.0[0], self.0[1]];
        return u16::from_be_bytes(id);
    }

    pub fn with_id(&mut self, id: u16) -> &mut Self {
        let ids = id.to_be_bytes();
        (self.0[0], self.0[1]) = (ids[0], ids[1]);
        return self;
    }

    /**
    A one bit field that specifies whether this message is a
    query (0), or a response (1).
    */
    pub fn qr(&self) -> bool {
        return (self.0[2] & 0b1000_0000) == 0b1000_0000;
    }

    pub fn with_qr(&mut self, rd: bool) -> &mut Self {
        if rd {
            self.set_bit(2, 7, 1);
        } else {
            self.set_bit(2, 7, 0);
        }
        return self;
    }

    /**
    A four bit field that specifies kind of query in this
    message.  This value is set by the originator of a query
    and copied into the response.  The values are:
    ```shell
    0               a standard query (QUERY)
    1               an inverse query (IQUERY)
    2               a server status request (STATUS)
    3-15            reserved for future use
    ```
    */
    pub fn opcode(&self) -> u8 {
        return (self.0[2] & 0b0111_1000) >> 3;
    }

    pub fn with_opcode(&mut self, opcode: u8) -> &mut Self {
        if opcode > 0xF {
            return self;
        }
        let oc: u8 = opcode << 3;

        if oc & 0b0100_0000 == 0b0100_0000 {
            self.set_bit(2, 6, 1);
        } else {
            self.set_bit(2, 6, 0);
        }
        if oc & 0b0010_0000 == 0b0010_0000 {
            self.set_bit(2, 5, 1);
        } else {
            self.set_bit(2, 5, 0);
        }
        if oc & 0b0001_0000 == 0b0001_0000 {
            self.set_bit(2, 4, 1);
        } else {
            self.set_bit(2, 4, 0);
        }
        if oc & 0b0000_1000 == 0b0000_1000 {
            self.set_bit(2, 3, 1);
        } else {
            self.set_bit(2, 3, 0);
        }

        return self;
    }

    /**
    Authoritative Answer - this bit is valid in responses,
    and specifies that the responding name server is an
    authority for the domain name in question section.
    Note that the contents of the answer section may have
    multiple owner names because of aliases.  The AA bit
    corresponds to the name which matches the query name, or
    the first owner name in the answer section.
    */
    pub fn aa(&self) -> bool {
        return (self.0[2] & 0b0000_0100) == 0b0000_0100;
    }

    pub fn with_aa(&mut self, aa: bool) -> &mut Self {
        if aa {
            self.set_bit(2, 2, 1);
        } else {
            self.set_bit(2, 2, 0);
        }
        return self;
    }

    /**
    TrunCation - specifies that this message was truncated
    due to length greater than that permitted on the
    transmission channel.
    */
    pub fn tc(&self) -> bool {
        return (self.0[2] & 0b0000_0010) == 0b0000_0010;
    }

    pub fn with_tc(&mut self, tc: bool) -> &mut Self {
        if tc {
            self.set_bit(2, 1, 1);
        } else {
            self.set_bit(2, 1, 0);
        }
        return self;
    }

    /**
    Recursion Desired - this bit may be set in a query and
    is copied into the response.  If RD is set, it directs
    the name server to pursue the query recursively.
    Recursive query support is optional.

    other ref: https://www.rfc-editor.org/rfc/rfc1034.html#section-4.3.1
    */
    pub fn rd(&self) -> bool {
        return self.0[2] & 0b0000_0001 == 0b0000_0001;
    }

    pub fn with_rd(&mut self, rd: bool) -> &mut Self {
        if rd {
            self.set_bit(2, 0, 1);
        } else {
            self.set_bit(2, 0, 0);
        }
        return self;
    }

    /**
    Recursion Available - this be is set or cleared in a
    response, and denotes whether recursive query support is
    available in the name server.

    other ref: https://www.rfc-editor.org/rfc/rfc1034.html#section-4.3.1
    */
    pub fn ra(&self) -> bool {
        return self.0[3] & 0b1000_0000 == 0b1000_0000;
    }

    pub fn with_ra(&mut self, ra: bool) -> &mut Self {
        if ra {
            self.set_bit(3, 7, 1);
        } else {
            self.set_bit(3, 7, 0);
        }
        return self;
    }

    /**
    Reserved for future use.  Must be zero in all queries
    and responses.
    */
    pub fn z(&self) -> u8 {
        return (self.0[3] & 0b0111_0000) >> 4;
    }

    pub fn with_z(&mut self, z: u8) -> &mut Self {
        if z > 0x7 {
            return self;
        }
        let _z = z << 4;

        if _z & 0b0100_0000 == 0b0100_0000 {
            self.set_bit(3, 6, 1);
        } else {
            self.set_bit(3, 6, 0);
        }
        if _z & 0b0010_0000 == 0b0010_0000 {
            self.set_bit(3, 5, 1);
        } else {
            self.set_bit(3, 5, 0);
        }
        if _z & 0b0001_0000 == 0b0001_0000 {
            self.set_bit(3, 4, 1);
        } else {
            self.set_bit(3, 4, 0);
        }

        return self;
    }

    /**
    Response code - this 4 bit field is set as part of
    responses.  The values have the following
    interpretation:
    ```shell
    0               No error condition
    1               Format error - The name server was
                    unable to interpret the query.
    2               Server failure - The name server was
                    unable to process this query due to a
                    problem with the name server.
    3               Name Error - Meaningful only for
                    responses from an authoritative name
                    server, this code signifies that the
                    domain name referenced in the query does
                    not exist.
    4               Not Implemented - The name server does
                    not support the requested kind of query.
    5               Refused - The name server refuses to
                    perform the specified operation for
                    policy reasons.  For example, a name
                    server may not wish to provide the
                    information to the particular requester,
                    or a name server may not wish to perform
                    a particular operation (e.g., zone
                    transfer) for particular data.
    6-15            Reserved for future use.
    ```
    */
    pub fn rcode(&self) -> u8 {
        return self.0[3] & 0b0000_1111;
    }

    pub fn with_rcode(&mut self, rcode: u8) -> &mut Self {
        if rcode > 0xF {
            return self;
        }

        if rcode & 0b0000_1000 == 0b0000_1000 {
            self.set_bit(3, 3, 1);
        } else {
            self.set_bit(3, 3, 0);
        }
        if rcode & 0b0000_0100 == 0b0000_0100 {
            self.set_bit(3, 2, 1);
        } else {
            self.set_bit(3, 2, 0);
        }
        if rcode & 0b0000_0010 == 0b0000_0010 {
            self.set_bit(3, 1, 1);
        } else {
            self.set_bit(3, 1, 0);
        }
        if rcode & 0b0000_0001 == 0b0000_0001 {
            self.set_bit(3, 0, 1);
        } else {
            self.set_bit(3, 0, 0);
        }

        return self;
    }

    /**
    an unsigned 16 bit integer specifying the number of
    entries in the question section.
    */
    pub fn qdcount(&self) -> u16 {
        let qd: [u8; 2] = [self.0[4], self.0[5]];
        return u16::from_be_bytes(qd);
    }

    pub fn with_qdcount(&mut self, qdcount: u16) -> &mut Self {
        let bts = qdcount.to_be_bytes();
        (self.0[4], self.0[5]) = (bts[0], bts[1]);
        return self;
    }

    /**
    an unsigned 16 bit integer specifying the number of
    resource records in the answer section.
    */
    pub fn ancount(&self) -> u16 {
        let an = [self.0[6], self.0[7]];
        return u16::from_be_bytes(an);
    }

    pub fn with_ancount(&mut self, ancount: u16) -> &mut Self {
        let bts = ancount.to_be_bytes();
        (self.0[6], self.0[7]) = (bts[0], bts[1]);
        return self;
    }

    /**
    an unsigned 16 bit integer specifying the number of name
    server resource records in the authority records
    section.
    */
    pub fn nscount(&self) -> u16 {
        let ns = [self.0[8], self.0[9]];
        return u16::from_be_bytes(ns);
    }

    pub fn with_nscount(&mut self, nscount: u16) -> &mut Self {
        let bts = nscount.to_be_bytes();
        (self.0[8], self.0[9]) = (bts[0], bts[1]);
        return self;
    }

    /**
    an unsigned 16 bit integer specifying the number of
    resource records in the additional records section.
    */
    pub fn arcount(&self) -> u16 {
        let ar = [self.0[10], self.0[11]];
        return u16::from_be_bytes(ar);
    }

    pub fn with_arcount(&mut self, arcount: u16) -> &mut Self {
        let bts = arcount.to_be_bytes();
        (self.0[10], self.0[11]) = (bts[0], bts[1]);
        return self;
    }

    pub fn get_0(&self) -> [u8; 12] {
        return self.0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_header_id() {
        let head = Header([1, 2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(258, head.id());
    }

    #[test]
    pub fn test_header_with_id() {
        let mut head = Header([0; 12]);
        head.with_id(12);
        assert_eq!(12, head.id());
    }

    #[test]
    pub fn test_header_qr() {
        let mut head = Header([0, 0, 0xFF, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(true, head.qr());
        head = Header([0, 0, 0xF, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(false, head.qr());
    }

    #[test]
    pub fn test_header_with_qr() {
        let mut head = Header([0; 12]);
        head.with_qr(false);
        assert_eq!(false, head.qr());
        head.with_qr(true);
        assert_eq!(true, head.qr());
        head.with_qr(false);
        assert_eq!(false, head.qr());
    }

    #[test]
    pub fn test_header_opcode() {
        let mut head = Header([0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(15, head.opcode());
        head = Header([0, 0, 0b0111_1000, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(15, head.opcode());
        head = Header([0, 0, 0b0000_1000, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(1, head.opcode());
    }

    #[test]
    pub fn test_header_with_opcode() {
        let mut head = Header([0; 12]);
        head.with_opcode(12);
        assert_eq!(12, head.opcode());
        head.with_opcode(99);
        assert_eq!(12, head.opcode());
        head.with_opcode(15);
        assert_eq!(15, head.opcode());
    }

    #[test]
    pub fn test_header_aa() {
        let mut head = Header([0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(true, head.aa());
        head = Header([0, 0, 64, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(false, head.aa());
    }

    #[test]
    pub fn test_header_with_aa() {
        let mut head = Header([0; 12]);
        head.with_aa(true);
        assert_eq!(true, head.aa());
        head.with_aa(false);
        assert_eq!(false, head.aa());
    }

    #[test]
    pub fn test_header_tc() {
        let mut head = Header([0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(true, head.tc());
        head = Header([0, 0, 0b0000_0010, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(true, head.tc());
        head = Header([0, 0, 0b0000_0000, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(false, head.tc());
    }

    #[test]
    pub fn test_header_with_tc() {
        let mut head = Header([0; 12]);
        head.with_tc(true);
        assert_eq!(true, head.tc());
        head.with_tc(false);
        assert_eq!(false, head.tc());
    }

    #[test]
    pub fn test_header_rd() {
        let mut head = Header([0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(true, head.rd());
        head = Header([0, 0, 0b0000_0001, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(true, head.rd());
        head = Header([0, 0, 0b0000_0010, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(false, head.rd());
    }

    #[test]
    pub fn test_header_with_rd() {
        let mut head = Header([0; 12]);
        head.with_rd(true);
        assert_eq!(true, head.rd());
        head.with_rd(false);
        assert_eq!(false, head.rd());
    }

    #[test]
    pub fn test_header_ra() {
        let mut head = Header([0, 0, 0, 0b1000_0000, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(true, head.ra());
        head = Header([0, 0, 0, u8::MAX, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(true, head.ra());
        head = Header([0, 0, 0, 0b0100_0000, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(false, head.ra());
    }

    #[test]
    pub fn test_header_with_ra() {
        let mut head = Header([0; 12]);
        head.with_ra(true);
        assert_eq!(true, head.ra());
        head.with_ra(false);
        assert_eq!(false, head.ra());
    }

    #[test]
    pub fn test_header_z() {
        let head = Header([0, 0, 0, 0b0111_0000, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(7, head.z());
    }

    #[test]
    pub fn test_header_with_z() {
        let mut head = Header([0; 12]);
        head.with_z(1);
        assert_eq!(1, head.z());
        head.with_z(7);
        assert_eq!(7, head.z());
        head.with_z(8);
        assert_eq!(7, head.z());
    }

    #[test]
    pub fn test_header_rcode() {
        let mut head = Header([0, 0, 0, 0b0000_1111, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(15, head.rcode());
        head = Header([0, 0, 0, 0b0000_0111, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(7, head.rcode());
    }

    #[test]
    pub fn test_header_with_rcode() {
        let mut head = Header([0; 12]);
        head.with_rcode(1);
        assert_eq!(1, head.rcode());
        head.with_rcode(7);
        assert_eq!(7, head.rcode());
        head.with_rcode(15);
        assert_eq!(15, head.rcode());
        head.with_rcode(16);
        assert_eq!(15, head.rcode());
    }

    #[test]
    pub fn test_header_qdcount() {
        let head = Header([0, 0, 0, 14, 2, 4, 0, 0, 0, 0, 0, 0]);
        assert_eq!(516, head.qdcount());
    }

    #[test]
    pub fn test_header_with_qdcount() {
        let mut head = Header([0; 12]);
        head.with_qdcount(16);
        assert_eq!(16, head.qdcount());
        head.with_qdcount(516);
        assert_eq!(2, head.0[4]);
        assert_eq!(4, head.0[5]);
    }

    #[test]
    pub fn test_header_ancount() {
        let head = Header([0, 0, 0, 14, 0, 0, 2, 4, 0, 0, 0, 0]);
        assert_eq!(516, head.ancount());
    }

    #[test]
    pub fn test_header_with_ancount() {
        let mut head = Header([0; 12]);
        head.with_ancount(16);
        assert_eq!(16, head.ancount());
        head.with_ancount(516);
        assert_eq!(2, head.0[6]);
        assert_eq!(4, head.0[7]);
    }

    #[test]
    pub fn test_header_nscount() {
        let head = Header([0, 0, 0, 14, 0, 0, 0, 0, 2, 4, 0, 0]);
        assert_eq!(516, head.nscount());
    }

    #[test]
    pub fn test_header_with_nscount() {
        let mut head = Header([0; 12]);
        head.with_nscount(16);
        assert_eq!(16, head.nscount());
        head.with_nscount(516);
        assert_eq!(2, head.0[8]);
        assert_eq!(4, head.0[9]);
    }

    #[test]
    pub fn test_header_arcount() {
        let head = Header([0, 0, 0, 14, 0, 0, 0, 0, 0, 0, 2, 4]);
        assert_eq!(516, head.arcount());
    }

    #[test]
    pub fn test_header_with_arcount() {
        let mut head = Header([0; 12]);
        head.with_arcount(16);
        assert_eq!(16, head.arcount());
        head.with_arcount(516);
        assert_eq!(2, head.0[10]);
        assert_eq!(4, head.0[11]);
    }
}
