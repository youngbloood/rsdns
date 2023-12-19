/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.4.2

# WKS RDATA format

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |                    ADDRESS                    |
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    |       PROTOCOL        |                       |
    +--+--+--+--+--+--+--+--+                       |
    |                                               |
    /                   <BIT MAP>                   /
    /                                               /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

where:

ADDRESS         An 32 bit Internet address

PROTOCOL        An 8 bit IP protocol number

<BIT MAP>       A variable length bit map.  The bit map must be a
                multiple of 8 bits long.

The WKS record is used to describe the well known services supported by
a particular protocol on a particular internet address.  The PROTOCOL
field specifies an IP protocol number, and the bit map has one bit per
port of the specified protocol.  The first bit corresponds to port 0,
the second to port 1, etc.  If the bit map does not include a bit for a
protocol of interest, that bit is assumed zero.  The appropriate values
and mnemonics for ports and protocols are specified in [RFC-1010].

For example, if PROTOCOL=TCP (6), the 26th bit corresponds to TCP port
25 (SMTP).  If this bit is set, a SMTP server should be listening on TCP
port 25; if zero, SMTP service is not supported on the specified
address.

The purpose of WKS RRs is to provide availability information for
servers for TCP and UDP.  If a server supports both TCP and UDP, or has
multiple Internet addresses, then multiple WKS RRs are used.

WKS RRs cause no additional section processing.

In master files, both ports and protocols are expressed using mnemonics
or decimal numbers.
 */

use std::net::Ipv4Addr;

use anyhow::Error;

use super::RDataOperation;

#[derive(Debug)]
pub struct WKS {
    /// An 32 bit Internet address
    addr: Ipv4Addr,

    /// An 8 bit IP protocol number
    protocol: u8,

    /// A variable length bit map.  The bit map must be a multiple of 8 bits long.
    bit_map: Vec<u8>,
}

impl WKS {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        let wks = WKS {
            addr: todo!(),
            protocol: todo!(),
            bit_map: todo!(),
        };
        Ok(wks)
    }
}

impl RDataOperation for WKS {
    fn decode(&self) -> Vec<Vec<u8>> {
        return vec![
            self.addr.octets().to_vec(),
            vec![self.protocol],
            self.bit_map.to_vec(),
        ];
    }

    fn encode(&self) -> Vec<u8> {
        let mut r = self.addr.octets().to_vec();
        r.push(self.protocol);
        r.extend_from_slice(&self.bit_map.to_vec());
        return r;
    }
}
