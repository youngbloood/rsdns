use std::{fmt, net::UdpSocket};

use crate::DNS;
use anyhow::Error;

pub trait ForwardOperation {
    fn forward(&self, dns: &mut DNS) -> Result<DNS, Error>;
}

pub struct DefaultForward {
    target: String,
    protocol: String,
    port: String,
}

impl DefaultForward {
    pub fn new() -> Self {
        Self {
            target: "".to_string(),
            protocol: "".to_string(),
            port: "0".to_string(),
        }
    }

    pub fn with_target(&mut self, target: &str) -> &mut Self {
        self.target = target.to_string();
        return self;
    }
    pub fn with_protocol(&mut self, protocol: &str) -> &mut Self {
        self.protocol = protocol.to_string();
        return self;
    }

    pub fn with_port(&mut self, port: &str) -> &mut Self {
        self.port = port.to_string();
        return self;
    }
}

impl ForwardOperation for DefaultForward {
    fn forward(&self, dns: &mut DNS) -> Result<DNS, Error> {
        match self.protocol.as_str() {
            "udp" => {
                // https://stackoverflow.com/questions/7382906/cant-assign-requested-address-c-udp-sockets/7383682#7383682
                let addr = fmt::format(format_args!("{}:{}", "0.0.0.0", self.port));
                let socket = UdpSocket::bind(addr).expect("failed bind udp socket");

                socket
                    .connect(&self.target)
                    .expect("connect to google dns failed");

                socket.send(&dns.encode(false)?).expect("query dns failed");

                let mut buff = [0u8; 512];
                let (data_len, _) = socket.recv_from(&mut buff)?;
                let resp = &buff[..data_len];
                let new_dns: DNS = DNS::from(resp)?;

                Ok(new_dns)
            }
            _ => Err(Error::msg(
                "not found the match protocol to forward the dns request",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{dns, DNS};

    #[test]
    fn test_default_forward_forward() {
        let mut dns = DNS::new();
        dns.with_ques("google.com", dns::TYPE_MX, dns::CLASS_IN);
        dns.with_ques("baidu.com", dns::TYPE_MX, dns::CLASS_IN);
        dns.head().with_rd(true);
        println!("dns1 = {:?}", &dns.encode(false));

        let mut fwd: DefaultForward = DefaultForward::new();
        fwd.with_target("8.8.8.8:53").with_protocol("udp");
        let new_dns = fwd.forward(&mut dns).unwrap();
        println!("new_dns = {:?}", new_dns);
    }
}
