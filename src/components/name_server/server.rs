use super::zones::{zone::Zones, DefaultZones, ZonesOperation};
use crate::{dns::VecRcRf, DNS};
use anyhow::{Error, Result};
use bytes::{Bytes, BytesMut};
use nom::AsBytes;
use std::{cell::RefCell, fmt::format, io::Cursor, rc::Rc};
use tokio::{self, io::AsyncReadExt};

/**
  The domain system provides:
  - Standard formats for resource data.
  - Standard methods for querying the database.
  - Standard methods for name servers to refresh local data from
    foreign name servers.
*/
pub struct NameServer {
    protocol: String,
    port: String,
    zones: VecRcRf<Zones>,
}

unsafe impl Sync for NameServer {}
unsafe impl Send for NameServer {}

impl NameServer {
    pub fn new() -> Self {
        let mut ns = NameServer {
            zones: vec![],
            protocol: "udp".to_string(),
            port: "53".to_string(),
        };

        let zones: Vec<Zones> = DefaultZones::new().calalog_zones();
        for zone in zones {
            ns.zones.push(Rc::new(RefCell::new(zone)));
        }

        ns
    }

    pub fn from(mut zoneser: Box<dyn ZonesOperation>) -> Self {
        let mut ns = NameServer {
            zones: vec![],
            protocol: String::new(),
            port: "53".to_string(),
        };
        let zones = zoneser.calalog_zones();
        for zone in zones {
            ns.zones.push(Rc::new(RefCell::new(zone)));
        }
        return ns;
    }

    // start serve, it will block till the progress quit
    pub async fn serve(&'static self) -> Result<()> {
        match self.protocol.as_str() {
            "udp" => {
                let port = self.port.as_str();
                let sock = tokio::net::UdpSocket::bind(format!("0.0.0.0:{}", port))
                    .await
                    .expect("bind udp failed");
                loop {
                    let mut bts = bytes::BytesMut::new();
                    let size = sock.recv(bts.as_mut()).await.unwrap();
                    unsafe { bts.set_len(size) };

                    let dns_query = DNS::from(bts.as_bytes()).expect("parse dns packet err");
                    tokio::spawn(async move { self.query(dns_query) });
                }
            }

            "tcp" => {
                let port = self.port.as_str();
                let sock = tokio::net::TcpListener::bind(format!("0.0.0.0:{}", port))
                    .await
                    .expect("bind udp failed");
                loop {
                    let (tcp_stream, sock_addr) = sock.accept().await.unwrap();
                    tokio::spawn(async move {
                        let (mut rh, wh) = tcp_stream.into_split();
                        let mut buf = Vec::new();
                        if let Ok(n) = rh.read_to_end(&mut buf).await {
                            if n == 0 {
                                // socket closed
                                return;
                            }
                        }
                        let bts = Bytes::from(buf);
                        let dns_query = DNS::from(bts.as_bytes()).expect("parse dns packet err");
                        tokio::spawn(async move { self.query(dns_query) });
                    });
                }
            }
            _ => todo!(),
        }
    }

    pub async fn query(&self, dns_packet: DNS) -> DNS {
        let mut new_dns = DNS::new();
        for ques in &dns_packet.ques().0 {
            new_dns.with_ques(
                ques.qname().encode_to_str().as_str(),
                ques.qtype(),
                ques.qclass(),
            )
        }

        let mut rrs = vec![];
        for zone in &self.zones {
            rrs.extend(zone.clone().borrow().get_rr(dns_packet.ques()))
        }
        for rr in rrs {
            new_dns.with_additional(rr.clone())
        }

        return new_dns;
    }
}

// impl NameServerOperation for NameServer {
//     fn find(&mut self, ques: &Question) -> Option<RcRf<RR>> {
//         for zone in &self.zones {
//             let rr = zone.borrow().get_rr(ques);
//             if rr.is_some() {
//                 return rr;
//             }
//         }

//         return None;
//     }
// }
