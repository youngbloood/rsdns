use anyhow::Error;
use rsdns::dns;
use rsdns::DNS;
use std::net::UdpSocket;

fn main() -> Result<(), Error> {
    let mut dns = DNS::new();
    dns.ques().qname().get_mut_0().push("baidu".to_owned());
    dns.ques().qname().get_mut_0().push("com".to_owned());
    dns.ques().with_qtype(dns::TYPE_WILDCARDS);
    dns.ques().with_qclass(dns::CLASS_IN);

    println!("dns = {:?}", &dns.encode());
    let socket = UdpSocket::bind("127.0.0.1:13400").expect("failed bind udp socket");
    let size = socket
        .send_to(&dns.encode(), "223.5.5.5:53")
        .expect("failed to send the dns request");
    println!("size = {}", size);

    Ok(())
}
