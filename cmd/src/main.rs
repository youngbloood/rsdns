use anyhow::Error;
use rsdns::dns;
use rsdns::DNS;
use std::net::UdpSocket;

fn main() -> Result<(), Error> {
    let mut dns = DNS::new();
    dns.with_ques("baidu.com", dns::TYPE_A, dns::CLASS_IN);

    dns.head().with_qr(1);

    println!("dns = {:?}", &dns.encode());
    let socket = UdpSocket::bind("127.0.0.1:13400").expect("failed bind udp socket");

    let bts: [u8; 27] = [
        22, 168, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, 0, 15,
        0, 1,
    ];
    println!("dns2 = {:?}", &bts);
    let size = socket
        .send_to(&bts, "8.8.8.8:53")
        .expect("failed to send the dns request");
    println!("size = {}", size);

    Ok(())
}
