use std::{
    fmt,
    net::UdpSocket,
    sync::mpsc::{self, Receiver, Sender},
    thread::{self, Thread},
};

use crate::DNS;
use anyhow::Error;

pub trait ForwardOperation {
    fn forward(&self, dns: &mut DNS) -> Result<DNS, Error>;
}

pub struct DefaultForward {
    target: String,
    protocol: String,
    port: String,

    socket: Option<UdpSocket>,
}

impl DefaultForward {
    pub fn new() -> Self {
        Self {
            target: "".to_string(),
            protocol: "".to_string(),
            port: "0".to_string(),
            socket: None,
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

    pub fn start(&mut self) {
        // https://stackoverflow.com/questions/7382906/cant-assign-requested-address-c-udp-sockets/7383682#7383682
        let addr = fmt::format(format_args!("{}:{}", "0.0.0.0", self.port));
        self.socket = Some(UdpSocket::bind(addr).expect("failed bind udp socket"));
    }

    // pub fn receive_resp(&self) -> Result<DNS, Error> {}
}

impl ForwardOperation for DefaultForward {
    fn forward(&self, dns: &mut DNS) -> Result<DNS, Error> {
        match self.protocol.as_str() {
            "udp" => {
                println!("encode dns = {:?}", &dns.encode(true)?);
                let _ = self
                    .socket
                    .as_ref()
                    .unwrap()
                    .send_to(&dns.encode(false)?, &self.target);

                let mut buff = [0u8; 512];
                let (data_len, _) = self.socket.as_ref().unwrap().recv_from(&mut buff)?;
                let resp = &buff[..data_len];
                println!("resp = {:?}", resp);

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
    use std::{
        cell::RefCell,
        fmt::format,
        fs::{self, File, OpenOptions},
        io::Write,
        path::{self, Path},
        rc::Rc,
        thread::{self},
        time::Duration,
    };

    use super::*;
    use crate::{
        dns::{
            rdata::{tsig::TSig, RDataType},
            Class, ResourceRecord, Type, CLASS_ANY, CLASS_HS, CLASS_IN, TYPE_A, TYPE_ANY,
            TYPE_AXFR, TYPE_TXT,
        },
        DNS,
    };

    fn test_default_forward_forward_part(fwd: &DefaultForward, domains: &[&str]) -> Vec<String> {
        let mut result = vec![];
        let mut query = |domain: &str, typ: Type, class: Class| -> Result<DNS, Error> {
            let mut dns = DNS::new();
            dns.with_ques(domain, typ, class);
            dns.head().with_rd(true);

            match fwd.forward(&mut dns) {
                Ok(mut new_dns) => {
                    let encoded_new_dns = new_dns.encode(new_dns.is_compressed()).unwrap();
                    let raw = new_dns.raw().to_vec();
                    // assert_eq!(raw, encoded_new_dns);

                    let mut fd = OpenOptions::new()
                        .append(true)
                        .create(true)
                        .write(true)
                        .open("1111")
                        .unwrap();
                    fd.write(&new_dns.raw());

                    Ok(new_dns)
                }
                Err(e) => Err(e),
            }
        };

        let is_print = false;
        let print = |domain: &str, typ: Type, class: Class, dns: DNS| {
            if !is_print {
                return;
            }
            println!(
                "Domain[{}], Type[{}], Class[{}], ParsedDNS = {:?}",
                domain, typ, class, dns
            );
        };

        let dur = Duration::from_micros(100);

        for domain in domains {
            // for debug
            // if !domain.eq(&"yahoo.co.jp") {
            //     continue;
            // }
            for typ in TYPE_A..TYPE_TXT {
                for class in CLASS_IN..CLASS_HS {
                    match query(domain, typ, class) {
                        Ok(new_dns) => {
                            print(domain, typ, class, new_dns);
                        }
                        Err(e) => eprintln!("{}", e),
                    }
                }

                let result = query(domain, typ, CLASS_ANY);
                assert_eq!(true, result.is_ok());
                print(domain, typ, CLASS_ANY, result.unwrap());
            }

            for typ in TYPE_AXFR..TYPE_ANY {
                for class in CLASS_IN..CLASS_HS {
                    let result = query(domain, typ, class);
                    assert_eq!(true, result.is_ok());
                    print(domain, typ, class, result.unwrap());
                }

                let result = query(domain, typ, CLASS_ANY);
                assert_eq!(true, result.is_ok());
                print(domain, typ, CLASS_ANY, result.unwrap());
            }
        }

        result
    }

    // cargo test  test_default_forward_forward_batch --  --test-threads 10
    #[test]
    fn test_default_forward_forward_batch() {
        // data from https://zh.wikipedia.org/wiki/%E6%9C%80%E5%8F%97%E6%AC%A2%E8%BF%8E%E7%BD%91%E7%AB%99%E5%88%97%E8%A1%A8
        let domains = get_wait_domains();
        // let mut jhs = vec![];

        let mut chunks = domains.chunks(200);
        let mut iter = chunks.next();

        let mut fwd: DefaultForward = DefaultForward::new();
        let mut port = 31114;
        fwd.with_target("8.8.4.4:53")
            .with_protocol("udp")
            .with_port(port.to_string().as_str());

        let _not_match = test_default_forward_forward_part(&fwd, iter.as_ref().unwrap());

        // let mut port = 31114;
        // while iter.is_some() {
        //     let jh = thread::spawn(move || {
        //         let mut fwd: DefaultForward = DefaultForward::new();
        //         fwd.with_target("8.8.4.4:53")
        //             .with_protocol("udp")
        //             .with_port(port.to_string().as_str());

        //         let _not_match = test_default_forward_forward_part(&fwd, iter.as_ref().unwrap());
        //         // println!("not-match = {:?}", not_match);
        //     });
        //     jhs.push(jh);
        //     iter = chunks.next();
        //     port += 50;
        // }

        // for jh in jhs {
        //     let _ = jh.join();
        // }
    }

    fn get_wait_domains() -> &'static [&'static str] {
        return &[
            "google.com",
            "YouTube.com",
            "Facebook.com",
            "instagram.com",
            "twitter.com",
            "baidu.com",
            "wikipedia.org",
            "yahoo.com",
            "yandex.ru",
            "xvideos.com",
            "whatsapp.com",
            "xnxx.com",
            "yahoo.co.jp",
            "amazon.com",
            "live.com",
            "netflix.com",
            "pornhub.com",
            "office.com",
            "tiktok.com",
            "reddit.com",
            "zoom.us",
            "linkedin.com",
            "vk.com",
            "xhamster.com",
            "discord.com",
            "bing.com",
            "Naver.com",
            "twitch.tv",
            "mail.ru",
            "microsoftonline.com",
            "duckduckgo.com",
            "roblox.com",
            "bilibili.com",
            "qq.com",
            "pinterest.com",
            "Microsoft.com",
            "msn.com",
            "docomo.ne.jp",
            "news.yahoo.co.jp",
            "globo.com",
            "samsung.com",
            "google.com.br",
            "t.me",
            "eBay.com",
            "turbopages.org",
            "accuweather.com",
            "ok.ru",
            "bbc.co.uk",
            "fandom.com",
            "weather.com",
        ];
    }

    fn qeury(domain: &str, typ: Type, class: Class) -> Result<DNS, Error> {
        thread::sleep(Duration::from_millis(500));
        let mut dns = DNS::new();
        dns.with_ques(domain, typ, class);
        dns.head().with_rd(true);

        let mut fwd: DefaultForward = DefaultForward::new();
        let port = 31114;
        fwd.with_target("8.8.4.4:53")
            .with_protocol("udp")
            .with_port(port.to_string().as_str())
            .start();

        fwd.forward(&mut dns)
    }

    #[test]
    fn test_one_type_one_class() {
        let domains = get_wait_domains();
        let save_dir = "./test_dns_raw_tsig";
        for domain in domains {
            let dns = qeury(&domain, 250, 1).unwrap();
            let filename = format!("{}/{}_{}_{}", save_dir, domain, 250, 1);
            let mut fd = File::open(&filename).unwrap_or(File::create(&filename).unwrap());
            fd.write(&dns.raw());
            thread::sleep(Duration::from_millis(100))
            // println!("dns = {:?}", dns);
        }
    }

    #[test]
    fn test_tsig() {
        let domain = "tieba.baidu.com";
        let typ = 250;
        let class = 1;

        let mut dns = DNS::new();
        dns.with_ques(domain, typ, class);
        dns.head().with_rd(true);

        let mut tsig = TSig::new();
        tsig.with_algorithm_name("HMAC-MD5.SIG-ALG.REG.INT")
            .with_original_id(dns.head().id())
            .with_time_signed();
        let mut tsig_rr = ResourceRecord::new();
        tsig_rr
            .with_type(typ)
            .with_class(class)
            .with_name(domain)
            .with_rdata(RDataType::TSig(tsig));
        dns.with_additional(Rc::new(RefCell::new(tsig_rr)));

        let mut fwd: DefaultForward = DefaultForward::new();
        let port = 31514;
        fwd.with_target("8.8.4.4:53")
            .with_protocol("udp")
            .with_port(port.to_string().as_str())
            .start();

        let receive_dns = fwd.forward(&mut dns).unwrap();
        println!("receive_dns = {:?}", receive_dns);
    }

    #[test]
    #[ignore]
    fn test_add_raw_dns_resp_to_file() {
        let domains = get_wait_domains();

        let mut fwd: DefaultForward = DefaultForward::new();
        let port = 31114;
        fwd.with_target("8.8.4.4:53")
            .with_protocol("udp")
            .with_port(port.to_string().as_str())
            .start();

        let query = |domain: &str, typ: Type, class: Class| -> Result<DNS, Error> {
            thread::sleep(Duration::from_millis(500));
            let mut dns = DNS::new();
            dns.with_ques(domain, typ, class);
            dns.head().with_rd(true);

            fwd.forward(&mut dns)
        };

        let write_to_file = |filename: &str, content: &[u8]| {
            let dir = path::Path::new(filename).parent().unwrap();
            if !dir.exists() {
                let _ = std::fs::create_dir(dir.as_os_str());
            }

            let mut fd = OpenOptions::new()
                .append(true)
                .create(true)
                .write(true)
                .open(filename)
                .unwrap();
            let _ = fd.write(content);
        };

        let base_dir = "test_dns_raw";

        for domain in domains {
            println!("domain = {}", domain);
            // for debug
            // if !domain.eq(&"yahoo.co.jp") {
            //     continue;
            // }
            for typ in TYPE_A..TYPE_TXT + 1 {
                for class in CLASS_IN..CLASS_HS + 1 {
                    match query(domain, typ, class) {
                        Err(e) => {
                            panic!("{}", e);
                        }
                        Ok(mut dns) => {
                            let ques = dns.ques().0.get(0).unwrap();
                            let filename = format!(
                                "./{}/{}/{}_{}",
                                base_dir,
                                ques.qname().encode_to_str(),
                                ques.qtype(),
                                ques.qclass(),
                            );
                            write_to_file(filename.as_str(), &dns.raw());
                        }
                    }
                }

                match query(domain, typ, CLASS_ANY) {
                    Err(e) => panic!("{}", e),
                    Ok(mut dns) => {
                        let ques = dns.ques().0.get(0).unwrap();
                        let filename = format!(
                            "./{}/{}/{}_{}",
                            base_dir,
                            ques.qname().encode_to_str(),
                            ques.qtype(),
                            ques.qclass(),
                        );
                        write_to_file(filename.as_str(), &dns.raw());
                    }
                }
            }

            for typ in TYPE_AXFR..TYPE_ANY + 1 {
                for class in CLASS_IN..CLASS_HS + 1 {
                    match query(domain, typ, class) {
                        Err(e) => panic!("{}", e),
                        Ok(mut dns) => {
                            let ques = dns.ques().0.get(0).unwrap();
                            let filename = format!(
                                "./{}/{}/{}_{}",
                                base_dir,
                                ques.qname().encode_to_str(),
                                ques.qtype(),
                                ques.qclass(),
                            );
                            write_to_file(filename.as_str(), &dns.raw());
                        }
                    }
                }
                match query(domain, typ, CLASS_ANY) {
                    Err(e) => panic!("{}", e),
                    Ok(mut dns) => {
                        let ques = dns.ques().0.get(0).unwrap();
                        let filename = format!(
                            "./{}/{}/{}_{}",
                            base_dir,
                            ques.qname().encode_to_str(),
                            ques.qtype(),
                            ques.qclass(),
                        );
                        write_to_file(filename.as_str(), &dns.raw());
                    }
                }
            }
        }
    }
}
