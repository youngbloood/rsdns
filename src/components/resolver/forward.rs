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
    use std::thread;

    use super::*;
    use crate::{
        dns::{
            self, Class, Type, CLASS_HS, CLASS_IN, CLASS_WILDCARDS, TYPE_A, TYPE_AXFR, TYPE_TXT,
            TYPE_WILDCARDS,
        },
        DNS,
    };

    fn test_default_forward_forward_part(domains: &[&str]) {
        let query = |domain: &str, typ: Type, class: Class| -> Result<DNS, Error> {
            let mut dns = DNS::new();
            dns.with_ques(domain, typ, class);
            dns.head().with_rd(true);
            let mut fwd: DefaultForward = DefaultForward::new();
            fwd.with_target("8.8.8.8:53").with_protocol("udp");
            let new_dns = fwd.forward(&mut dns).unwrap();

            Ok(new_dns)
        };

        let is_print = true;
        let print = |domain: &str, typ: Type, class: Class, dns: DNS| {
            if !is_print {
                return;
            }
            println!(
                "Domain[{}], Type[{}], Class[{}], ParsedDNS = {:?}",
                domain, typ, class, dns
            );
        };

        for domain in domains {
            // for debug
            // if !domain.eq(&"yahoo.co.jp") {
            //     continue;
            // }
            for typ in TYPE_A..TYPE_TXT {
                for class in CLASS_IN..CLASS_HS {
                    let result = query(domain, typ, class);
                    assert_eq!(true, result.is_ok());
                    print(domain, typ, class, result.unwrap());
                }

                let result = query(domain, typ, CLASS_WILDCARDS);
                assert_eq!(true, result.is_ok());
                print(domain, typ, CLASS_WILDCARDS, result.unwrap());
            }

            for typ in TYPE_AXFR..TYPE_WILDCARDS {
                for class in CLASS_IN..CLASS_HS {
                    let result = query(domain, typ, class);
                    assert_eq!(true, result.is_ok());
                    print(domain, typ, class, result.unwrap());
                }

                let result = query(domain, typ, CLASS_WILDCARDS);
                assert_eq!(true, result.is_ok());
                print(domain, typ, CLASS_WILDCARDS, result.unwrap());
            }
        }
    }

    #[test]
    fn test_default_forward_forward_batch() {
        // data from https://zh.wikipedia.org/wiki/%E6%9C%80%E5%8F%97%E6%AC%A2%E8%BF%8E%E7%BD%91%E7%AB%99%E5%88%97%E8%A1%A8
        // 1-10

        let domains: &[&[&str]] = &[
            &[
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
            ],
            &[
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
            ],
            &[
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
            ],
            &[
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
            ],
            &[
                "samsung.com",
                "google.com.br",
                "t.me",
                "eBay.com",
                "turbopages.org",
            ],
            &[
                "accuweather.com",
                "ok.ru",
                "bbc.co.uk",
                "fandom.com",
                "weather.com",
            ],
        ];

        let mut jhs = vec![];
        for domain in domains {
            let jh = thread::spawn(|| test_default_forward_forward_part(domain));
            jhs.push(jh);
        }

        for jh in jhs {
            let _ = jh.join();
        }
    }
}
