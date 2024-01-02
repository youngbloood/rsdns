use super::header::Header;
use super::pseudo_rr::PseudoRR;
use super::question::Questions;
use super::rr::RRs;
use super::{Class, Question, RcRf, ResourceRecord, Type};
use crate::dns::compress_list::CompressList;
use anyhow::Error;
use std::cell::RefCell;
use std::fmt::Debug;
use std::rc::Rc;

/**
# DNS Structure:
```shell
+---------------------+
|        Header       |
+---------------------+
|       Question      | the question for the name server
+---------------------+
|        Answer       | RRs answering the question
+---------------------+
|      Authority      | RRs pointing toward an authority
+---------------------+
|      Additional     | RRs holding additional information
+---------------------+
```
*/

#[derive(Debug)]
pub struct DNS {
    _raw: Vec<u8>,
    _is_compressed: bool,
    _parsed_len: usize,

    head: Header,
    ques: Questions,
    answers: RRs,
    authority: RRs,
    additional: RRs,
}

impl DNS {
    pub fn new() -> Self {
        Self {
            _raw: vec![],
            _is_compressed: false,
            _parsed_len: 0,

            head: Header::new(),
            ques: Questions::new(),
            answers: RRs::new(),
            authority: RRs::new(),
            additional: RRs::new(),
        }
    }

    pub fn raw(&self) -> &Vec<u8> {
        return &self._raw;
    }

    pub fn is_compressed(&self) -> bool {
        self._is_compressed
    }

    pub fn parsed_len(&self) -> usize {
        self._parsed_len
    }

    pub fn from_fake(raw: &[u8]) -> Result<Self, Error> {
        let mut offset = 0;
        let mut dns = Self {
            _raw: raw.to_vec(),
            _is_compressed: false,
            _parsed_len: 0,
            head: Header::from(raw, &mut offset),
            ques: Questions::new(),
            answers: RRs::new(),
            authority: RRs::new(),
            additional: RRs::new(),
        };
        // parse question
        for _i in 0..dns.head.qdcount() {
            let ques = Question::from(&raw, &mut offset)?;
            dns.ques.push(ques);
        }

        Ok(dns)
    }

    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        let dns_packet_err = Err(Error::msg("the dns package not incomplete"));
        if raw.len() < 12 {
            return dns_packet_err;
        }

        let mut offset = 0;
        let mut dns = Self {
            _raw: raw.to_vec(),
            _is_compressed: false,
            _parsed_len: 0,

            head: Header::from(raw, &mut offset),
            ques: Questions::new(),
            answers: RRs::new(),
            authority: RRs::new(),
            additional: RRs::new(),
        };

        // for debug
        // println!("rcode = {}", dns.head.rcode());
        println!(
            "qd={}, an={}, ns={}, ar={}",
            dns.head.qdcount(),
            dns.head.ancount(),
            dns.head.nscount(),
            dns.head.arcount(),
        );

        // parse question
        for _i in 0..dns.head.qdcount() {
            let ques = Question::from(&raw, &mut offset)?;
            dns.ques.push(ques);
        }

        if offset > raw.len() {
            return Ok(dns);
        }
        // parse anwer
        for _i in 0..dns.head.ancount() {
            let rr = ResourceRecord::from(&raw, &mut offset, &mut dns._is_compressed)?;
            dns.answers.0.push(Rc::new(RefCell::new(rr)));
        }

        // parse authority
        for _i in 0..dns.head.nscount() {
            let rr = ResourceRecord::from(&raw, &mut offset, &mut dns._is_compressed)?;
            dns.authority.0.push(Rc::new(RefCell::new(rr)));
        }

        // parse additional
        for _i in 0..dns.head.arcount() {
            let rr = ResourceRecord::from(&raw, &mut offset, &mut dns._is_compressed)?;
            dns.additional.0.push(Rc::new(RefCell::new(rr)));
        }

        dns._parsed_len = offset;
        return Ok(dns);
    }

    pub fn head(&mut self) -> &mut Header {
        return &mut self.head;
    }

    pub fn ques(&mut self) -> &mut Questions {
        return &mut self.ques;
    }

    pub fn with_ques(&mut self, domain: &str, qtype: Type, qclass: Class) {
        let mut ques = Question::new();
        let mut names = domain.split(".");
        let mut iter = names.next();
        while iter.is_some() {
            ques.with_name(iter.unwrap());
            iter = names.next();
        }
        ques.with_qclass(qclass).with_qtype(qtype);

        self.ques.push(ques);
    }

    pub fn with_answer(&mut self, rr: RcRf<ResourceRecord>) {
        self.answers.extend(rr);
    }

    pub fn with_authority(&mut self, ns: RcRf<ResourceRecord>) {
        self.authority.extend(ns);
    }

    pub fn with_additional(&mut self, ar: RcRf<ResourceRecord>) {
        self.additional.extend(ar);
    }

    pub fn encode(&mut self, is_compressed: bool) -> Result<Vec<u8>, Error> {
        let mut result = Vec::<u8>::new();

        // set head
        self.head.with_qdcount(self.ques.len() as u16);
        self.head.with_ancount(self.answers.len() as u16);
        self.head.with_nscount(self.authority.len() as u16);
        self.head.with_arcount(self.additional.len() as u16);

        // encode head
        result.extend_from_slice(&self.head.get_0());
        let mut cl = CompressList::new();
        // encode questions
        self.ques.encode(&mut result, &mut cl);
        // encode answers
        self.answers.encode(&mut result, &mut cl, is_compressed)?;
        // encode authority
        self.authority.encode(&mut result, &mut cl, is_compressed)?;
        // encode additional
        self.additional
            .encode(&mut result, &mut cl, is_compressed)?;

        return Ok(result);
    }
}

#[cfg(test)]
mod tests {
    use crate::DNS;
    use core::panic;
    use std::fs;

    fn test_dns_from_a_file(filepath: &str) -> Option<DNS> {
        let raw_dns = fs::read(filepath).unwrap();
        // println!("filepath={}, raw_dns={:?}", filepath, raw_dns);
        println!("filepath={:?}", raw_dns);
        match DNS::from(&raw_dns) {
            Ok(mut parsed_dns) => {
                assert_eq!(
                    raw_dns.to_vec()[..parsed_dns.parsed_len()],
                    parsed_dns.encode(parsed_dns.is_compressed()).unwrap()
                );
                Some(parsed_dns)
            }
            Err(e) => {
                panic!("{}", e);
            }
        }
    }
    #[test]
    #[ignore = "for single file debug"]
    fn test_dns_from_file() {
        let dns = test_dns_from_a_file("./test_dns_raw_tsig/netflix.com_250_1");
        if dns.is_some() {
            println!("dns = {:?}", dns);
        }
    }

    #[test]
    fn test_dns_from_domain() {
        let domain = "google.com";
        let dir_path = format!("./test_dns_raw/{}", domain);

        let dir = fs::read_dir(dir_path).unwrap();
        dir.for_each(|f| {
            let f_path = f.unwrap().path();
            let filename = f_path.to_str().unwrap();

            test_dns_from_a_file(filename);
        });
    }

    #[test]
    fn test_dns_from_all() {
        let dir = fs::read_dir("./test_dns_raw").unwrap();
        dir.for_each(|f| {
            let f_path = f.unwrap().path();
            let filename = f_path.to_str().unwrap();

            if f_path.is_dir() {
                if let Ok(entry) = f_path.read_dir() {
                    entry.for_each(|_f| {
                        let _f_path = _f.as_ref().unwrap().path();
                        if _f_path.is_dir() {
                            return;
                        }
                        let _filename = _f_path.to_str().unwrap();
                        test_dns_from_a_file(_filename);
                    })
                }
                return;
            }

            test_dns_from_a_file(filename);
        });
    }
}
