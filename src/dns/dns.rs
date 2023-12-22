use super::header::Header;
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

    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        let dns_packet_err = Err(Error::msg("the dns package not incomplete"));
        if raw.len() < 12 {
            return dns_packet_err;
        }

        let mut offset = 0;
        let mut dns = Self {
            _raw: raw.to_vec(),
            _is_compressed: false,

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

    #[test]
    fn test_dns_from() {
        // these data come from a real source data. from: 8.8.8.8:53
        let cases: &[(&[u8], String, usize, bool)] = &[
            (
                &[
                    59, 30, 129, 128, 0, 1, 0, 0, 0, 1, 0, 0, 8, 70, 97, 99, 101, 98, 111, 111,
                    107, 3, 99, 111, 109, 0, 0, 3, 0, 1, 192, 12, 0, 6, 0, 1, 0, 0, 7, 8, 0, 33, 1,
                    97, 2, 110, 115, 192, 12, 3, 100, 110, 115, 192, 12, 245, 137, 22, 81, 0, 0,
                    56, 64, 0, 0, 7, 8, 0, 9, 58, 128, 0, 0, 1, 44,
                ],
                "Facebook.com".to_string(),
                0,
                true,
            ),
            // compressed msg
            (
                &[
                    54, 174, 129, 128, 0, 1, 0, 6, 0, 0, 0, 0, // header 12 byte
                    // question
                    5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, // question name:baidu.com
                    0, 15, 0, 1, // question type and class
                    // answer
                    192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 9, 0, 20, 4, 109, 120, 53, 48, 192, 12,
                    192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 9, 0, 20, 4, 106, 112, 109, 120, 192,
                    12, 192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 14, 0, 10, 2, 109, 120, 6, 109, 97,
                    105, 108, 108, 98, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 8, 0, 20, 3,
                    109, 120, 49, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 16, 0, 15, 2,
                    109, 120, 1, 110, 6, 115, 104, 105, 102, 101, 110, 192, 18, 192, 12, 0, 15, 0,
                    1, 0, 0, 21, 22, 0, 11, 0, 20, 6, 117, 115, 109, 120, 48, 49, 192, 12,
                ],
                "baidu.com".to_string(),
                6,
                true,
            ),
            // compressed msg
            (
                &[
                    197, 142, 129, 128, 0, 1, 0, 6, 0, 0, 0, 0, // header 12 byte
                    // question
                    5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, // question name:baidu.com
                    0, 15, 0, 1, // question type and class
                    // answer
                    192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 14, 0, 10, 2, 109, 120, 6, 109, 97, 105,
                    108, 108, 98, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 11, 0, 20, 6,
                    117, 115, 109, 120, 48, 49, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 8,
                    0, 20, 3, 109, 120, 49, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 9, 0,
                    20, 4, 106, 112, 109, 120, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 9,
                    0, 20, 4, 109, 120, 53, 48, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 16,
                    0, 15, 2, 109, 120, 1, 110, 6, 115, 104, 105, 102, 101, 110, 192, 18,
                ],
                "baidu.com".to_string(),
                6,
                true,
            ),
            // uncompressed msg
            (
                &[
                    106, 174, 133, 128, 0, 1, 0, 1, 0, 0, 0, 0, // header 12 byte
                    // question
                    6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109,
                    0, // question name:google.com
                    0, 15, 0, 1, // question type and class
                    // answer
                    6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 60, 0,
                    4, 8, 7, 198, 46,
                ],
                "google.com".to_string(),
                1,
                false,
            ),
            (
                &[
                    96, 5, 129, 128, 0, 1, 0, 5, 0, 0, 0, 0, 5, 98, 97, 105, 100, 117, 3, 99, 111,
                    109, 0, 0, 2, 0, 1, // rr1
                    192, 12, // rr1.name
                    0, 2, // rr1.typ
                    0, 1, // rr1.class
                    0, 0, 58, 151, // rr1.ttl
                    0, 6, // rr1.rdlength
                    3, 100, 110, 115, 192, 12, // rr1.rdata
                    // rr2
                    192, 12, // rr2.name
                    0, 2, // rr2.typ
                    0, 1, // rr2.class
                    0, 0, 58, 151, // rr2.ttl
                    0, 6, // rr2.rdlength
                    3, 110, 115, 51, 192, 12, // rr2.rdata
                    // rr3
                    192, 12, // rr3.name
                    0, 2, // rr3.typ
                    0, 1, //  rr3.class
                    0, 0, 58, 151, // rr3.ttl
                    0, 6, // rr3.rdlength
                    3, 110, 115, 55, 192, 12, // rr3.rdata
                    // rr4
                    192, 12, // rr4.name
                    0, 2, // rr4.typ
                    0, 1, //  rr4.class
                    0, 0, 58, 151, // rr4.ttl
                    0, 6, // rr4.rdlength
                    3, 110, 115, 50, 192, 12, // rr4.rdata
                    // rr5
                    192, 12, // rr5.name
                    0, 2, // rr5.typ
                    0, 1, //  rr5.class
                    0, 0, 58, 151, // rr5.ttl
                    0, 6, // rr5.rdlength
                    3, 110, 115, 52, 192, 12, // rr5.rdata
                ],
                "baidu.com".to_string(),
                5,
                true,
            ),
            (
                &[
                    160, 247, 129, 128, 0, 1, 0, 2, 0, 0, 0, 0, 5, 98, 97, 105, 100, 117, 3, 99,
                    111, 109, 0, 0, 1, 0, 1, 192, 12, 0, 1, 0, 1, 0, 0, 1, 49, 0, 4, 110, 242, 68,
                    66, 192, 12, 0, 1, 0, 1, 0, 0, 1, 49, 0, 4, 39, 156, 66, 10,
                ],
                "baidu.com".to_string(),
                2,
                true,
            ),
            (
                &[
                    227, 91, 129, 128, 0, 1, 0, 4, 0, 0, 0, 0, 5, 121, 97, 104, 111, 111, 2, 99,
                    111, 2, 106, 112, 0, 0, 15, 0, 1, 192, 12, 0, 15, 0, 1, 0, 0, 1, 255, 0, 13, 0,
                    10, 3, 109, 120, 49, 4, 109, 97, 105, 108, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0,
                    1, 255, 0, 8, 0, 10, 3, 109, 120, 50, 192, 47, 192, 12, 0, 15, 0, 1, 0, 0, 1,
                    255, 0, 8, 0, 10, 3, 109, 120, 51, 192, 47, 192, 12, 0, 15, 0, 1, 0, 0, 1, 255,
                    0, 8, 0, 10, 3, 109, 120, 53, 192, 47,
                ],
                "yahoo.co.jp".to_string(),
                4,
                true,
            ),
        ];

        for cs in cases {
            let mut dns = DNS::from(&cs.0.to_vec()).unwrap();
            assert_eq!(cs.2, dns.answers.len());
            if cs.2 != 0 {
                assert_eq!(cs.1, dns.answers.0.get(0).as_ref().unwrap().borrow().name());
            }

            println!("dns = {:?}", dns);
            let compression = dns.encode(cs.3).unwrap();
            assert_eq!(cs.0, compression);
            let parse_self_dns = DNS::from(&compression.to_vec()).unwrap();
            println!("parse_encoded_dns: dns = {:?}", parse_self_dns);
        }
    }
}
