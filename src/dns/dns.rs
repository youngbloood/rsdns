use std::cell::RefCell;
use std::rc::Rc;

use anyhow::Error;

use super::header::Header;
use super::question::Question;
use super::rr::RRs;
use super::{Class, RcRf, ResourceRecord, Type};

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

    head: Header,
    ques: Vec<Question>,
    answers: RRs,
    authority: RRs,
    additional: RRs,
}

impl DNS {
    pub fn new() -> Self {
        Self {
            _raw: vec![],
            head: Header::new(),
            ques: vec![],
            answers: RRs::new(),
            authority: RRs::new(),
            additional: RRs::new(),
        }
    }
    pub fn from(_raw: &[u8]) -> Result<Self, Error> {
        let dns_packet_err = Err(Error::msg("the dns package not incomplete"));
        if _raw.len() < 12 {
            return dns_packet_err;
        }

        let mut split_pos = 12;

        let mut dns = Self {
            _raw: _raw.to_vec(),

            head: Header::from(
                _raw[..split_pos]
                    .try_into()
                    .expect("slice covert to array error"),
            ),
            ques: vec![],
            answers: RRs::new(),
            authority: RRs::new(),
            additional: RRs::new(),
        };

        // parse question
        for i in 0..dns.head.qdcount() {
            let ques = Question::from(&_raw[split_pos..])?;
            split_pos += ques.length();
            dns.ques.push(ques);
        }

        // parse anwer
        for i in 0..dns.head.ancount() {
            let rr = ResourceRecord::from(&_raw[split_pos..])?;
            split_pos += rr.all_length();
            dns.answers.0.push(Rc::new(RefCell::new(rr)));
        }

        // parse authority
        for i in 0..dns.head.nscount() {
            let rr = ResourceRecord::from(&_raw[split_pos..])?;
            split_pos += rr.all_length();
            dns.answers.0.push(Rc::new(RefCell::new(rr)));
        }

        // parse additional
        for i in 0..dns.head.arcount() {
            let rr = ResourceRecord::from(&_raw[split_pos..])?;
            split_pos += rr.all_length();
            dns.answers.0.push(Rc::new(RefCell::new(rr)));
        }

        return Ok(dns);
    }

    pub fn head(&mut self) -> &mut Header {
        return &mut self.head;
    }

    pub fn ques(&mut self) -> &mut Vec<Question> {
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

    pub fn encode(&mut self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        self.head.with_qdcount(self.ques.len() as u16);
        self.head.with_ancount(self.answers.len() as u16);
        self.head.with_nscount(self.authority.len() as u16);
        self.head.with_arcount(self.additional.len() as u16);

        result.extend_from_slice(&self.head.get_0());
        for ques in &self.ques {
            result.extend_from_slice(&ques.encode());
        }

        result.extend_from_slice(&self.answers.encode());
        result.extend_from_slice(&self.authority.encode());
        result.extend_from_slice(&self.additional.encode());

        return result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::DNS;

    #[test]
    fn test_dns_from() {
        let raws: [[u8; 512]; 3] = [
            [
                54, 174, 129, 128, 0, 1, 0, 6, 0, 0, 0, 0, // header 12 byte
                // question
                5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, // question name:baidu.com
                0, 15, 0, 1, // question type and class
                // answer
                192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 9, 0, 20, 4, 109, 120, 53, 48, 192, 12, 192,
                12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 9, 0, 20, 4, 106, 112, 109, 120, 192, 12, 192,
                12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 14, 0, 10, 2, 109, 120, 6, 109, 97, 105, 108,
                108, 98, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 8, 0, 20, 3, 109, 120, 49,
                192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 16, 0, 15, 2, 109, 120, 1, 110, 6,
                115, 104, 105, 102, 101, 110, 192, 18, 192, 12, 0, 15, 0, 1, 0, 0, 21, 22, 0, 11,
                0, 20, 6, 117, 115, 109, 120, 48, 49, 192, 12, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                197, 142, 129, 128, 0, 1, 0, 6, 0, 0, 0, 0, // header 12 byte
                // question
                5, 98, 97, 105, 100, 117, 3, 99, 111, 109, 0, // question name:baidu.com
                0, 15, 0, 1, // question type and class
                // answer
                192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 14, 0, 10, 2, 109, 120, 6, 109, 97, 105, 108,
                108, 98, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 11, 0, 20, 6, 117, 115,
                109, 120, 48, 49, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 8, 0, 20, 3, 109,
                120, 49, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 9, 0, 20, 4, 106, 112,
                109, 120, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 9, 0, 20, 4, 109, 120,
                53, 48, 192, 12, 192, 12, 0, 15, 0, 1, 0, 0, 20, 34, 0, 16, 0, 15, 2, 109, 120, 1,
                110, 6, 115, 104, 105, 102, 101, 110, 192, 18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
            [
                106, 174, 133, 128, 0, 1, 0, 1, 0, 0, 0, 0, // header 12 byte
                // question
                6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109,
                0, // question name:google.com
                0, 15, 0, 1, // question type and class
                // answer
                6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4,
                8, 7, 198, 46, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            ],
        ];

        for raw in raws {
            let dns = DNS::from(&raw.to_vec()).unwrap();
            println!("dns = {:?}", dns);
        }
    }
}
