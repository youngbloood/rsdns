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

        let mut dns = Self {
            _raw: _raw.to_vec(),

            head: Header::from(_raw[..12].try_into().expect("slice covert to array error")),
            ques: vec![],
            answers: RRs::new(),
            authority: RRs::new(),
            additional: RRs::new(),
        };

        dns.ques.push(Question::from(&_raw[12..])?);

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
