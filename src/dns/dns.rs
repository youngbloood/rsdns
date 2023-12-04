use anyhow::Error;

use super::header::Header;
use super::question::Question;
use super::rr::RRs;

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
pub struct DNS {
    raw: Vec<u8>,

    head: Header,
    ques: Question,
    answers: Option<RRs>,
    authority: Option<RRs>,
    additional: Option<RRs>,
}

impl DNS {
    pub fn from(raw: &[u8]) -> Result<Self, Error> {
        let dns_packet_err = Err(Error::msg("the dns package not incomplete"));
        if raw.len() < 12 {
            return dns_packet_err;
        }

        let mut dns = Self {
            raw: raw.to_vec(),

            head: Header::new(raw[..12].try_into().expect("slice covert to array error")),
            ques: todo!(),
            answers: None,
            authority: None,
            additional: None,
        };

        dns.ques = Question::new(&raw[12..])?;

        return Ok(dns);
    }

    pub fn head(&self) -> &Header {
        return &self.head;
    }

    pub fn encode(&mut self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        if self.answers.is_some() {
            self.head
                .with_ancount(self.answers.as_ref().unwrap().get_0().len() as u16);
        }
        if self.authority.is_some() {
            self.head
                .with_nscount(self.authority.as_ref().unwrap().get_0().len() as u16);
        }
        if self.additional.is_some() {
            self.head
                .with_arcount(self.additional.as_ref().unwrap().get_0().len() as u16);
        }
        result.extend_from_slice(&self.head.get_0());
        result.extend_from_slice(&self.ques.encode());
        result.extend_from_slice(&self.answers.as_ref().unwrap().encode());

        return result;
    }
}
