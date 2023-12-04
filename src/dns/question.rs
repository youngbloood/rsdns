use super::labels::Labels;
use anyhow::Error;

/**
The question section is used to carry the "question" in most queries,
i.e., the parameters that define what is being asked.  The section
contains QDCOUNT (usually 1) entries, each of the following format:
# Question Structure:
```shell
                                1  1  1  1  1  1
  0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                                               |
/                     QNAME                     /
/                                               /
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QTYPE                     |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
|                     QCLASS                    |
+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
*/
#[derive(Debug)]
pub struct Question {
    /// cache the question's length
    length: usize,

    /**
    a domain name represented as a sequence of labels, where
    each label consists of a length octet followed by that
    number of octets.  The domain name terminates with the
    zero length octet for the null label of the root.  Note
    that this field may be an odd number of octets; no
    padding is used.
    */
    qname: Labels,

    /**
    a two octet code which specifies the type of the query.
    The values for this field include all codes valid for a
    TYPE field, together with some more general codes which
    can match more than one type of RR.
    */
    qtype: u16,

    /**
    a two octet code that specifies the class of the query.
    For example, the QCLASS field is IN for the Internet.
    */
    qclass: u16,
}

impl Question {
    pub fn new(raw: &[u8]) -> Result<Self, Error> {
        let pkg_err = Err(Error::msg("the question package not incomplete"));
        if raw.len() == 0 {
            return pkg_err;
        }

        let mut ques = Question {
            qname: Labels::new(),
            qtype: 0,
            qclass: 0,
            length: 0,
        };

        // parse domain name
        let domain_length = ques.qname.parse(&raw)?;
        if raw.len() < 4 + domain_length {
            return pkg_err;
        }
        // parse qtype
        ques.qtype = u16::from_be_bytes(raw[domain_length..domain_length + 2].try_into()?);
        // parse qclass
        ques.qclass = u16::from_be_bytes(raw[domain_length + 2..domain_length + 4].try_into()?);
        // length
        ques.length = domain_length + 4;

        return Ok(ques);
    }

    pub fn qname(&self) -> &Labels {
        return &self.qname;
    }

    pub fn length(&self) -> usize {
        return self.length;
    }

    pub fn qtype(&self) -> u16 {
        return self.qtype;
    }

    pub fn qclass(&self) -> u16 {
        return self.qclass;
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut result = Vec::<u8>::new();

        // encode domain qname
        for name in self.qname.get_0() {
            result.push(name.len() as u8);
            for v in name.as_bytes() {
                result.push(*v);
            }
        }
        result.push(b'\x00');

        // encode qtype
        for v in self.qtype.to_be_bytes() {
            result.push(v);
        }
        // encode qclass
        for v in self.qclass.to_be_bytes() {
            result.push(v);
        }

        return result;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    pub fn test_question_new() {
        // correct
        let mut ques = Question::new(&mut vec![
            // google com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // type & qclass
            0x11, 0x22, 0x33, 0x44,
        ]);
        assert_eq!(true, ques.as_ref().is_ok());
        assert_eq!(2, ques.as_ref().unwrap().qname().get_0().len());
        assert_eq!(16, ques.as_ref().unwrap().length());
        assert_eq!(
            "google",
            ques.as_ref().unwrap().qname().get_0().get(0).unwrap()
        );
        assert_eq!(
            "com",
            ques.as_ref().unwrap().qname().get_0().get(1).unwrap()
        );

        // incorrect
        let mut raw = vec![
            // google com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // qtype & qclass; qclass miss a u8
            0x11, 0x22, 0x33,
        ];
        while raw.len() != 0 {
            ques = Question::new(&mut raw);
            assert_eq!(true, ques.is_err());
            raw.pop();
        }
    }

    #[test]
    pub fn test_question_encode() {
        // correct
        let mut labels = Labels::new();
        labels
            .get_mut_0()
            .extend_from_slice(&vec!["google".to_string(), "com".to_string()]);
        println!("labels = {:?}", &labels);
        let ques = Question {
            length: 16,
            qname: labels,
            qtype: 4386,
            qclass: 13124,
        };

        let raw1: Vec<u8> = vec![
            // google com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // type & qclass
            0x11, 0x22, 0x33, 0x44,
        ];

        let raw2: Vec<u8> = vec![
            // google com
            0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            // type & qclass
            0x11, 0x22, 0x33, 0x43,
        ];

        assert_eq!(raw1, ques.encode());
        assert_ne!(raw2, ques.encode());
    }
}
