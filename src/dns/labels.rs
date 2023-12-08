use anyhow::Error;
use nom::AsChar;

/// The labels must follow the rules for ARPANET host names.  They must
/// start with a letter, end with a letter or digit, and have as interior
/// characters only letters, digits, and hyphen.  There are also some
/// restrictions on the length.  Labels must be 63 characters or less.
#[derive(Debug)]
pub struct Labels(Vec<String>);

impl Labels {
    pub fn new() -> Self {
        Labels { 0: vec![] }
    }

    pub fn parse(&mut self, raw: &[u8]) -> Result<usize, Error> {
        match Self::from(raw) {
            Ok((r, length)) => {
                *self = r;
                Ok(length)
            }
            Err(e) => Err(e),
        }
    }

    pub fn get_0(&self) -> &Vec<String> {
        return &self.0;
    }

    pub fn get_mut_0(&mut self) -> &mut Vec<String> {
        return &mut self.0;
    }

    pub fn from(raw: &[u8]) -> Result<(Self, usize), Error> {
        let mut label = Labels { 0: vec![] };
        let mut iter = raw.as_ref().into_iter();
        let mut start = 0_usize;
        let mut all_length = 0;

        let label_err: Error = Error::msg("the question package not incomplete");

        loop {
            let u = iter.next().unwrap_or(&('\x00' as u8));
            start += 1;
            all_length += 1;
            if u.as_char().eq(&'\x00') {
                break;
            }

            let mut length = *u as usize;
            all_length += length;

            if start + length >= raw.len() {
                return Err(label_err);
            }
            label
                .0
                .push(String::from_utf8(raw[start..start + length].to_vec()).unwrap());
            while length > 0 {
                iter.next();
                start += 1;
                length -= 1;
            }
        }

        Ok((label, all_length))
    }

    pub fn encode_to_str(&self) -> String {
        return self.0.join(".");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_labels_parse() {
        let mut label = Labels::new();
        let r = label.parse(
            &vec![
                // google com
                0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            ]
            .to_vec(),
        );
        assert_eq!(true, r.is_ok());
        assert_eq!(12, r.unwrap());
        assert_eq!("google", label.0.get(0).unwrap());
        assert_eq!("com", label.0.get(1).unwrap());

        let r = label.parse(
            &vec![
                // google com
                0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            ]
            .to_vec(),
        );
        assert_eq!(false, r.is_ok());
    }
}
