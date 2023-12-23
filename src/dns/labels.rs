use crate::util;
use anyhow::Error;
use nom::AsChar;

/// The labels must follow the rules for ARPANET host names.  They must
/// start with a letter, end with a letter or digit, and have as interior
/// characters only letters, digits, and hyphen.  There are also some
/// restrictions on the length.  Labels must be 63 characters or less.
#[derive(Debug)]
pub struct Labels(pub Vec<String>);

impl Labels {
    pub fn new() -> Self {
        Labels { 0: vec![] }
    }

    pub fn from(name: &str) -> Result<Self, Error> {
        let mut labels = Labels { 0: vec![] };
        labels.0.push(name.to_string());

        Ok(labels)
    }

    pub fn extend(&mut self, labels: Labels) {
        for l in labels.0 {
            self.0.push(l);
        }
    }

    pub fn parse(raw: &[u8], offset: &mut usize) -> Result<Self, Error> {
        let mut label = Labels { 0: vec![] };
        let mut iter = raw[*offset..].as_ref().iter();
        let mut start: usize = *offset;

        let label_err: Error = Error::msg("the labels not incomplete");

        loop {
            let (mut comressed_offset, is_compressed) = util::is_compressed_wrap(&raw[start..]);
            if is_compressed {
                let lb = Self::parse(raw, &mut comressed_offset)?;
                label.extend(lb);
                break;
            }

            let u = iter.next().unwrap_or(&('\x00' as u8));
            start += 1;
            *offset += 1;
            if u.as_char().eq(&'\x00') {
                break;
            }

            let mut length = *u as usize;
            *offset += length;

            if *offset >= raw.len() {
                return Err(label_err);
            }
            label
                .0
                .push(String::from_utf8(raw[start..start + length].to_vec()).unwrap());
            // TODO: 使用skip优化
            while length > 0 {
                start += 1;
                length -= 1;
                iter.next();
            }
        }

        Ok(label)
    }

    pub fn encode_to_str(&self) -> String {
        return self.0.join(".");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_labels_from() {
        let mut offset = 0_usize;
        let label = Labels::parse(
            &vec![
                // google com
                0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
            ]
            .to_vec(),
            &mut offset,
        );
        assert_eq!(true, label.is_ok());
        assert_eq!("google", label.as_ref().unwrap().0.get(0).unwrap());
        assert_eq!("com", label.as_ref().unwrap().0.get(1).unwrap());

        let mut offset = 0_usize;
        let label = Labels::parse(
            &vec![
                // google com
                0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d,
            ]
            .to_vec(),
            &mut offset,
        );
        assert_eq!(false, label.is_ok());
    }
}
