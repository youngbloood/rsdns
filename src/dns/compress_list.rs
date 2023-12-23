use nom::FindSubstring;

/**
CompressList: Save the domain_name(String) and offset(usize) as a tuple into Vector
 */
#[derive(Debug)]
pub struct CompressList(Vec<(String, usize)>);

impl CompressList {
    pub fn new() -> Self {
        Self { 0: vec![] }
    }

    fn sort(&mut self) {
        self.0.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
    }

    fn get(&self, domain: &str) -> Option<(String, usize)> {
        match self
            .0
            .binary_search_by(|probe| probe.0.cmp(&domain.to_string()))
        {
            Ok(pos) => Some(self.0.get(pos).unwrap().clone()),
            Err(_) => None,
        }
    }

    pub fn get_0(&self) -> &Vec<(String, usize)> {
        return &self.0;
    }

    /// Push the domain and the subdomain into CompressList.
    /// eg: push the "mail.google.com"
    /// then "mail.google.com", "mail.google", "google.com", "mail", "google", "com" will be pushed into CompressList.
    /// the subdomain's offset decide by param offset
    pub fn push(&mut self, domain: &str, offset: usize) {
        let col: Vec<&str> = domain.split(".").collect();
        for i in 1..col.len() + 1 {
            let mut keys = col.windows(i);
            let mut iter = keys.next();
            while iter.is_some() {
                let names = iter.as_ref().unwrap();
                let sub_domain = names.join(".");

                let mut sub_domain_offset = offset;
                let result = domain.find_substring(&sub_domain);
                if result.is_some() {
                    sub_domain_offset += result.unwrap();
                }

                match self.get(sub_domain.as_str()) {
                    Some(_) => {
                        iter = keys.next();
                        continue;
                    }
                    None => {
                        self.0.push((sub_domain, sub_domain_offset));
                        self.sort();
                        iter = keys.next();
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn compress_list_push() {
        let mut cl = CompressList::new();
        cl.push("baidu.com", 12);
        cl.push("google.com", 33);
        cl.push("mail.email.amazon.jp", 55);
        println!("cl = {:?}", cl);
    }
}
