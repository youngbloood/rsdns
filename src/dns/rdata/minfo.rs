/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.7

# MINFO RDATA format (EXPERIMENTAL)
```shell
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    RMAILBX                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    EMAILBX                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
```
where:

RMAILBX         A <domain-name> which specifies a mailbox which is
                responsible for the mailing list or mailbox.  If this
                domain name names the root, the owner of the MINFO RR is
                responsible for itself.  Note that many existing mailing
                lists use a mailbox X-request for the RMAILBX field of
                mailing list X, e.g., Msgroup-request for Msgroup.  This
                field provides a more general mechanism.


EMAILBX         A <domain-name> which specifies a mailbox which is to
                receive error messages related to the mailing list or
                mailbox specified by the owner of the MINFO RR (similar
                to the ERRORS-TO: field which has been proposed).  If
                this domain name names the root, errors should be
                returned to the sender of the message.

MINFO records cause no additional section processing.  Although these
records can be associated with a simple mailbox, they are usually used
with a mailing list.
 */

use super::{encode_domain_name_wrap, parse_domain_name, RDataOperation};
use crate::dns::rdata::ERR_RDATE_MSG;
use anyhow::{anyhow, Error};
use std::collections::HashMap;

#[derive(Debug)]
pub struct MInfo {
    pub rmail_bx: String,
    pub email_bx: String,
}

impl MInfo {
    pub fn from(raw: &[u8], rdata: &[u8]) -> Result<Self, Error> {
        let mut minfo = Self {
            rmail_bx: "".to_string(),
            email_bx: "".to_string(),
        };
        minfo.decode(raw, rdata)?;

        Ok(minfo)
    }
}

impl RDataOperation for MInfo {
    fn decode(&mut self, raw: &[u8], rdata: &[u8]) -> Result<(), Error> {
        let list = parse_domain_name(raw, rdata)?;
        if list.len() < 2 {
            return Err(anyhow!(ERR_RDATE_MSG));
        }
        self.rmail_bx = list.get(0).unwrap().encode_to_str();
        self.email_bx = list.get(1).unwrap().encode_to_str();

        Ok(())
    }

    fn encode(&self, hm: &HashMap<String, usize>, is_compressed: bool) -> Result<Vec<u8>, Error> {
        let mut r = vec![];
        r.extend_from_slice(&encode_domain_name_wrap(
            self.rmail_bx.as_str(),
            hm,
            is_compressed,
        )?);
        r.extend_from_slice(&encode_domain_name_wrap(
            self.email_bx.as_str(),
            hm,
            is_compressed,
        )?);

        Ok(r)
    }
}
