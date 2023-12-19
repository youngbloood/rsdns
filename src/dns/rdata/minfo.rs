/*!
ref: https://www.rfc-editor.org/rfc/rfc1035#section-3.3.7

# MINFO RDATA format (EXPERIMENTAL)

    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    RMAILBX                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /                    EMAILBX                    /
    +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

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

use anyhow::Error;

use crate::{dns::labels::Labels, util};

use super::RDataOperation;

#[derive(Debug)]
pub struct MInfo {
    rmail_bx: String,
    email_bx: String,
}

impl MInfo {
    pub fn from(raw: &[u8], _rdata: &[u8]) -> Result<Self, Error> {
        let getv = |mut offset: &mut usize| -> Result<Labels, Error> {
            if *offset > _rdata.len() {
                return Err(Error::msg("not completed labels"));
            }
            let (mut compressed_offset, is_compressed) =
                util::is_compressed_wrap(&_rdata[*offset..]);
            if is_compressed {
                *offset += 2;
                return Ok(Labels::from(raw, &mut compressed_offset)?);
            }
            return Ok(Labels::from(_rdata, &mut offset)?);
        };

        let mut offset = 0_usize;

        Ok(Self {
            rmail_bx: getv(&mut offset)?.encode_to_str(),
            email_bx: getv(&mut offset)?.encode_to_str(),
        })
    }
}

impl RDataOperation for MInfo {
    fn decode(&self) -> Vec<Vec<u8>> {
        return vec![
            self.rmail_bx.as_bytes().to_vec(),
            self.email_bx.as_bytes().to_vec(),
        ];
    }

    fn encode(&self) -> Vec<u8> {
        let mut r = vec![];
        r.extend_from_slice(self.rmail_bx.as_bytes());
        r.extend_from_slice(self.email_bx.as_bytes());

        return r;
    }
}
