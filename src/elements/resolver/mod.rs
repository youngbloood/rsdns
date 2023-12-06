/*!
# The system administrators provide:

- The definition of zone boundaries.

- Master files of data.

- Updates to master files.

- Statements of the refresh policies desired.

*/

use crate::DNS;

trait Resolver {
    fn resolve(dns: &mut DNS);
}
