/*!
    NAME SERVERS are server programs which hold information about
    the domain tree's structure and set information.  A name
    server may cache structure or set information about any part
    of the domain tree, but in general a particular name server
    has complete information about a subset of the domain space,
    and pointers to other name servers that can be used to lead to
    information from any part of the domain tree.  Name servers
    know the parts of the domain tree for which they have complete
    information; a name server is said to be an AUTHORITY for
    these parts of the name space.  Authoritative information is
    organized into units called ZONEs, and these zones can be
    automatically distributed to the name servers which provide
    redundant service for the data in a zone.

   ```shell
    +-------------------------------------------------+
    |                  Name Server                    |
    +------+------------------------------------+-----+     <- trait: ZonesOperation (get the zones list)
    |  ... |                zone{n}             | ... |
    +------+-----+-----------+------------+-----+-----+     <- trait: MasterFileOperation (decode dt from file, and encode dt to file)
    |      | ... |   dt{n}   |   dt{n+1}  | ... |     |
    |      |     |    |      |     |      |     |     |
    |      |     |    V      |     V      |     |     |
    |      |     |  file{n}  |  file{n+1} |     |     |
    +------+-----+-----------+------------+-----+-----+
    ```
    dt is a shortening of domian_tree.
*/

mod server;
mod zones;

use crate::dns::{Question, RcRf, ResourceRecord};

pub trait NameServerOperation {
    fn find(&mut self, ques: &Question) -> Option<RcRf<ResourceRecord>>;
}
