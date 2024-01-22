/*!
The DNS has three major components:

  - The DOMAIN NAME SPACE and RESOURCE RECORDS, which are
    specifications for a tree structured name space and data
    associated with the names.  Conceptually, each node and leaf
    of the domain name space tree names a set of information, and
    query operations are attempts to extract specific types of
    information from a particular set.  A query names the domain
    name of interest and describes the type of resource
    information that is desired.  For example, the Internet
    uses some of its domain names to identify hosts; queries for
    address resources return Internet host addresses.

  - NAME SERVERS are server programs which hold information about
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

  - RESOLVERS are programs that extract information from name
    servers in response to client requests.  Resolvers must be
    able to access at least one name server and use that name
    server's information to answer a query directly, or pursue the
    query using referrals to other name servers.  A resolver will
    typically be a system routine that is directly accessible to
    user programs; hence no protocol is necessary between the
    resolver and the user program.
*/

pub mod name_server;
pub mod resolver;
