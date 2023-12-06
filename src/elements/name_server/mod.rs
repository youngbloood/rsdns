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

*/

mod server;
mod zones;
