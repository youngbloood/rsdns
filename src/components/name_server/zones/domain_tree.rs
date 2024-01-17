/*!
The domain name space is a tree structure.  Each node and leaf on the
tree corresponds to a resource set (which may be empty).  The domain
system makes no distinctions between the uses of the interior nodes and
leaves, and this memo uses the term "node" to refer to both.

Each node has a label, which is zero to 63 octets in length.  Brother
nodes may not have the same label, although the same label can be used
for nodes which are not brothers.  One label is reserved, and that is
the null (i.e., zero length) label used for the root.

The domain name of a node is the list of the labels on the path from the
node to the root of the tree.  By convention, the labels that compose a
domain name are printed or read left to right, from the most specific
(lowest, farthest from the root) to the least specific (highest, closest
to the root).

Internally, programs that manipulate domain names should represent them
as sequences of labels, where each label is a length octet followed by
an octet string.  Because all domain names end at the root, which has a
null string for a label, these internal representations can use a length
byte of zero to terminate a domain name.

By convention, domain names can be stored with arbitrary case, but
domain name comparisons for all present domain functions are done in a
case-insensitive manner, assuming an ASCII character set, and a high
order zero bit.  This means that you are free to create a node with
label "A" or a node with label "a", but not both as brothers; you could
refer to either using "a" or "A".  When you receive a domain name or
label, you should preserve its case.  The rationale for this choice is
that we may someday need to add full binary domain names for new
services; existing services would not be changed.

When a user needs to type a domain name, the length of each label is
omitted and the labels are separated by dots (".").  Since a complete
domain name ends with the root label, this leads to a printed form which
ends in a dot.  We use this property to distinguish between:

   - a character string which represents a complete domain name
     (often called "absolute").  For example, "poneria.ISI.EDU."

   - a character string that represents the starting labels of a
     domain name which is incomplete, and should be completed by
     local software using knowledge of the local domain (often
     called "relative").  For example, "poneria" used in the
     ISI.EDU domain.

Relative names are either taken relative to a well known origin, or to a
list of domains used as a search list.  Relative names appear mostly at
the user interface, where their interpretation varies from
implementation to implementation, and in master files, where they are
relative to a single origin domain name.  The most common interpretation
uses the root "." as either the single origin or as one of the members
of the search list, so a multi-label relative name is often one where
the trailing dot has been omitted to save typing.

To simplify implementations, the total number of octets that represent a
domain name (i.e., the sum of all label octets and label lengths) is
limited to 255.

A domain is identified by a domain name, and consists of that part of
the domain name space that is at or below the domain name which
specifies the domain.  A domain is a subdomain of another domain if it
is contained within that domain.  This relationship can be tested by
seeing if the subdomain's name ends with the containing domain's name.
For example, A.B.C.D is a subdomain of B.C.D, C.D, D, and " ".


# Examples:
The following figure shows a part of the current domain name space, and
is used in many examples in this RFC.  Note that the tree is a very
small subset of the actual name space.
```shell
                                   |
                                   |
             +---------------------+------------------+
             |                     |                  |
            MIL                   EDU                ARPA
             |                     |                  |
             |                     |                  |
       +-----+-----+               |     +------+-----+-----+
       |     |     |               |     |      |           |
      BRL  NOSC  DARPA             |  IN-ADDR  SRI-NIC     ACC
                                   |
       +--------+------------------+---------------+--------+
       |        |                  |               |        |
      UCI      MIT                 |              UDEL     YALE
                |                 ISI
                |                  |
            +---+---+              |
            |       |              |
           LCS  ACHILLES  +--+-----+-----+--------+
            |             |  |     |     |        |
            XX            A  C   VAXA  VENERA Mockapetris
```
In this example, the root domain has three immediate subdomains: MIL,
EDU, and ARPA.  The LCS.MIT.EDU domain has one immediate subdomain named
XX.LCS.MIT.EDU.  All of the leaves are also domains.

*/

use crate::dns::{Class, RcRf, VecRcRf, RR};
use std::{cell::RefCell, rc::Rc};

pub type ClassDomainTreeUnion = (Class, RcRf<DomainTree>);

#[derive(Debug)]
pub struct DomainTree {
    owner: String,
    leaves: VecRcRf<DomainTree>,
    rr: Option<RcRf<RR>>,
}

impl DomainTree {
    pub fn new() -> Self {
        Self {
            owner: ".".to_string(),
            leaves: vec![],
            rr: None,
        }
    }

    pub fn push(&mut self, domain: &str) {
        if !domain.contains(".") {
            self.leaves.push(Rc::new(RefCell::new(DomainTree {
                owner: domain.to_string(),
                leaves: vec![],
                rr: None,
            })));
            // 排序
            self.leaves
                .sort_by(|a, b| a.borrow().owner.cmp(&b.borrow().owner));
            return;
        }

        let mut names = domain.rsplitn(2, ".").into_iter();
        let first = names.next();
        if first.is_some() {
            match self.leaves.binary_search_by(|probe| {
                probe
                    .clone()
                    .borrow()
                    .owner
                    .cmp(&first.unwrap().to_string())
            }) {
                Ok(pos) => {
                    // 找到了，则在该节点下插入
                    self.leaves
                        .get(pos)
                        .unwrap()
                        .clone()
                        .try_borrow_mut()
                        .unwrap()
                        .push(names.next().unwrap());
                }
                Err(_) => {
                    // 未找到，新起一个DomainTree
                    let mut _leaf = DomainTree {
                        owner: first.unwrap().to_string(),
                        leaves: vec![],
                        rr: None,
                    };
                    _leaf.push(names.next().unwrap());
                    self.leaves.push(Rc::new(RefCell::new(_leaf)));
                    // 排序
                    self.leaves
                        .sort_by(|a, b| a.borrow().owner.cmp(&b.borrow().owner));
                }
            }
        }
    }

    pub fn set_rr(&mut self, domain: &str, rr: RcRf<RR>) {
        let _rr = Rc::clone(&rr);
        if !domain.contains(".") {
            match self
                .leaves
                .binary_search_by(|probe| probe.clone().borrow().owner.cmp(&domain.to_string()))
            {
                Ok(pos) => {
                    self.leaves
                        .get(pos)
                        .unwrap()
                        .clone()
                        .try_borrow_mut()
                        .unwrap()
                        .rr = Some(rr);
                }
                Err(_) => return,
            }
            return;
        }

        let mut names = domain.rsplitn(2, ".").into_iter();
        let first: Option<&str> = names.next();
        if first.is_some() {
            match self.leaves.binary_search_by(|probe| {
                probe
                    .clone()
                    .borrow()
                    .owner
                    .cmp(&first.unwrap().to_string())
            }) {
                Ok(pos) => {
                    self.leaves
                        .get(pos)
                        .unwrap()
                        .clone()
                        .try_borrow_mut()
                        .unwrap()
                        .set_rr(names.next().unwrap(), _rr);
                }
                Err(_) => return,
            }
        }
    }

    pub fn get_rr(&self, domain: &str) -> Option<RcRf<RR>> {
        if !domain.contains(".") {
            match self
                .leaves
                .binary_search_by(|probe| probe.clone().borrow().owner.cmp(&domain.to_string()))
            {
                Ok(pos) => {
                    let dt = self.leaves.get(pos).unwrap();
                    let c = Rc::clone(dt);

                    if c.borrow().owner == domain && c.borrow().rr.is_some() {
                        return Some(Rc::clone(&c.borrow().rr.as_ref().unwrap()));
                    }
                }
                Err(_) => return None,
            }
            return None;
        }

        let mut names = domain.rsplitn(2, ".").into_iter();
        let first = names.next();
        if first.is_some() {
            match self.leaves.binary_search_by(|probe| {
                probe
                    .clone()
                    .borrow()
                    .owner
                    .cmp(&first.unwrap().to_string())
            }) {
                Ok(pos) => {
                    return self
                        .leaves
                        .get(pos)
                        .unwrap()
                        .clone()
                        .try_borrow_mut()
                        .unwrap()
                        .get_rr(names.next().unwrap());
                }
                Err(_) => return None,
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, rc::Rc};

    use crate::dns::RR;

    use super::DomainTree;

    #[test]
    pub fn test_domaintree_push() {
        let mut tree = DomainTree::new();
        tree.push("baidu.com");
        println!("tree = {:?}", tree);
        tree.push("google.com");
        println!("tree = {:?}", tree);
    }

    #[test]
    pub fn test_domaintree_set_rr() {
        let mut tree = DomainTree::new();
        tree.push("baidu.com");
        println!("tree = {:?}", tree);

        let mut rr = RR::new();
        rr.with_name("baidu.com")
            .with_class(11)
            .with_type(12)
            .with_ttl(13);

        let flag = Rc::new(RefCell::new(rr));

        tree.set_rr("baidu.com", flag.clone());
        println!("tree2 = {:?}", tree);

        tree.set_rr("baidu.com1", flag.clone());
        println!("tree3 = {:?}", tree);
    }

    #[test]
    pub fn test_domaintree_get_rr() {
        let mut tree = DomainTree::new();
        tree.push("baidu.com");

        let mut rr = RR::new();
        rr.with_name("baidu.com")
            .with_class(11)
            .with_type(12)
            .with_ttl(13);

        let flag = Rc::new(RefCell::new(rr));

        tree.set_rr("baidu.com", flag.clone());

        let mut rr = tree.get_rr("baidu.com");
        assert_eq!(true, rr.is_some());
        assert_eq!(11, rr.as_ref().unwrap().clone().borrow().class());
        assert_eq!(12, rr.as_ref().unwrap().clone().borrow().typ());
        assert_eq!(13, rr.as_ref().unwrap().clone().borrow().ttl());

        rr = tree.get_rr("baidu.com1");
        assert_eq!(true, rr.is_none());
        rr = tree.get_rr("baidu1.com");
        assert_eq!(true, rr.is_none());
    }
}
