use super::hashutils::{sha3_internal, Digest};
use std::fmt;

#[derive(PartialEq, Clone)]
pub enum Node<'a> {
    Empty {},
    Hash {
        pos: u32,
        index: u16,
        hash: Digest,
    },
    Leaf {
        pos: u32,
        index: u16,
        hash: Digest,
        key: Digest,
        value: Option<&'a [u8]>,
        vindex: u16,
        vpos: u32,
        vsize: u16,
    },
    Internal {
        pos: u32,
        index: u16,
        hash: Digest,
        left: Box<Node<'a>>,
        right: Box<Node<'a>>,
    },
}

impl<'a> Node<'a> {
    // Is the node a Leaf?
    pub fn is_leaf(&self) -> bool {
        match self {
            Node::Leaf { .. } => true,
            Node::Hash { pos, .. } => {
                if pos & 1 == 1 {
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    pub fn should_save(&self) -> bool {
        match self {
            Node::Internal { index, .. } => {
                if *index == 0 {
                    return true;
                }
                false
            }
            _ => false,
        }
    }

    pub fn is_leaf_or_internal(&self) -> bool {
        match self {
            Node::Leaf { .. } => true,
            Node::Internal { .. } => true,
            _ => false,
        }
    }

    pub fn position(&mut self, val: u32) {
        match self {
            Node::Leaf { ref mut pos, .. } => *pos = val * 2 + 1,
            Node::Internal { ref mut pos, .. } => *pos = val * 2,
            _ => unimplemented!(),
        }
    }

    pub fn get_info(&self) -> (u16, u32, Digest) {
        match self {
            Node::Leaf {
                pos, index, hash, ..
            } => (*index, *pos, *hash),
            Node::Internal {
                pos, index, hash, ..
            } => (*index, *pos, *hash),
            Node::Hash { pos, index, hash } => (*index, *pos, *hash),
            Node::Empty {} => (0, 0, Default::default()),
        }
    }

    pub fn hash(&self) -> Digest {
        match self {
            Node::Empty {} => Digest([0; 32]),
            Node::Hash { hash, .. } => Digest(hash.0),
            Node::Leaf { hash, .. } => Digest(hash.0),
            Node::Internal { left, right, .. } => {
                let lh = left.as_ref().hash();
                let rh = right.as_ref().hash();
                sha3_internal(lh, rh)
            }
        }
    }

    // Set the index and position once written to store
    pub fn set_index_and_pos(&mut self, nindex: u16, npos: u32) {
        //println!("set_index_pos {:?}:{:?}", nindex, pos);
        match self {
            Node::Internal {
                ref mut index,
                ref mut pos,
                ..
            } => {
                println!("mutate internal with {:?}", nindex);
                *index = nindex;
                *pos = npos * 2;
            }
            Node::Leaf {
                ref mut index,
                ref mut pos,
                ..
            } => {
                *index = nindex;
                *pos = npos * 2 + 1;
                //self.position(pos);
            }
            _ => unimplemented!(),
        }
    }

    // Convert current node into a HashNode. Can't seem to make From/Into trait work for an enum
    /*pub fn to_hash_node(&self) -> Self {
        match self {
            Node::Leaf { pos, index, .. } => Node::Hash {
                pos: *pos,
                index: *index,
                hash: self.hash(),
            },
            Node::Internal { pos, index, .. } => Node::Hash {
                pos: *pos,
                index: *index,
                hash: self.hash(),
            },
            Node::Empty {} => Node::empty(),
            _ => *self,
        }
    }*/

    // Create an Empty Node
    pub fn empty() -> Self {
        Node::Empty {}
    }

    // Create basic Leaf Node
    pub fn leaf(key: Digest, value: Option<&'a [u8]>) -> Self {
        Node::Leaf {
            pos: 0,
            index: 0,
            hash: Default::default(), // Should this be an Option?
            key,
            value,
            vindex: 0,
            vpos: 0,
            vsize: 0,
        }
    }
}

impl<'a> fmt::Debug for Node<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Node::Empty {} => write!(f, "Node::Empty"),
            Node::Leaf { value, .. } => write!(f, "Node:Leaf({:?})", value),
            Node::Internal { left, right, .. } => {
                write!(f, "Node:Internal({:?}, {:?})", left, right)
            }
            Node::Hash { hash, .. } => write!(f, "Node::Hash({:?})", hash.0),
        }
    }
}
