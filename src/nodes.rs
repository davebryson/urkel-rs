use hashutils::{sha3_internal, sha3_zero_hash, Digest};
use std::fmt;

/// Store the hash of the node along with file store information
#[derive(Clone, Copy)]
pub struct NodeStore {
    pub data: Digest,
    pub index: usize,
    pub flags: usize,
}

impl Default for NodeStore {
    fn default() -> Self {
        NodeStore {
            data: Default::default(),
            index: 0,
            flags: 0,
        }
    }
}

/// Used in leaf to store the actual value - mainly needed for filestore information
#[derive(Clone, Copy)]
pub struct ValueStore {
    pub vindex: usize,
    pub vpos: usize,
    pub vsize: usize,
}

impl Default for ValueStore {
    fn default() -> Self {
        ValueStore {
            vindex: 0,
            vpos: 0,
            vsize: 0,
        }
    }
}

pub enum Node {
    Empty {},
    Hash {
        params: NodeStore,
    },
    Leaf {
        key: Digest,
        value: Vec<u8>,
        params: NodeStore,
        content: ValueStore,
    },
    Internal {
        left: Box<Node>,
        right: Box<Node>,
        params: NodeStore,
    },
}

impl Node {
    // Generate hash for specific node
    pub fn hash(&self) -> Digest {
        match self {
            Node::Empty {} => sha3_zero_hash(),
            Node::Hash { params } => Digest(params.data.0),
            Node::Leaf { params, .. } => Digest(params.data.0),
            Node::Internal { left, right, .. } => {
                let lh = left.as_ref().hash();
                let rh = right.as_ref().hash();
                sha3_internal(lh, rh)
            }
        }
    }

    // Convert current node into a HashNode. Can't seem to make From/Into trait work for an enum
    pub fn to_hash_node(&self) -> Self {
        match self {
            Node::Leaf { params, .. } => Node::Hash {
                params: NodeStore {
                    data: self.hash(),
                    index: params.index,
                    flags: params.flags,
                },
            },
            Node::Internal { params, .. } => Node::Hash {
                params: NodeStore {
                    data: self.hash(),
                    index: params.index,
                    flags: params.flags,
                },
            },
            Node::Hash { params } => Node::Hash { params: *params },
            Node::Empty {} => Node::empty(),
        }
    }

    // Create an Empty Node
    pub fn empty() -> Self {
        Node::Empty {}
    }

    // Create basic Leaf Node
    pub fn leaf(key: Digest, value: Vec<u8>, params: NodeStore) -> Self {
        Node::Leaf {
            key,
            value,
            params,
            content: Default::default(),
        }
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Node::Empty {} => write!(f, "Node::Empty"),
            Node::Leaf { value, .. } => write!(f, "Node:Leaf({:?})", value),
            Node::Internal { left, right, .. } => {
                write!(f, "Node:Internal({:?}, {:?})", left, right)
            }
            Node::Hash { params } => write!(f, "Node::Hash({:?})", params.data),
        }
    }
}
