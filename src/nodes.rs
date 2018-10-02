use super::hashutils::{sha3_internal, sha3_zero_hash, Digest};
use std::fmt;

use byteorder::{LittleEndian, WriteBytesExt};

/// Store the hash of the node along with file store information
#[derive(Clone, Copy)]
pub struct NodeStore {
    pub data: Digest,
    pub index: usize,
    pub is_leaf: bool,
    pub pos: usize,
}

impl Default for NodeStore {
    fn default() -> Self {
        NodeStore {
            data: Default::default(),
            index: 0,
            is_leaf: false,
            pos: 0,
        }
    }
}

impl NodeStore {
    pub fn set_position(&mut self, p: usize) {
        if self.is_leaf {
            self.pos = p * 2 + 1
        } else {
            self.pos = p * 2
        }
    }

    pub fn set_index(&mut self, value: usize) {
        self.index = value;
    }

    pub fn get_raw_position(&self) -> usize {
        self.pos >> 1
    }

    pub fn get_encoded_position(&self) -> u32 {
        self.pos as u32
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
        vindex: usize,
        vpos: usize,
        vsize: usize,
        params: NodeStore,
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

    pub fn update_from_store(&self, index: usize, pos: usize) {
        match self {
            Node::Internal { mut params, .. } => {
                params.index = index;
                params.set_position(pos);
            }
            Node::Leaf { mut params, .. } => {
                params.index = index;
                params.set_position(pos);
            }
            _ => unimplemented!(),
        }
    }

    /// Encode a node to the database
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Node::Internal { left, right, .. } => {
                let mut wtr = vec![];
                // Do left node
                let left_params = left.get_params();
                // index of file
                wtr.write_u16::<LittleEndian>((left_params.0 * 2) as u16)
                    .unwrap();
                // flags
                wtr.write_u32::<LittleEndian>(left_params.1).unwrap();
                // hash
                wtr.extend_from_slice(&left_params.2);

                // Do right node
                let right_params = right.get_params();
                // index of file
                wtr.write_u16::<LittleEndian>(right_params.0 as u16)
                    .unwrap();
                // flags
                wtr.write_u32::<LittleEndian>(right_params.1).unwrap();
                // hash
                wtr.extend_from_slice(&right_params.2);

                wtr
            }
            Node::Leaf {
                vindex,
                vpos,
                mut vsize,
                key,
                value,
                ..
            } => {
                let mut wtr = vec![];
                // Write Value
                vsize = value.len();
                // append value to buffer
                wtr.extend_from_slice(value.as_slice());

                // Write Node
                // leaf value index
                wtr.write_u16::<LittleEndian>((vindex * 2 + 1) as u16)
                    .unwrap();
                // leaf value position
                wtr.write_u32::<LittleEndian>(*vpos as u32).unwrap();
                // value size
                wtr.write_u16::<LittleEndian>(vsize as u16).unwrap();
                // append key
                wtr.extend_from_slice(&key.0);

                wtr
            }
            _ => unimplemented!(),
        }
    }

    pub fn get_params(&self) -> (usize, u32, [u8; 32]) {
        match self {
            Node::Internal { params, .. } => {
                (params.index, params.get_encoded_position(), params.data.0)
            }
            Node::Leaf { params, .. } => {
                (params.index, params.get_encoded_position(), params.data.0)
            }
            _ => (0, 0, [0u8; 32]),
        }
    }

    // Convert current node into a HashNode. Can't seem to make From/Into trait work for an enum
    pub fn to_hash_node(&self) -> Self {
        match self {
            Node::Leaf { mut params, .. } => {
                params.data = self.hash();
                Node::Hash { params }
            }
            Node::Internal { mut params, .. } => {
                params.data = self.hash();
                Node::Hash { params }
            }
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
            vindex: 0,
            vpos: 0,
            vsize: 0,
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
