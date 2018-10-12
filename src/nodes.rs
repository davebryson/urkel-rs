use super::hashutils::{sha3_internal, Digest};
use super::Result;
use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use std::fmt;
use std::io::Cursor;
use store::KEY_SIZE;

pub const INTERNAL_NODE_SIZE: usize = 76; // (2 + 4 + 32) * 2;
pub const LEAF_NODE_SIZE: usize = 40; // 2 + 4 + 2 + 32;

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

    // true if index == 0
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

    pub fn index_and_position(&self) -> (u16, u32) {
        match self {
            Node::Leaf { pos, index, .. } => (*index, *pos),
            Node::Internal { pos, index, .. } => (*index, *pos),
            Node::Hash { pos, index, .. } => (*index, *pos),
            Node::Empty {} => (0, 0),
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

    pub fn encode(&self) -> Result<Vec<u8>> {
        match self {
            Node::Internal { left, right, .. } => {
                let mut wtr = vec![];
                // Do left node
                let (lindex, lpos) = left.index_and_position();
                // index of file
                wtr.write_u16::<LittleEndian>(lindex * 2)?;
                // pos
                wtr.write_u32::<LittleEndian>(lpos)?;
                // hash
                wtr.extend_from_slice(&(left.hash()).0);

                // Do right node
                let (rindex, rpos) = right.index_and_position();
                // index of file
                wtr.write_u16::<LittleEndian>(rindex)?;
                // flags
                wtr.write_u32::<LittleEndian>(rpos)?;
                // hash
                wtr.extend_from_slice(&(right.hash()).0);

                Ok(wtr)
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
                assert!(value.is_some(), "Leaf has no value!");

                value.map(|v| {
                    vsize = v.len() as u16;
                });

                // Write Node
                // leaf value index - NOTE + 1 for leaf detection
                wtr.write_u16::<LittleEndian>(*vindex * 2 + 1)?;
                // leaf value position
                wtr.write_u32::<LittleEndian>(*vpos)?;
                // value size
                wtr.write_u16::<LittleEndian>(vsize)?;
                // append key
                wtr.extend_from_slice(&key.0);

                Ok(wtr)
            }
            _ => unimplemented!(),
        }
    }

    // Need key size here to make sure we get the right amount of data for the key
    pub fn decode(mut bits: Vec<u8>, is_leaf: bool) -> Result<Node<'a>> {
        if is_leaf {
            // Make a leaf
            assert!(
                bits.len() == LEAF_NODE_SIZE,
                "node:decode - Not enough bits for a Leaf"
            );

            let k = bits.split_off(8);

            let mut rdr = Cursor::new(bits);
            let mut vindex = rdr.read_u16::<LittleEndian>()?;
            assert!(vindex & 1 == 1, "Database is corrupt!");

            vindex >>= 1;

            let vpos = rdr.read_u32::<LittleEndian>()?;
            let vsize = rdr.read_u16::<LittleEndian>()?;

            // Extract the key
            assert!(k.len() == 32);

            let mut keybits: [u8; 32] = Default::default();
            keybits.copy_from_slice(&k);

            Ok(Node::Leaf {
                pos: 0,
                index: 0,
                hash: Default::default(),
                key: Digest(keybits),
                value: None,
                vindex,
                vpos,
                vsize,
            })
        } else {
            // Make an internal
            assert!(
                bits.len() == INTERNAL_NODE_SIZE,
                format!(
                    "node.decode - Not enough bits {:?} for an Internal",
                    bits.len()
                )
            );

            let mut offset = 0;

            let mut left_index = LittleEndian::read_u16(&bits[offset..]);
            offset += 2;
            assert!(left_index & 1 == 0, "Database is corrupt!");

            left_index >>= 1;

            let leftnode = if left_index != 0 {
                let left_pos = LittleEndian::read_u32(&bits[offset..]);
                offset += 4;
                let left_hash = &bits[offset..offset + KEY_SIZE];
                offset += KEY_SIZE;
                // add hashnode to left
                Node::Hash {
                    pos: left_pos,
                    index: left_index,
                    hash: Digest::from(left_hash),
                }
            } else {
                offset += 4 + KEY_SIZE;
                Node::empty()
            };

            let right_index = LittleEndian::read_u16(&bits[offset..]);
            offset += 2;

            let rightnode = if right_index != 0 {
                let right_pos = LittleEndian::read_u32(&bits[offset..]);
                offset += 4;
                let right_hash = &bits[offset..offset + KEY_SIZE];

                Node::Hash {
                    pos: right_pos,
                    index: right_index,
                    hash: Digest::from(right_hash),
                }
            } else {
                Node::empty()
            };

            Ok(Node::Internal {
                pos: 0,
                index: 0,
                hash: Default::default(),
                left: Box::new(leftnode),
                right: Box::new(rightnode),
            })
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

#[cfg(test)]
mod tests {
    use super::*;
    use hashutils::sha3;

    #[test]
    fn leaf_encode_decode() {
        let lf = Node::Leaf {
            key: sha3(b"dave"),
            value: Some(&[1, 2, 3, 4]),
            pos: 0,
            index: 1,
            hash: Default::default(),
            vindex: 1,
            vpos: 20,
            vsize: 0,
        };

        let encoded_leaf = lf.encode();
        assert!(encoded_leaf.is_ok());

        let back = Node::decode(encoded_leaf.unwrap(), true);
        assert!(back.is_ok());
        assert!(match back.unwrap() {
            Node::Leaf {
                key,
                vpos,
                vsize,
                vindex,
                ..
            } => {
                assert!(key == sha3(b"dave"));
                assert!(vindex == 1);
                assert!(vpos == 20);
                assert!(vsize == 4);
                true
            }
            _ => false,
        })
    }

    #[test]
    fn internal_encode_decode() {
        let h: &[u8] = &[1u8; 32];
        let inner_leaf = Node::Leaf {
            key: sha3(b"dave"),
            value: Some(&[1, 2, 3, 4]),
            pos: 0,
            index: 1,
            hash: Digest::from(h),
            vindex: 1,
            vpos: 20,
            vsize: 0,
        };

        let inner = Node::Internal {
            left: Box::new(Node::empty()),
            right: Box::new(inner_leaf),
            pos: 20,
            index: 1,
            hash: Default::default(),
        };

        let encoded_int = inner.encode();
        assert!(encoded_int.is_ok());
        let back = Node::decode(encoded_int.unwrap(), false);
        assert!(!back.unwrap().is_leaf());
    }

}
