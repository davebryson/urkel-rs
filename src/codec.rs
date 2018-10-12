use byteorder::{ByteOrder, LittleEndian, ReadBytesExt, WriteBytesExt};
use hashutils::Digest;
use nodes::Node;
use std::io::Cursor;
use store::KEY_SIZE;

pub const INTERNAL_NODE_SIZE: usize = (2 + 4 + 32) * 2;
pub const LEAF_NODE_SIZE: usize = 2 + 4 + 2 + 32;

pub trait NodeCodec<'a> {
    fn encode(&self) -> (Vec<u8>, u8);
    fn decode(bits: Vec<u8>, is_leaf: bool) -> Node<'a>;
}

// TODO: Move back into node - no trait
impl<'a> NodeCodec<'a> for Node<'a> {
    fn encode(&self) -> (Vec<u8>, u8) {
        match self {
            Node::Internal { left, right, .. } => {
                let mut wtr = vec![];

                // Do left node
                let l_params = left.get_info();
                // index of file
                wtr.write_u16::<LittleEndian>(l_params.0 * 2).unwrap();
                // pos
                wtr.write_u32::<LittleEndian>(l_params.1).unwrap();
                // hash
                wtr.extend_from_slice(&(left.hash()).0);

                // Do right node
                let r_params = right.get_info();
                // index of file
                wtr.write_u16::<LittleEndian>(r_params.0).unwrap();
                // flags
                wtr.write_u32::<LittleEndian>(r_params.1).unwrap();
                // hash
                wtr.extend_from_slice(&(right.hash()).0);
                let l = wtr.len();

                (wtr, l as u8)
            }
            Node::Leaf {
                vindex,
                vpos,
                mut vsize,
                key,
                value,
                ..
            } => {
                let mut wtr = Vec::<u8>::with_capacity(LEAF_NODE_SIZE);
                assert!(value.is_some(), "Leaf has no value!");

                value.map(|v| {
                    vsize = v.len() as u16;
                });

                // Write Node
                // leaf value index - NOTE + 1 for leaf detection
                wtr.write_u16::<LittleEndian>(*vindex * 2 + 1).unwrap();
                // leaf value position
                wtr.write_u32::<LittleEndian>(*vpos).unwrap();
                // value size
                wtr.write_u16::<LittleEndian>(vsize).unwrap();
                // append key
                wtr.extend_from_slice(&key.0);

                (wtr, LEAF_NODE_SIZE as u8)
            }
            _ => unimplemented!(),
        }
    }

    // Need key size here to make sure we get the right amount of data for the key
    fn decode(mut bits: Vec<u8>, is_leaf: bool) -> Node<'a> {
        if is_leaf {
            // Make a leaf
            assert!(
                bits.len() == LEAF_NODE_SIZE,
                "node:decode - Not enough bits for a Leaf"
            );

            let k = bits.split_off(8);
            let mut rdr = Cursor::new(bits);

            let mut vindex = rdr.read_u16::<LittleEndian>().unwrap();
            assert!(vindex & 1 == 1, "Database is corrupt!");

            vindex >>= 1;

            let vpos = rdr.read_u32::<LittleEndian>().unwrap();
            let vsize = rdr.read_u16::<LittleEndian>().unwrap();

            // Extract the key
            assert!(k.len() == 32);

            let mut keybits: [u8; 32] = Default::default();
            keybits.copy_from_slice(&k);

            Node::Leaf {
                pos: 0,
                index: 0,
                hash: Default::default(),
                key: Digest(keybits),
                value: None,
                vindex,
                vpos,
                vsize,
            }
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
                //offset += KEYSIZE;

                Node::Hash {
                    pos: right_pos,
                    index: right_index,
                    hash: Digest::from(right_hash),
                }
            } else {
                //offset += 4 + KEYSIZE;
                Node::empty()
            };

            Node::Internal {
                pos: 0,
                index: 0,
                hash: Default::default(),
                left: Box::new(leftnode),
                right: Box::new(rightnode),
            }
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

        let (encoded_leaf, _size) = lf.encode();
        assert!(encoded_leaf.len() == LEAF_NODE_SIZE);

        let back = Node::decode(encoded_leaf, true);
        assert!(back.is_leaf());

        assert!(match back {
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

        let (encoded_int, _size) = inner.encode();
        assert!(encoded_int.len() == INTERNAL_NODE_SIZE);

        let back = Node::decode(encoded_int, false);
        assert!(!back.is_leaf());
    }

}
