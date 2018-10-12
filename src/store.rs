use codec::{NodeCodec, INTERNAL_NODE_SIZE, LEAF_NODE_SIZE};
use nodes::Node;
use rand::{thread_rng, Rng};
use std::fs::{File, OpenOptions};
use std::io::Error;
use std::io::{Read, Seek, SeekFrom, Write};
use std::iter;

const META_MAGIC: u32 = 0x6d72_6b6c;
const META_SIZE: u16 = 4 + 2 + 4 + 2 + 4 + 20;
pub const KEY_SIZE: usize = 32;
const MAX_FILE_SIZE: u32 = 0x7fff_f000;

// Makes a filename padded with zeros, like: 0000000001
fn pad_filename(val: usize) -> String {
    format!("{:0width$}", val, width = 10)
}

/// Load or create the meta file that holds the key used for the checksum
/// in the meta root.
pub fn random_key() -> [u8; 32] {
    let mut arr = [0; 32];
    thread_rng().fill(&mut arr[..]);
    arr
}

fn load_meta_key(path: &'static str) -> Result<[u8; 32], Error> {
    let mut f = OpenOptions::new().read(true).open(path)?;
    let mut buffer = [0; 32];
    f.read_exact(&mut buffer)?;
    Ok(buffer)
}

pub fn load_or_create_meta_key(path: &'static str) -> Result<[u8; 32], Error> {
    load_meta_key(path).or_else(|_| {
        let mut f = OpenOptions::new().write(true).create(true).open(path)?;
        let k = random_key();
        f.write_all(&k)?;
        Ok(k)
    })
}

// To add:
// currentMeta and lastMeta
pub struct Store {
    buffer: Vec<u8>,
    index: u16,
    pos: usize,
    file: File,
    key: [u8; 32],
    //state: MetaInfo,
    //last_state: MetaInfo,
}

impl Default for Store {
    fn default() -> Self {
        Store::open()
    }
}

impl Store {
    // Open should seek to the end of the file to get current position
    pub fn open() -> Self {
        // Load or create meta key
        let store_key = load_or_create_meta_key("meta.txt").expect("Can't access meta file!");
        // This should be a path and we find the current index by checking the last file in the path
        // TODO: Hardcoded
        let filename = pad_filename(1);
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(filename)
            .expect("Can't access file!");

        let size = f.seek(SeekFrom::End(0)).unwrap();
        Store {
            buffer: Vec::<u8>::with_capacity(1024),
            index: 1,
            pos: size as usize,
            file: f,
            key: store_key,
        }
    }

    fn write_bytes(&mut self, bits: &[u8]) {
        // TODO: Better way?
        for v in bits {
            self.buffer.push(*v);
            self.pos += 1;
        }
    }

    // Write node to buffer and eventually to file.   Note, this needs to mutate the node
    // to update it's position and index
    // Called from tree.write()
    pub fn write_node(&mut self, node: &mut Node) {
        let start_pos = self.pos;
        let (bits, _amt) = node.encode();

        match node {
            Node::Internal {
                ref mut index,
                ref mut pos,
                ..
            } => {
                *index = self.index;
                *pos = start_pos as u32 * 2;
            }
            Node::Leaf {
                ref mut index,
                ref mut pos,
                ..
            } => {
                *index = self.index;
                *pos = start_pos as u32 * 2 + 1;
            }
            _ => unimplemented!(),
        }

        // Write to buffer
        self.write_bytes(bits.as_slice());
    }

    pub fn write_value(&mut self, node: &mut Node) {
        assert!(node.is_leaf());
        let start_pos = self.pos;

        match node {
            Node::Leaf {
                value,
                ref mut vpos,
                ref mut vindex,
                ref mut vsize,
                ..
            } => value.map(|v| {
                let size = v.len();
                *vpos = start_pos as u32;
                *vindex = self.index;
                *vsize = size as u16;
                self.write_bytes(v);
            }),
            _ => unimplemented!(),
        };
    }

    // Read from file (todo: add index)
    // TODO: Should return result
    fn read(&mut self, pos: u32, size: usize) -> Vec<u8> {
        let mut buffer = vec![0; size];
        // TODO: Hardcoded file name for now...
        File::open("0000000001")
            .and_then(|mut f| {
                f.seek(SeekFrom::Start(pos.into()))?;
                f.read(&mut buffer)
            }).unwrap();

        buffer
    }

    // Resolve hashnode -> node
    pub fn resolve<'a>(&mut self, index: u16, pos: u32, leaf: bool) -> Node<'a> {
        let p = pos >> 1;
        if leaf {
            let buf = self.read(p, LEAF_NODE_SIZE);
            Node::decode(buf, true)
        } else {
            let buf = self.read(p, INTERNAL_NODE_SIZE);
            Node::decode(buf, false)
        }
    }

    // Get *value* for leaf
    pub fn retrieve(&mut self, vindex: u16, vpos: u32, vsize: u16) -> Vec<u8> {
        self.read(vpos, vsize as usize)
    }

    // TODO: This needs to take the newroot and write to meta
    pub fn commit(&mut self) -> Result<(), Error> {
        // Write meta data to current index file
        // Flush buffer to disk
        self.file.write_all(&self.buffer).and_then(|_| {
            // TODO:  Need f.sync_all()?; Move to Drop for store
            self.buffer.clear();
            self.pos = 0;
            Ok(())
        })
    }
}
