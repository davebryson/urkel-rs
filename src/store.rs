use nodes::Node;
use rand::{thread_rng, Rng};
use std::fs::{File, OpenOptions};
use std::io::Error;
use std::io::{Read, Seek, SeekFrom, Write};

const META_MAGIC: u32 = 0x6d72_6b6c;
const META_SIZE: u16 = 4 + 2 + 4 + 2 + 4 + 20;
const KEY_SIZE: u8 = 32;
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

struct MetaInfo {
    index: usize,
    pos: usize,
}

// To add:
// currentMeta and lastMeta
struct Store {
    buffer: Vec<u8>,
    index: usize,
    file: File,
    pos: usize,
    key: [u8; 32],
}

impl Store {
    // Open should seek to the end of the file to get current position
    pub fn open() -> Self {
        // Load or create meta key
        let store_key = load_or_create_meta_key("meta.txt").expect("Can't access meta file!");
        // This should be path and we find the current index by checking the last file in the path
        let filename = pad_filename(1);
        let mut f = OpenOptions::new()
            .append(true)
            .create(true)
            .open(filename)
            .expect("Can't access file!");

        let size = f.seek(SeekFrom::End(0)).unwrap();
        Store {
            buffer: vec![],
            index: 0,
            file: f,
            pos: size as usize,
            key: store_key,
        }
    }

    // Write node to buffer and eventually to file.   Note, this needs to mutate the node
    // to update it's position and index
    // Called from tree.write()
    pub fn write_node(&mut self, node: &Node) {
        let data = node.encode();
        let written = data.len();
        self.buffer.extend(data);

        node.update_from_store(self.index, self.pos);
        self.pos += written;
    }

    pub fn read_node() {}

    pub fn commit(&mut self, root: &Node) -> Result<(), Error> {
        // Write meta data to current index file

        // Flush buffer to disk
        self.file.write_all(&self.buffer).and_then(|_| {
            // TODO:  Need f.sync_all()?;
            self.buffer.clear();
            Ok(())
        })
    }
}
