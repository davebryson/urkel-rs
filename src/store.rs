use super::Result;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hashutils::checksum;
use nodes::{Node, INTERNAL_NODE_SIZE, LEAF_NODE_SIZE};
use rand::{thread_rng, Rng};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Cursor;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

const META_MAGIC: u32 = 0x6d72_6b6c;
const META_SIZE: u32 = 36; // 4 + 2 + 4 + 2 + 4 + 20;

pub const KEY_SIZE: usize = 32;
const MAX_FILE_SIZE: u32 = 0x7fff_f000;

const DEFAULT_BUFFER_SIZE: usize = 1024 * 8;
const LOCK_FILE_NAME: &'static str = "urkel.lock";

// To add:
// currentMeta and lastMeta
pub struct Store {
    buffer: Vec<u8>,
    index: u16,
    pos: usize,
    dir: PathBuf,
    file: File,
    key: [u8; 32],
    state: MetaEntry,
    //last_state: MetaInfo,
}

impl Default for Store {
    fn default() -> Self {
        Store::open("./data")
    }
}

impl Store {
    // Open should seek to the end of the file to get current position
    pub fn open(dir: &str) -> Self {
        let path = PathBuf::from(dir);

        // Load or create meta key
        let store_key = load_or_create_meta_key(dir).expect("Can't access meta file!");
        let logfiles = find_data_files(&path).unwrap();

        // Find the latest file index
        let index = if logfiles.is_empty() {
            1 // First file...!
        } else {
            logfiles[0].index
        };

        // Load the file and find it's size
        let mut f =
            get_file_handle(&get_data_file_path(&path, index), true).expect("Failed on file");

        let size = f.seek(SeekFrom::End(0)).unwrap();
        Store {
            buffer: Vec::<u8>::with_capacity(DEFAULT_BUFFER_SIZE),
            index,
            pos: size as usize,
            dir: path,
            file: f,
            key: store_key,
            state: MetaEntry::default(),
        }
    }

    fn write_bytes(&mut self, bits: &[u8]) {
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
        let bits = node.encode().expect("Failed to decode node");

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

    /// Write a Leaf value
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

    // Read from file
    fn read(&mut self, index: u16, pos: u32, size: usize) -> Result<Vec<u8>> {
        let mut f = get_file_handle(&get_data_file_path(&self.dir, index), false)
            .expect("Couldn't find file");

        let mut buffer = vec![0; size];
        f.seek(SeekFrom::Start(pos.into()))?;
        f.read_exact(&mut buffer)?;

        Ok(buffer)
    }

    // Resolve hashnode -> node
    pub fn resolve<'a>(&mut self, index: u16, pos: u32, leaf: bool) -> Result<Node<'a>> {
        let p = pos >> 1; // Divide out real position as it's store as pos * 2 ...
        if leaf {
            self.read(index, p, LEAF_NODE_SIZE)
                .and_then(|n| Node::decode(n, true))
        } else {
            self.read(index, p, INTERNAL_NODE_SIZE)
                .and_then(|n| Node::decode(n, false))
        }
    }

    // Get *value* for leaf
    pub fn retrieve(&mut self, vindex: u16, vpos: u32, vsize: u16) -> Result<Vec<u8>> {
        self.read(vindex, vpos, vsize as usize)
    }

    // TODO: This needs to take the newroot and write to meta
    pub fn commit(&mut self, root_node: Option<&Node>) -> Result<()> {
        // - Write meta data and buffer to current index file
        if let Some(n) = root_node {
            let is_leaf = n.is_leaf();
            let (index, pos) = n.index_and_position();
            self.state.root_index = index;
            self.state.root_pos = pos;
            self.state.root_leaf = is_leaf;
            let bits = self.state.encode(self.pos as u32, self.key);
            match bits {
                Ok(data) => self.write_bytes(&data),
                _ => panic!("Failed to write meta"),
            }
        };

        get_file_handle(&get_data_file_path(&self.dir, self.index), true)
            .and_then(|mut f| f.write_all(&self.buffer))
            .and_then(|_| {
                self.buffer.clear();
                self.pos = 0;
                Ok(())
            })
    }
}

struct StoreWriter {}

struct NodeWriter {}

struct MetaWriter {}

struct MetaEntry {
    meta_index: u16,
    meta_pos: u32,
    root_index: u16,
    root_pos: u32,
    root_leaf: bool,
}

impl Default for MetaEntry {
    fn default() -> Self {
        MetaEntry {
            meta_index: 0,
            meta_pos: 0,
            root_index: 0,
            root_pos: 0,
            root_leaf: false,
        }
    }
}

impl MetaEntry {
    /// Encode the metadata for inclusion in the FF
    fn encode(&self, buffer_pos: u32, meta_key: [u8; 32]) -> Result<Vec<u8>> {
        let padding = META_SIZE - (buffer_pos % META_SIZE);
        let mut wtr = vec![0; padding as usize];

        let leaf_flag = if self.root_leaf { 1 } else { 0 };
        let root_pos = (self.root_pos * 2) + leaf_flag;

        wtr.write_u32::<LittleEndian>(META_MAGIC)?;
        wtr.write_u16::<LittleEndian>(self.meta_index)?;
        wtr.write_u32::<LittleEndian>(self.meta_pos)?;
        wtr.write_u16::<LittleEndian>(self.root_index)?;
        wtr.write_u32::<LittleEndian>(root_pos)?;

        // Create the checksum
        // Slice off the contents above
        let preimage = &wtr.clone()[padding as usize..];
        // Checksum it
        let chktotal = checksum(preimage, meta_key);
        // Copy to the writer
        wtr.extend_from_slice(&chktotal[0..20]);

        Ok(wtr)
    }

    fn decode(mut bits: Vec<u8>, meta_key: [u8; 32]) -> Result<MetaEntry> {
        let preimage = &bits.clone()[0..16];
        let expected_checksum = &bits.clone()[16..];
        let mut rdr = Cursor::new(bits);

        let magic = rdr.read_u32::<LittleEndian>()?;
        if magic != META_MAGIC {
            panic!("Invalid meta magic number");
        }
        assert!(
            expected_checksum.len() == 20,
            "meta checksum has wrong size"
        );
        let chk = checksum(preimage, meta_key);
        if chk != expected_checksum {
            panic!("Invalid metaroot checksum!");
        }

        let meta_index = rdr.read_u16::<LittleEndian>()?;
        let meta_pos = rdr.read_u32::<LittleEndian>()?;
        let root_index = rdr.read_u16::<LittleEndian>()?;
        let root_pos = rdr.read_u32::<LittleEndian>()?;
        let is_leaf = root_pos & 1 == 1;
        let adj_root_pos = root_pos >> 1;

        Ok(MetaEntry {
            meta_index,
            meta_pos,
            root_index,
            root_pos: adj_root_pos,
            root_leaf: is_leaf,
        })
    }
}

// Loading log files

#[derive(Debug)]
struct StoreFile {
    index: u16,
    name: String,
}

// Return filenum if valid, else 0
fn valid_data_filename(val: &str) -> u32 {
    if val.len() < 10 {
        return 0;
    }
    u32::from_str(val).unwrap_or(0)
}

fn find_data_files(path: &Path) -> Result<Vec<StoreFile>> {
    let files = fs::read_dir(path)?;
    let mut data_files = Vec::<StoreFile>::new();

    for entry in files {
        let file = entry?;
        if file.metadata()?.is_file() {
            if let Some(name) = file.file_name().to_str() {
                let filenum = valid_data_filename(name);
                if filenum > 0 {
                    data_files.push(StoreFile {
                        index: filenum as u16,
                        name: String::from(name),
                    });
                }
            }
        }
    }
    // Sort to the latest index is the first element
    data_files.sort_by(|a, b| b.index.cmp(&a.index));
    Ok(data_files)
}

fn get_data_file_path(path: &Path, file_id: u16) -> PathBuf {
    let file_id = format!("{:010}", file_id);
    path.join(file_id)
}

pub fn get_file_handle(path: &Path, write: bool) -> Result<File> {
    if write {
        OpenOptions::new().append(true).create(true).open(path)
    } else {
        OpenOptions::new().read(true).open(path)
    }
}

/// Load or create the meta file that holds the key used for the checksum
/// in the meta root.
pub fn random_key() -> [u8; 32] {
    let mut arr = [0; 32];
    thread_rng().fill(&mut arr[..]);
    arr
}

fn load_or_create_meta_key(dir: &str) -> Result<[u8; 32]> {
    let path = Path::new(dir).join("meta");
    if path.exists() {
        println!("File exists");
        // Read the key if the meta file exists
        OpenOptions::new().read(true).open(path).and_then(|mut f| {
            let mut buffer = [0; 32];
            f.read_exact(&mut buffer)?;
            Ok(buffer)
        })
    } else {
        // Create a new key and meta file
        OpenOptions::new()
            .create(true)
            .write(true)
            .open(path)
            .and_then(|mut f| {
                let k = random_key();
                f.write_all(&k)?;
                Ok(k)
            })
    }
}
