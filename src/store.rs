use super::Result;
use nodes::{Node, INTERNAL_NODE_SIZE, LEAF_NODE_SIZE};
use rand::{thread_rng, Rng};
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::path::PathBuf;
use std::str::FromStr;

const META_MAGIC: u32 = 0x6d72_6b6c;
const META_SIZE: u16 = 4 + 2 + 4 + 2 + 4 + 20;

pub const KEY_SIZE: usize = 32;
const MAX_FILE_SIZE: u32 = 0x7fff_f000;
const DEFAULT_BUFFER_SIZE: usize = 1024 * 8;
const LOCK_FILE_NAME: &'static str = "urkel.lock";

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

// To add:
// currentMeta and lastMeta
pub struct Store {
    buffer: Vec<u8>,
    index: u16,
    pos: usize,
    dir: PathBuf,
    file: File,
    key: [u8; 32],
    //state: MetaInfo,
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
    pub fn commit(&mut self) -> Result<()> {
        // - Write meta data and buffer to current index file
        get_file_handle(&get_data_file_path(&self.dir, self.index), true)
            .and_then(|mut f| f.write_all(&self.buffer))
            .and_then(|_| {
                self.buffer.clear();
                self.pos = 0;
                Ok(())
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

/*#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_dirs() {
        let path = PathBuf::from("./data");
        let list = find_data_files(&path);
        assert!(list.is_ok());

        let file = list.unwrap();
        assert!(file.len() == 4);
        assert_eq!(file[0].index, 4);
        assert_eq!(file[0].name, String::from("0000000004"));
    }

}*/
