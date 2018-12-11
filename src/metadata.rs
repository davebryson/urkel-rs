use super::Result;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use hashutils::checksum;
use std::fs::File;
use std::io::Cursor;
use std::io::Read;
use std::io::{Error, ErrorKind};
use std::io::{Seek, SeekFrom};
use std::path::PathBuf;

const META_MAGIC: u32 = 0x6d72_6b6c;
const META_SIZE: usize = 36; // 4 + 2 + 4 + 2 + 4 + 20;
const SLAB_SIZE: u64 = 1_048_572; // 1mb

#[derive(Clone, Debug)]
pub struct MetaEntry {
    pub meta_index: u16,
    pub meta_pos: u32,
    pub root_index: u16,
    pub root_pos: u32,
    pub root_leaf: bool,
    //pub root_node: Option<Node<'a>>,
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
    pub fn encode(&self, buffer_pos: u32, meta_key: [u8; 32]) -> Result<Vec<u8>> {
        let padding = META_SIZE - (buffer_pos as usize % META_SIZE);
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

    pub fn decode(bits: &[u8], meta_key: [u8; 32]) -> Result<MetaEntry> {
        let preimage = &bits.to_owned()[0..16];
        let expected_checksum = &bits.to_owned()[16..36];
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

        // Carve off first 20 bytes
        let preimage_chk = &chk[0..20];

        if preimage_chk != expected_checksum {
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

// Opens the given file and attempts to find the file meta
pub fn recover_meta(
    path: &PathBuf,
    file_index: u16,
    meta_key: [u8; 32],
) -> Result<(MetaEntry, MetaEntry)> {
    let mut buffer = Vec::<u8>::with_capacity(SLAB_SIZE as usize);
    let mut f = File::open(path).unwrap();
    let mut size: u64 = 0;
    if let Ok(m) = f.metadata() {
        size = m.len();
    }

    let metasize = META_SIZE as u64;
    let mut off = size - (size % metasize);

    while off >= metasize {
        let mut pos = 0;
        let mut size = if off >= SLAB_SIZE {
            pos = off - SLAB_SIZE;
            SLAB_SIZE
        } else {
            off
        };

        f.seek(SeekFrom::Start(pos))?;
        {
            let reference = f.by_ref();
            reference.take(size).read_to_end(&mut buffer)?;
        } // drop reference here..

        assert!(!buffer.is_empty(), "Buffer is empty!");
        let mut cursor = Cursor::new(&buffer);

        // Parse meta -
        // Now read through this window bottom->up looking for the magic key
        while size >= metasize {
            size -= metasize;
            off -= metasize;

            cursor.set_position(size);
            let value = cursor.read_u32::<LittleEndian>()?;
            if value != META_MAGIC {
                continue;
            }

            let ind: usize = size as usize;
            if let Ok(result) = MetaEntry::decode(&buffer[ind..ind + META_SIZE], meta_key) {
                let mut state = result.clone();
                state.meta_index = file_index;
                state.meta_pos = size as u32;
                return Ok((state, result));
            }
        }
    }

    Err(Error::new(
        ErrorKind::Other,
        "Didn't find it! What's a meta with you?",
    ))
}
