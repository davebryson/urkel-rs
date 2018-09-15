use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufWriter;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;

// Makes a filename padded with zeros, like: 0000000001
fn pad_filename(val: usize) -> String {
    format!("{:0width$}", val, width = 10)
}

pub struct Store {
    index: usize,
    file: File,
    pos: u64,
}

impl Store {
    // Open should seek to the end of the file to get current position
    pub fn open() -> Self {
        // This should be path and we find the current index by checking the last file in the path
        let filename = pad_filename(1);
        let result = OpenOptions::new().append(true).create(true).open(filename);

        match result {
            Ok(mut f) => {
                // Get the current pos of eof
                let size = f.seek(SeekFrom::End(0)).unwrap();
                Store {
                    index: 0,
                    file: f,
                    pos: size,
                }
            }
            Err(msg) => panic!(msg),
        }
    }

    pub fn write(&mut self, data: &[u8]) {
        let mut writer = BufWriter::new(&self.file);
        if let Ok(bits) = writer.write(data) {
            self.pos += bits as u64;
        }
    }

    pub fn position(&self) -> u64 {
        self.pos
    }

    pub fn commit() {}
}
