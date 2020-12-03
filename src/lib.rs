use std::convert;

type StrongHash = md5::Digest;
type WeakHash = u32;

#[derive(Debug, Eq, PartialEq)]
struct ChunkHash {
    offset: usize,
    strong: StrongHash,
    weak: WeakHash,
}

#[derive(Debug)]
pub struct Signature {
    chunk_sz: usize,
    hashes: Vec<ChunkHash>,
}

impl Signature {
    #[inline]
    pub fn new(chunk_sz: usize) -> Self {
        Signature {
            chunk_sz,
            hashes: vec![],
        }
    }

    pub fn from(data: &[u8], chunk_sz: usize) -> Result<Signature, Error> {
        if data.len() < chunk_sz {
            return Err(SignatureError::BadChunkSize.into());
        }

        let mut sig = Signature::new(chunk_sz);
        let chunks = data.chunks(chunk_sz).collect::<Vec<&[u8]>>();
        for (id, &chunk) in chunks.iter().enumerate() {
            let strong = md5::compute(chunk);
            let weak = adler32::adler32(chunk).expect("reading from chunk cannot fail");
            sig.hashes.push(ChunkHash {
                offset: chunk_sz * id,
                strong,
                weak,
            });
        }

        Ok(sig)
    }

    #[inline]
    fn find(&self, weak_hash: WeakHash) -> Option<&ChunkHash> {
        for chash in &self.hashes {
            if chash.weak == weak_hash {
                return Some(&chash);
            }
        }
        None
    }
}

#[derive(Debug, Eq, PartialEq)]
enum DeltaType<'a> {
    Chunk(&'a ChunkHash),
    Raw { offset: usize, data: &'a [u8] },
}

#[derive(Debug, Eq, PartialEq)]
pub struct Delta<'a> {
    full_checksum: StrongHash,
    ops: Vec<DeltaType<'a>>,
}

impl<'a> Delta<'a> {
    #[inline]
    fn add_raw(&mut self, data: &'a [u8], last_match_end: usize, pos: usize) {
        if last_match_end != pos {
            self.ops.push(DeltaType::Raw {
                offset: last_match_end,
                data: &data[last_match_end..pos],
            });
        }
    }

    pub fn from(data: &'a [u8], signature: &'a Signature) -> Delta<'a> {
        let window = signature.chunk_sz;
        let mut delta = Delta {
            full_checksum: md5::compute(data),
            ops: vec![],
        };
        let mut last_match_end = 0usize;

        let rh_itr = RollingHashItr::new(data, window);
        for (pos, rh) in rh_itr {
            if let Some(chash) = signature.find(rh) {
                if chash.strong == md5::compute(&data[pos..(pos + window)]) {
                    delta.add_raw(data, last_match_end, pos);
                    delta.ops.push(DeltaType::Chunk(chash));
                    last_match_end = pos + window;
                }
            }
        }

        delta.add_raw(data, last_match_end, data.len());
        delta
    }
}

#[derive(Debug, PartialEq)]
pub enum Error {
    SignatureError(SignatureError),
}

#[derive(Debug, PartialEq)]
pub enum SignatureError {
    BadChunkSize,
}

impl convert::From<SignatureError> for Error {
    fn from(err: SignatureError) -> Self {
        Self::SignatureError(err)
    }
}

struct RollingHashItr<'a> {
    counter: usize,
    data: &'a [u8],
    window: usize,
    hash: adler32::RollingAdler32,
}

impl RollingHashItr<'_> {
    fn new(data: &[u8], window: usize) -> RollingHashItr {
        RollingHashItr {
            counter: 0,
            data,
            window,
            hash: adler32::RollingAdler32::default(),
        }
    }
}

impl Iterator for RollingHashItr<'_> {
    type Item = (usize, WeakHash);

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.counter > (self.data.len() - self.window) {
            return None;
        } else if self.counter == 0 {
            self.hash = adler32::RollingAdler32::from_buffer(&self.data[..self.window]);
            self.counter += 1;
            return Some((self.counter - 1, self.hash.hash()));
        }
        self.hash.remove(self.window, self.data[self.counter - 1]);
        self.hash.update(self.data[self.window + self.counter - 1]);
        self.counter += 1;
        Some((self.counter - 1, self.hash.hash()))
    }
}

#[cfg(test)]
mod tests {
    use crate::DeltaType::{Chunk, Raw};
    use crate::SignatureError::BadChunkSize;
    use crate::{Delta, Error, Signature};
    use std::io;

    #[test]
    fn test_signature() {
        let sig = Signature::from(b"abcdefg", 2);
        assert!(sig.is_ok());
        assert_eq!(
            Signature::from(b"abcdefg", 8).err().unwrap(),
            Error::SignatureError(BadChunkSize)
        )
    }

    #[test]
    fn test_delta_identical() {
        let sig = Signature::from(b"abcdefgh", 2).unwrap();
        let delta1 = Delta::from(b"abcdefgh", &sig);
        let delta2 = Delta {
            full_checksum: delta1.full_checksum,
            ops: vec![
                Chunk(&sig.hashes[0]),
                Chunk(&sig.hashes[1]),
                Chunk(&sig.hashes[2]),
                Chunk(&sig.hashes[3]),
            ],
        };
        assert_eq!(delta1, delta2);
    }

    #[test]
    fn test_delta_mid_raw() {
        let sig = Signature::from(b"abcdefgh", 2).unwrap();
        let delta1 = Delta::from(b"abtkcdefgh", &sig);
        let delta2 = Delta {
            full_checksum: delta1.full_checksum,
            ops: vec![
                Chunk(&sig.hashes[0]),
                Raw { offset: 2, data: &[b't', b'k'] },
                Chunk(&sig.hashes[1]),
                Chunk(&sig.hashes[2]),
                Chunk(&sig.hashes[3]),
            ],
        };
        assert_eq!(delta1, delta2);
    }

    #[test]
    fn test_delta_start_end_odd() {
        let sig = Signature::from(b"qweabcdefghop", 2).unwrap();
        let delta1 = Delta::from(b"abtkcdefgh", &sig);
        let delta2 = Delta {
            full_checksum: delta1.full_checksum,
            ops: vec![
                Raw { offset: 0, data: &[b'a', b'b', b't', b'k', b'c'] },
                Chunk(&sig.hashes[3]),
                Chunk(&sig.hashes[4]),
                Raw { offset: 9, data: &[b'h'] },
            ],
        };
        assert_eq!(delta1, delta2);
    }

    #[test]
    fn test_delta_prefix() {
        let sig = Signature::from(b"aabcdefgh", 2).unwrap();
        let delta1 = Delta::from(b"abcdefgh", &sig);
        let delta2 = Delta {
            full_checksum: delta1.full_checksum,
            ops: vec![
                Raw { offset: 0, data: &[b'a'] },
                Chunk(&sig.hashes[1]),
                Chunk(&sig.hashes[2]),
                Chunk(&sig.hashes[3]),
                Raw { offset: 7, data: &[b'h'] },
            ],
        };
        assert_eq!(delta1, delta2);
    }

    #[test]
    fn test_delta_odd_chunk_sz() {
        let sig = Signature::from(b"aabcdefghijk", 3).unwrap();
        let delta1 = Delta::from(b"abcdefgh", &sig);
        let delta2 = Delta {
            full_checksum: delta1.full_checksum,
            ops: vec![
                Raw { offset: 0, data: &[b'a', b'b'] },
                Chunk(&sig.hashes[1]),
                Chunk(&sig.hashes[2]),
            ],
        };
        assert_eq!(delta1, delta2);
    }

    #[test]
    fn test_adler32() {
        // taken from https://github.com/remram44/adler32-rs/blob/master/src/lib.rs#L216
        fn adler32_slow<R: io::Read>(reader: R) -> io::Result<u32> {
            let mut a: u32 = 1;
            let mut b: u32 = 0;

            for byte in reader.bytes() {
                let byte = byte? as u32;
                a = (a + byte) % 65521;
                b = (b + a) % 65521;
            }

            Ok((b << 16) | a)
        }

        fn do_test(total: &[u8], window: usize) {
            assert!(total.len() >= window);

            const CHUNK_SZ: usize = 2;
            let mut v = vec![];

            let mut h = adler32::RollingAdler32::from_buffer(&total[..window]);
            for i in 0..(total.len() - window) {
                h.remove(window, total[i]);
                h.update(total[window + i]);
                if i % CHUNK_SZ == 0 {
                    v.push(h.hash());
                }
            }
            assert_eq!(
                h.hash(),
                adler32_slow(&total[(total.len() - window)..]).unwrap()
            );
        }

        do_test(b"abcd", 1);
        do_test(b"a", 1);
        do_test(b"th", 1);
        do_test(b"this a test", 4);
        do_test(b"hello world", 5);
    }
}
