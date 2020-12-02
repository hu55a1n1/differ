use std::convert;

type StrongHash = md5::Digest;
type WeakHash = u32;

#[derive(Debug)]
struct ChunkHash {
    offset: usize,
    strong: StrongHash,
    weak: WeakHash,
}

#[derive(Debug)]
struct Signature {
    chunk_sz: usize,
    hashes: Vec<ChunkHash>,
}

impl Signature {
    fn new(chunk_sz: usize) -> Self {
        Signature { chunk_sz, hashes: vec![] }
    }
}

#[derive(Debug)]
enum Ops<'a> {
    Chunk(&'a ChunkHash),
    Raw { offset: usize, data: &'a [u8] },
}

#[derive(Debug)]
struct Delta<'a> {
    full_checksum: StrongHash,
    ops: Vec<Ops<'a>>,
}

#[derive(Debug, PartialEq)]
enum Error {
    SignatureError(SignatureError)
}

#[derive(Debug, PartialEq)]
enum SignatureError {
    BadChunkSize
}


impl convert::From<SignatureError> for Error {
    fn from(err: SignatureError) -> Self {
        Self::SignatureError(err)
    }
}

fn get_signature(data: &[u8], chunk_sz: usize) -> Result<Signature, Error> {
    if data.len() < chunk_sz {
        return Err(SignatureError::BadChunkSize.into());
    }

    let mut sig = Signature::new(chunk_sz);
    let chunks = data.chunks(chunk_sz).collect::<Vec<&[u8]>>();
    for (id, &chunk) in chunks.iter().enumerate() {
        let strong = md5::compute(chunk);
        let weak = adler32::adler32(chunk).expect("reading from chunk cannot fail");
        sig.hashes.push(ChunkHash { offset: chunk_sz * id, strong, weak });
    }

    Ok(sig)
}

fn matching_chunk_hash(hashes: &[ChunkHash], weak_hash: WeakHash) -> Option<&ChunkHash> {
    for hash in hashes {
        if hash.weak == weak_hash {
            return Some(&hash);
        }
    }
    None
}

fn add_remaining_raw<'a>(mut delta: Delta<'a>, data: &'a [u8], last_match_end: Option<usize>, pos: usize) -> Delta<'a> {
    if let Some(last_match_end) = last_match_end {
        if last_match_end != pos {
            delta.ops.push(Ops::Raw { offset: last_match_end, data: &data[last_match_end..pos] });
        }
    }
    delta
}

fn get_delta<'a>(data: &'a [u8], signature: &'a Signature) -> Delta<'a> {
    let window = signature.chunk_sz;
    let mut delta = Delta { full_checksum: md5::compute(data), ops: vec![] };
    let rh_itr = RollingHashItr::new(data, window);
    let mut last_match_end: Option<usize> = None;

    for (i, rh) in rh_itr {
        if let Some(chash) = matching_chunk_hash(&signature.hashes, rh) {
            let sh = md5::compute(&data[i..(i + window)]);
            if sh == chash.strong {
                delta = add_remaining_raw(delta, data, last_match_end, i);
                delta.ops.push(Ops::Chunk(chash));
                last_match_end = Some(i + window);
            }
        }
    }

    delta = add_remaining_raw(delta, data, last_match_end, data.len());
    delta
}

struct RollingHashItr<'a> {
    counter: usize,
    data: &'a [u8],
    window: usize,
    hash: adler32::RollingAdler32,
}

impl RollingHashItr<'_> {
    fn new(data: &[u8], window: usize) -> RollingHashItr {
        RollingHashItr { counter: 0, data, window, hash: adler32::RollingAdler32::default() }
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
    use std::io;
    use crate::{get_signature, Error, get_delta};
    use crate::SignatureError::BadChunkSize;

    #[test]
    fn test_signature() {
        let sig = get_signature(b"abcdefg", 2);
        println!("{:?}", sig);
        assert!(sig.is_ok());
        assert_eq!(get_signature(b"abcdefg", 8).err().unwrap(), Error::SignatureError(BadChunkSize))
    }

    #[test]
    fn test_delta() {
        let sig = get_signature(b"abcdefgh", 2).unwrap();
        println!("{:?}", sig);
        let delta = get_delta(b"abtkcdefgh", &sig);
        println!("{:?}", delta);
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

            println!("{:?} -> {:?}", h.hash(), adler32_slow(&total[(total.len() - window)..]).unwrap());
            println!("{:?}", v);

            assert_eq!(h.hash(), adler32_slow(&total[(total.len() - window)..]).unwrap());
        }
        do_test(b"abcd", 1);

        do_test(b"a", 1);
        do_test(b"th", 1);
        do_test(b"this a test", 4);
        do_test(b"hello world", 5);
    }
}
