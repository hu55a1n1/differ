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
    Liternal { offset: usize, data: &'a [u8] },
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

fn matching_chunk_hash(hashes: &Vec<ChunkHash>, weak_hash: WeakHash) -> Option<&ChunkHash> {
    for hash in hashes {
        if hash.weak == weak_hash {
            return Some(&hash);
        }
    }
    None
}

fn get_delta<'a>(data: &'a [u8], signature: &'a Signature) -> Delta<'a> {
    let mut d = Delta { full_checksum: md5::compute(data), ops: vec![] };
    let mut h = adler32::RollingAdler32::default();
    let mut last_match_end: Option<usize> = None;

    for i in 0..(data.len() - signature.chunk_sz) {
        if i == 0 {
            h = adler32::RollingAdler32::from_buffer(&data[..signature.chunk_sz]);
        } else {
            h.remove(signature.chunk_sz, data[i - 1]);
            h.update(data[signature.chunk_sz + i - 1]);
        }
        let wh = h.hash();
        if let Some(chash) = matching_chunk_hash(&signature.hashes, wh) {
            // println!("matching weakHash: {:?} -> {:?}", i, chash.offset);

            let sh = md5::compute(&data[i..(i + signature.chunk_sz)]);
            if sh == chash.strong {
                // println!("matching chunk!");

                if last_match_end.is_some() && last_match_end.unwrap() != i {
                    d.ops.push(Ops::Liternal { offset: last_match_end.unwrap(), data: &data[last_match_end.unwrap()..i] });
                }
                d.ops.push(Ops::Chunk(chash));

                last_match_end = Some(i + signature.chunk_sz);
                // i += signature.chunk_sz;
            }
        }
    }
    d
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
