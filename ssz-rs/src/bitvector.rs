use crate::{
    de::{Deserialize, DeserializeError},
    error::{Error, InstanceError, TypeError},
    lib::*,
    list::{get_power_of_two_ceil, log2, sha256},
    merkleization::{
        merkleize, pack_bytes, MerkleProof, MerkleizationError, Merkleized, Node, BITS_PER_CHUNK,
        BYTES_PER_CHUNK,
    },
    ser::{Serialize, SerializeError},
    Serializable, SimpleSerialize,
};
use bitvec::{
    field::BitField,
    prelude::{BitVec, Lsb0},
};

const BITS_PER_BYTE: usize = crate::BITS_PER_BYTE as usize;

fn byte_length(bound: usize) -> usize {
    (bound + BITS_PER_BYTE - 1) / BITS_PER_BYTE
}

type BitvectorInner = BitVec<u8, Lsb0>;

/// A homogenous collection of a fixed number of boolean values.
///
/// NOTE: a `Bitvector` of length `0` is illegal.
///
/// NOTE: once `const_generics` and `const_evaluatable_checked` features stabilize,
/// this type can use something like
/// bitvec::array::BitArray<T, {N / 8}> where T: BitRegister, [T; {N / 8}]: BitViewSized
///
/// Refer: <https://stackoverflow.com/a/65462213>
#[derive(PartialEq, Eq, Clone)]
pub struct Bitvector<const N: usize>(BitvectorInner);

impl<const N: usize> MerkleProof for Bitvector<N> {
    fn get_len_and_tree_depth(&mut self) -> (usize, usize) {
        let len = self.pack_bits().unwrap().len() / BYTES_PER_CHUNK;
        let mut tree_depth = get_power_of_two_ceil(len);
        tree_depth = log2(tree_depth) as usize;
        (len, tree_depth)
    }

    fn get_hash_tree(&mut self) -> Vec<Vec<u8>> {
        let (len, tree_depth) = self.get_len_and_tree_depth();

        let base: usize = 2;
        let pow2 = base.pow(tree_depth as u32);
        let mut root_vec = vec![Vec::<u8>::new(); pow2];

        let chunks = self.pack_bits().unwrap();
        for i in 0..len {
            let mut slice: Vec<u8> = vec![0; BYTES_PER_CHUNK];
            for j in (BYTES_PER_CHUNK * i)..(BYTES_PER_CHUNK * i + 32) {
                slice[j - BYTES_PER_CHUNK * i] = chunks[j];
            }

            root_vec.push(slice);
        }

        for _ in len..pow2 {
            let zeroes: Vec<u8> = vec![0; 32];
            root_vec.push(zeroes);
        }

        for i in 1..pow2 {
            let idx = pow2 - i;
            let mut root_concat = root_vec[2 * idx].clone();
            root_concat.append(&mut root_vec[2 * idx + 1].clone());
            let new_root = sha256(root_concat).to_vec();
            root_vec[idx] = new_root;
        }
        root_vec
    }

    fn get_proof(&mut self, vec: Vec<usize>) -> serde_json::Map<String, serde_json::Value> {
        // chunk idx to get
        let idx = vec[0];
        let roots = self.get_hash_tree();

        let (_len, tree_depth) = self.get_len_and_tree_depth();

        if tree_depth > 0 {
            let n: u8 = tree_depth as u8;
            let mut dir: Vec<u8> = Vec::<u8>::new();
            dir.resize(n.into(), 0);

            let mut idx_to_get = idx.clone();

            for i in 0..n {
                dir[(n - i - 1) as usize] = (idx_to_get % 2) as u8;
                idx_to_get /= 2;
            }

            let mut proof: Vec<Vec<u8>> = Vec::new();
            let mut curr = 1;
            for i in 0..dir.len() {
                curr = curr * 2 + dir[i];
                proof.push(roots[curr as usize ^ 1].clone())
            }
            let root = roots[1].clone();

            let list_len_ind = vec![0; n as usize];
            let list_item_ind = vec![0; n as usize];

            let proof: Vec<String> = proof.iter().map(|p| hex::encode(p)).collect();

            let val = roots[curr as usize].clone();

            let mut map = serde_json::Map::new();

            let root_bytes = hex::encode(root);
            let val = hex::encode(val);

            map.insert("directions".to_owned(), dir.into());
            map.insert("val".to_owned(), val.clone().into());
            map.insert("root_bytes".to_owned(), root_bytes.into());
            map.insert("proof".to_owned(), proof.into());
            map.insert("bytes".to_owned(), vec![0, 32].into());
            map.insert("field_value".to_owned(), val.into());

            map.insert("list_len_ind".to_owned(), list_len_ind.into());
            map.insert("list_item_ind".to_owned(), list_item_ind.into());

            return map;
        }

        let mut map = serde_json::Map::new();
        let val = roots[1].clone();
        let root_bytes = hex::encode(val.clone());
        let val = hex::encode(val);

        map.insert("directions".to_owned(), Vec::<u8>::new().into());
        map.insert("val".to_owned(), val.clone().into());
        map.insert("root_bytes".to_owned(), root_bytes.into());
        map.insert("proof".to_owned(), Vec::<String>::new().into());
        map.insert("bytes".to_owned(), vec![0, 32].into());
        map.insert("field_value".to_owned(), val.into());

        map.insert("list_len_ind".to_owned(), Vec::<u8>::new().into());
        map.insert("list_item_ind".to_owned(), Vec::<u8>::new().into());

        return map;
    }
}

impl<const N: usize> fmt::Debug for Bitvector<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Bitvector<{N}>[")?;
        let len = self.len();
        let mut bits_written = 0;
        for (index, bit) in self.iter().enumerate() {
            let value = i32::from(*bit);
            write!(f, "{value}")?;
            bits_written += 1;
            // SAFETY: checked subtraction is unnecessary, as len >= 1 for bitvectors; qed
            if bits_written % 4 == 0 && index != len - 1 {
                write!(f, "_")?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl<const N: usize> Default for Bitvector<N> {
    fn default() -> Self {
        // SAFETY: there is currently no way to enforce statically
        // that `N` is non-zero with const generics so panics are possible.
        assert!(N > 0);

        Self(BitVec::repeat(false, N))
    }
}

impl<const N: usize> Bitvector<N> {
    /// Return the bit at `index`. `None` if index is out-of-bounds.
    pub fn get(&mut self, index: usize) -> Option<bool> {
        self.0.get(index).map(|value| *value)
    }

    /// Set the bit at `index` to `value`. Return the previous value
    /// or `None` if index is out-of-bounds.
    pub fn set(&mut self, index: usize, value: bool) -> Option<bool> {
        self.get_mut(index).map(|mut slot| {
            let old = *slot;
            *slot = value;
            old
        })
    }

    fn pack_bits(&self) -> Result<Vec<u8>, MerkleizationError> {
        let mut data = vec![];
        let _ = self.serialize(&mut data)?;
        pack_bytes(&mut data);
        Ok(data)
    }

    fn chunk_count() -> usize {
        (N + BITS_PER_CHUNK - 1) / BITS_PER_CHUNK
    }
}

impl<const N: usize> Deref for Bitvector<N> {
    type Target = BitvectorInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for Bitvector<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Serializable for Bitvector<N> {
    fn is_variable_size() -> bool {
        false
    }

    fn size_hint() -> usize {
        byte_length(N)
    }
}

impl<const N: usize> Serialize for Bitvector<N> {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        if N == 0 {
            return Err(TypeError::InvalidBound(N).into());
        }
        let bytes_to_write = Self::size_hint();
        buffer.reserve(bytes_to_write);
        for byte in self.chunks(BITS_PER_BYTE) {
            buffer.push(byte.load());
        }
        Ok(bytes_to_write)
    }
}

impl<const N: usize> Deserialize for Bitvector<N> {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        if N == 0 {
            return Err(TypeError::InvalidBound(N).into());
        }

        let expected_length = byte_length(N);
        if encoding.len() < expected_length {
            return Err(DeserializeError::ExpectedFurtherInput {
                provided: encoding.len(),
                expected: expected_length,
            });
        }
        if encoding.len() > expected_length {
            return Err(DeserializeError::AdditionalInput {
                provided: encoding.len(),
                expected: expected_length,
            });
        }

        let mut result = Self::default();
        for (slot, byte) in result.chunks_mut(BITS_PER_BYTE).zip(encoding.iter().copied()) {
            slot.store_le(byte);
        }
        let remainder_count = N % BITS_PER_BYTE;
        if remainder_count != 0 {
            let last_byte = encoding.last().unwrap();
            let remainder_bits = last_byte >> remainder_count;
            if remainder_bits != 0 {
                return Err(DeserializeError::InvalidByte(*last_byte));
            }
        }
        Ok(result)
    }
}

impl<const N: usize> Merkleized for Bitvector<N> {
    fn hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
        let chunks = self.pack_bits()?;
        merkleize(&chunks, Some(Self::chunk_count()))
    }
}

impl<const N: usize> SimpleSerialize for Bitvector<N> {}

impl<const N: usize> TryFrom<&[u8]> for Bitvector<N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::deserialize(value).map_err(Error::Deserialize)
    }
}

impl<const N: usize> TryFrom<&[bool]> for Bitvector<N> {
    type Error = Error;

    fn try_from(value: &[bool]) -> Result<Self, Self::Error> {
        if value.len() != N {
            let len = value.len();
            Err(Error::Instance(InstanceError::Exact { required: N, provided: len }))
        } else {
            let mut result = Self::default();
            for (i, &bit) in value.iter().enumerate() {
                result.set(i, bit);
            }
            Ok(result)
        }
    }
}

#[cfg(feature = "serde")]
impl<const N: usize> serde::Serialize for Bitvector<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut buf = Vec::with_capacity(byte_length(N));
        let _ = crate::Serialize::serialize(self, &mut buf).map_err(serde::ser::Error::custom)?;
        crate::serde::as_hex::serialize(&buf, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, const N: usize> serde::Deserialize<'de> for Bitvector<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        crate::serde::as_hex::deserialize(deserializer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize;

    const COUNT: usize = 12;

    #[test]
    fn encode_bitvector() {
        let value: Bitvector<4> = Bitvector::default();
        let encoding = serialize(&value).expect("can encode");
        let expected = [0u8];
        assert_eq!(encoding, expected);

        let value: Bitvector<COUNT> = Bitvector::default();
        let encoding = serialize(&value).expect("can encode");
        let expected = [0u8, 0u8];
        assert_eq!(encoding, expected);

        let mut value: Bitvector<COUNT> = Bitvector::default();
        value.set(3, true).expect("test data correct");
        value.set(4, true).expect("test data correct");
        assert!(value.get(4).expect("test data correct"));
        assert!(!value.get(0).expect("test data correct"));
        let encoding = serialize(&value).expect("can encode");
        let expected = [24u8, 0u8];
        assert_eq!(encoding, expected);
    }

    #[test]
    fn decode_bitvector() {
        let bytes = vec![12u8];
        let result = Bitvector::<4>::deserialize(&bytes).expect("test data is correct");
        let expected = Bitvector::try_from([false, false, true, true].as_ref()).unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn decode_bitvector_several() {
        let bytes = vec![24u8, 1u8];
        let result = Bitvector::<COUNT>::deserialize(&bytes).expect("test data is correct");
        let expected = Bitvector::try_from(
            [false, false, false, true, true, false, false, false, true, false, false, false]
                .as_ref(),
        )
        .unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn roundtrip_bitvector() {
        let input = Bitvector::<COUNT>::try_from(
            [false, false, false, true, true, false, false, false, false, false, false, false]
                .as_ref(),
        )
        .unwrap();
        let mut buffer = vec![];
        let _ = input.serialize(&mut buffer).expect("can serialize");
        let recovered = Bitvector::<COUNT>::deserialize(&buffer).expect("can decode");
        assert_eq!(input, recovered);
    }
}
