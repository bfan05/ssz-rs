use crate::{
    de::{Deserialize, DeserializeError},
    error::{Error, InstanceError},
    lib::*,
    merkleization::{
        merkleize, mix_in_length, pack_bytes, MerkleProof, MerkleizationError, Merkleized, Node,
        BITS_PER_CHUNK, BYTES_PER_CHUNK, NUM_BYTES_TO_SQUEEZE,
    },
    ser::{Serialize, SerializeError},
    Serializable, SimpleSerialize,
};
use bitvec::prelude::{BitVec, Lsb0};
use sha2::{Digest, Sha256};

const BITS_PER_BYTE: usize = crate::BITS_PER_BYTE as usize;

// +1 for length bit
fn byte_length(bound: usize) -> usize {
    (bound + BITS_PER_BYTE - 1 + 1) / BITS_PER_BYTE
}

type BitlistInner = BitVec<u8, Lsb0>;

/// A homogenous collection of a variable number of boolean values.
#[derive(PartialEq, Eq, Clone)]
pub struct Bitlist<const N: usize>(BitlistInner);

pub fn log2(x: usize) -> u32 {
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        1usize.leading_zeros() - x.leading_zeros()
    } else {
        0usize.leading_zeros() - x.leading_zeros()
    }
}

pub fn get_power_of_two_ceil(x: usize) -> usize {
    match x {
        x if x <= 1 => 1,
        2 => 2,
        x => 2 * get_power_of_two_ceil((x + 1) / 2),
    }
}

pub fn sha256<T: AsRef<[u8]>>(bytes: T) -> [u8; NUM_BYTES_TO_SQUEEZE] {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    let output = hasher.finalize();
    output.into()
}

impl<const N: usize> MerkleProof for Bitlist<N> {
    fn get_len_and_tree_depth(&mut self) -> (usize, usize) {
        let len = self.pack_bits().unwrap().len();
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

        for i in 0..(chunks.len() / BYTES_PER_CHUNK) {
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

    fn get_proof(&mut self, vec: Vec<usize>) -> Vec<String> {
        todo!()
    }
}

impl<const N: usize> fmt::Debug for Bitlist<N> {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "Bitlist<len={}, cap={N}>[", self.len())?;
        let len = self.len();
        let mut bits_written = 0;
        for (index, bit) in self.iter().enumerate() {
            let value = i32::from(*bit);
            write!(f, "{value}")?;
            bits_written += 1;
            // SAFETY: checked subtraction is unnecessary, as len >= 1 when this for loop runs; qed
            if bits_written % 4 == 0 && index != len - 1 {
                write!(f, "_")?;
            }
        }
        write!(f, "]")?;
        Ok(())
    }
}

impl<const N: usize> Default for Bitlist<N> {
    fn default() -> Self {
        Self(BitVec::new())
    }
}

impl<const N: usize> Bitlist<N> {
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
        let _ = self.serialize_with_length(&mut data, false)?;
        pack_bytes(&mut data);
        Ok(data)
    }

    fn serialize_with_length(
        &self,
        buffer: &mut Vec<u8>,
        with_length_bit: bool,
    ) -> Result<usize, SerializeError> {
        if self.len() > N {
            return Err(InstanceError::Bounded { bound: N, provided: self.len() }.into());
        }
        let start_len = buffer.len();
        buffer.extend_from_slice(self.as_raw_slice());

        if with_length_bit {
            let element_count = self.len();
            let marker_index = element_count % BITS_PER_BYTE;
            if marker_index == 0 {
                buffer.push(1u8);
            } else {
                let last = buffer.last_mut().expect("bitlist cannot be empty");
                *last |= 1u8 << marker_index;
            }
        }
        // SAFETY: checked subtraction is unnecessary, as buffer.len() > start_len; qed
        Ok(buffer.len() - start_len)
    }

    fn chunk_count() -> usize {
        (N + BITS_PER_CHUNK - 1) / BITS_PER_CHUNK
    }
}

impl<const N: usize> Deref for Bitlist<N> {
    type Target = BitlistInner;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<const N: usize> DerefMut for Bitlist<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl<const N: usize> Serializable for Bitlist<N> {
    fn is_variable_size() -> bool {
        true
    }

    fn size_hint() -> usize {
        0
    }
}

impl<const N: usize> Serialize for Bitlist<N> {
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        self.serialize_with_length(buffer, true)
    }
}

impl<const N: usize> Deserialize for Bitlist<N> {
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        // validate byte length - min
        if encoding.is_empty() {
            return Err(DeserializeError::ExpectedFurtherInput { provided: 0, expected: 1 });
        }

        // validate byte length - max
        let max_len = byte_length(N);
        if encoding.len() > max_len {
            return Err(DeserializeError::AdditionalInput {
                provided: encoding.len(),
                expected: max_len,
            });
        }

        let (last_byte, prefix) = encoding.split_last().unwrap();
        if *last_byte == 0u8 {
            return Err(DeserializeError::InvalidByte(*last_byte));
        }

        let mut result = BitlistInner::from_slice(prefix);
        let last = BitlistInner::from_element(*last_byte);

        // validate bit length satisfies bound `N`
        // SAFETY: checked subtraction is unnecessary,
        // as last_byte != 0, so last.trailing_zeros <= 7; qed
        // therefore: bit_length >= 1
        let bit_length = BITS_PER_BYTE - last.trailing_zeros();
        let additional_members = bit_length - 1; // skip marker bit
        let total_members = result.len() + additional_members;
        if total_members > N {
            return Err(DeserializeError::InvalidInstance(InstanceError::Bounded {
                bound: N,
                provided: total_members,
            }));
        }

        result.extend_from_bitslice(&last[..additional_members]);
        Ok(Self(result))
    }
}

impl<const N: usize> Merkleized for Bitlist<N> {
    fn hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
        let chunks = self.pack_bits()?;
        let data_root = merkleize(&chunks, Some(Self::chunk_count()))?;
        Ok(mix_in_length(&data_root, self.len()))
    }
}

impl<const N: usize> SimpleSerialize for Bitlist<N> {}

impl<const N: usize> TryFrom<&[u8]> for Bitlist<N> {
    type Error = Error;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Self::deserialize(value).map_err(Error::Deserialize)
    }
}

impl<const N: usize> TryFrom<&[bool]> for Bitlist<N> {
    type Error = Error;

    fn try_from(value: &[bool]) -> Result<Self, Self::Error> {
        if value.len() > N {
            let len = value.len();
            Err(Error::Instance(InstanceError::Bounded { bound: N, provided: len }))
        } else {
            let mut result = Self::default();
            for bit in value {
                result.push(*bit);
            }
            Ok(result)
        }
    }
}

#[cfg(feature = "serde")]
impl<const N: usize> serde::Serialize for Bitlist<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let byte_count = byte_length(self.len());
        let mut buf = Vec::with_capacity(byte_count);
        let _ = crate::Serialize::serialize(self, &mut buf).map_err(serde::ser::Error::custom)?;
        crate::serde::as_hex::serialize(&buf, serializer)
    }
}

#[cfg(feature = "serde")]
impl<'de, const N: usize> serde::Deserialize<'de> for Bitlist<N> {
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

    const COUNT: usize = 256;

    #[test]
    fn encode_bitlist() {
        let value: Bitlist<COUNT> = Bitlist::default();
        let encoding = serialize(&value).expect("can encode");
        let expected = [1u8];
        assert_eq!(encoding, expected);

        let mut value: Bitlist<COUNT> = Bitlist::default();
        value.push(false);
        value.push(true);
        let encoding = serialize(&value).expect("can encode");
        let expected = [6u8];
        assert_eq!(encoding, expected);

        let mut value: Bitlist<COUNT> = Bitlist::default();
        value.push(false);
        value.push(false);
        value.push(false);
        value.push(true);
        value.push(true);
        value.push(false);
        value.push(false);
        value.push(false);
        assert!(!value.get(0).expect("test data correct"));
        assert!(value.get(3).expect("test data correct"));
        assert!(value.get(4).expect("test data correct"));
        assert!(!value.get(7).expect("test data correct"));
        let encoding = serialize(&value).expect("can encode");
        let expected = [24u8, 1u8];
        assert_eq!(encoding, expected);
    }

    #[test]
    fn decode_bitlist() {
        let bytes = vec![1u8];
        let result = Bitlist::<COUNT>::deserialize(&bytes).expect("test data is correct");
        let expected = Bitlist::<COUNT>::default();
        assert_eq!(result, expected);

        let bytes = vec![24u8, 1u8];
        let result = Bitlist::<COUNT>::deserialize(&bytes).expect("test data is correct");
        let expected =
            Bitlist::try_from([false, false, false, true, true, false, false, false].as_ref())
                .unwrap();
        assert_eq!(result, expected);

        let bytes = vec![24u8, 2u8];
        let result = Bitlist::<COUNT>::deserialize(&bytes).expect("test data is correct");
        let expected = Bitlist::try_from(
            [false, false, false, true, true, false, false, false, false].as_ref(),
        )
        .unwrap();
        assert_eq!(result, expected);
        let bytes = vec![24u8, 3u8];
        let result = Bitlist::<COUNT>::deserialize(&bytes).expect("test data is correct");
        let expected = Bitlist::try_from(
            [false, false, false, true, true, false, false, false, true].as_ref(),
        )
        .unwrap();
        assert_eq!(result, expected);

        let bytes = vec![24u8, 0u8];
        let result = Bitlist::<COUNT>::deserialize(&bytes).expect_err("test data is incorrect");
        let expected = DeserializeError::InvalidByte(0u8);
        assert_eq!(result.to_string(), expected.to_string());
    }

    #[test]
    fn roundtrip_bitlist() {
        let input = Bitlist::<COUNT>::try_from(
            [
                false, false, false, true, true, false, false, false, false, false, false, false,
                false, false, false, true, true, false, false, false, false, false, false, false,
                true,
            ]
            .as_ref(),
        )
        .unwrap();
        let mut buffer = vec![];
        let _ = input.serialize(&mut buffer).expect("can serialize");
        let recovered = Bitlist::<COUNT>::deserialize(&buffer).expect("can decode");
        assert_eq!(input, recovered);
    }
}
