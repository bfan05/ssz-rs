use core::ops::Not;

use crate::{
    de::{deserialize_homogeneous_composite, Deserialize, DeserializeError},
    error::{Error, InstanceError, TypeError},
    lib::*,
    merkleization::{
        elements_to_chunks, merkleize, pack, MerkleProof, MerkleizationError, Merkleized, Node,
        BYTES_PER_CHUNK, NUM_BYTES_TO_SQUEEZE,
    },
    ser::{Serialize, SerializeError, Serializer},
    Serializable, SimpleSerialize,
};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// A homogenous collection of a fixed number of values.
/// NOTE: a `Vector` of length `0` is illegal.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct Vector<T: Serializable, const N: usize> {
    data: Vec<T>,
}

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

impl<T, const N: usize> MerkleProof for Vector<T, N>
where
    // T: Serializable + Merkleized,
    T: Serializable + Merkleized,
{
    fn get_len_and_tree_depth(&mut self) -> (usize, usize) {
        let mut len = self.as_ref().len();
        let mut tree_depth = get_power_of_two_ceil(len);
        if T::is_composite_type().not() {
            len = pack(self.as_ref()).unwrap().len() / BYTES_PER_CHUNK;
            tree_depth = get_power_of_two_ceil(len);
        }
        tree_depth = log2(tree_depth) as usize;
        (len, tree_depth)
    }

    fn get_hash_tree(&mut self) -> Vec<Vec<u8>> {
        let (len, tree_depth) = self.get_len_and_tree_depth();

        let base: usize = 2;
        let pow2 = base.pow(tree_depth as u32);
        let mut root_vec = vec![Vec::<u8>::new(); pow2];

        if T::is_composite_type() {
            for i in 0..len {
                let root = self[i].hash_tree_root();
                root_vec.push(root.as_ref().unwrap().to_vec());
            }
        } else {
            let new_chunks = pack(self.as_ref()).unwrap();
            for i in 0..(new_chunks.len() / BYTES_PER_CHUNK) {
                let mut slice: Vec<u8> = vec![0; BYTES_PER_CHUNK];
                for j in (BYTES_PER_CHUNK * i)..(BYTES_PER_CHUNK * i + 32) {
                    slice[j - BYTES_PER_CHUNK * i] = new_chunks[j];
                }

                root_vec.push(slice);
            }
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

    fn get_proof(&mut self, idx: usize) -> Map<String, Value> {
        let roots = self.get_hash_tree();
        let zeroes = self.get_zeroes();

        let (len, tree_depth) = self.get_len_and_tree_depth();

        let scale = get_power_of_two_ceil(self.as_ref().len() / len);

        let total_depth = get_power_of_two_ceil(N / scale);
        let total_depth = log2(total_depth) as usize;

        let idx_to_get = (idx as usize) / scale;

        let base_len = total_depth - tree_depth;

        let mut base_path = vec![vec![0; 32]; base_len];
        let mut base_dir = vec![0; base_len];

        let mut root = roots[1].clone();
        for i in 1..(base_len + 1) {
            // base_path[base_len - i] contains the zero hash along the path
            base_path[base_len - i] = zeroes[tree_depth + i].clone();
            // root is the hash of the current element we are on, eventually will be hash of everything
            let mut root_clone = root.clone();
            // hash root with the corresponding 0
            root_clone.append(&mut base_path[base_len - i].clone());
            root = sha256(root_clone).to_vec();
        }

        // dir of proof
        let mut new_dir = vec![0; tree_depth];
        let mut dir_idx: usize = idx_to_get;
        for i in 0..tree_depth {
            new_dir[total_depth - base_len - 1 - i] = dir_idx % 2;
            dir_idx /= 2;
        }
        let mut roots_idx: usize = 1;
        let mut new_path = Vec::new();
        // roots_idx is the index of the element along the path whose hash we need
        // new_path is the path of the merkle proof
        for i in 0..tree_depth {
            roots_idx = roots_idx * 2 + new_dir[i];
            new_path.push(roots[roots_idx ^ 1].clone());
        }
        // get the full path and directions
        base_path.append(&mut new_path);
        base_dir.append(&mut new_dir);

        // val is the hash root of the actual validator we want to get
        let val = roots[roots_idx].clone();

        let mut map = Map::new();

        let root = hex::encode(root);
        let val = hex::encode(val);
        let mut proof: Vec<String> = base_path.iter().map(|p| hex::encode(p)).collect();

        // println!("val: {:?}", val);
        // println!("root: {:?}", root);

        map.insert("directions".to_owned(), base_dir.into());
        map.insert("val".to_owned(), val.into());
        map.insert("root_bytes".to_owned(), root.into());
        map.insert("proof".to_owned(), proof.into());

        map

        // if vec.len() == 1 {
        //     return proof;
        // } else {
        //     proof.append(&mut self[idx_to_get].get_proof(vec[1..].to_vec()));
        //     return proof;
        // }
    }
}

impl<T: Serializable, const N: usize> AsRef<[T]> for Vector<T, N> {
    fn as_ref(&self) -> &[T] {
        &self.data
    }
}

impl<T: Serializable + PartialEq, const N: usize> PartialEq for Vector<T, N> {
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<T: Serializable + Eq, const N: usize> Eq for Vector<T, N> {}

impl<T: Serializable, const N: usize> TryFrom<Vec<T>> for Vector<T, N> {
    type Error = (Vec<T>, Error);

    fn try_from(data: Vec<T>) -> Result<Self, Self::Error> {
        if N == 0 {
            return Err((data, Error::Type(TypeError::InvalidBound(N))));
        }
        if data.len() != N {
            let len = data.len();
            Err((data, Error::Instance(InstanceError::Exact { required: N, provided: len })))
        } else {
            Ok(Self { data })
        }
    }
}

impl<T, const N: usize> TryFrom<&[T]> for Vector<T, N>
where
    T: Serializable + Clone,
{
    type Error = Error;

    fn try_from(data: &[T]) -> Result<Self, Self::Error> {
        if N == 0 {
            return Err(Error::Type(TypeError::InvalidBound(N)));
        }
        if data.len() != N {
            let len = data.len();
            Err(Error::Instance(InstanceError::Exact { required: N, provided: len }))
        } else {
            Ok(Self { data: data.to_vec() })
        }
    }
}

impl<T, const N: usize> fmt::Debug for Vector<T, N>
where
    T: Serializable + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        if f.alternate() {
            write!(f, "Vector<{}, {}>{:#?}", any::type_name::<T>(), N, self.data)
        } else {
            write!(f, "Vector<{}, {}>{:?}", any::type_name::<T>(), N, self.data)
        }
    }
}

impl<T, const N: usize> Default for Vector<T, N>
where
    T: Serializable + Default,
{
    fn default() -> Self {
        // SAFETY: there is currently no way to enforce statically
        // that `N` is non-zero with const generics so panics are possible.
        assert!(N > 0);

        let mut data = Vec::with_capacity(N);
        for _ in 0..N {
            data.push(T::default());
        }

        // SAFETY: panic can't happen because data.len() == N != 0; qed
        data.try_into()
            // need to drop data so we do not require it as Debug as required by `expect`
            .map_err(|(_, err)| err)
            .expect("any Vector can be constructed with nonzero default data")
    }
}

impl<T, const N: usize> Deref for Vector<T, N>
where
    T: Serializable,
{
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T, Idx: SliceIndex<[T]>, const N: usize> Index<Idx> for Vector<T, N>
where
    T: Serializable,
{
    type Output = <Idx as SliceIndex<[T]>>::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.data[index]
    }
}

// NOTE: implement `IndexMut` rather than `DerefMut` to ensure
// the inner data is not mutated without being able to
// track which elements changed
impl<T, Idx: SliceIndex<[T]>, const N: usize> IndexMut<Idx> for Vector<T, N>
where
    T: Serializable,
{
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl<T, const N: usize> Serializable for Vector<T, N>
where
    T: Serializable,
{
    fn is_variable_size() -> bool {
        T::is_variable_size()
    }

    fn size_hint() -> usize {
        T::size_hint() * N
    }
}

impl<T, const N: usize> Serialize for Vector<T, N>
where
    T: Serializable,
{
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        if N == 0 {
            return Err(TypeError::InvalidBound(N).into());
        }
        let mut serializer = Serializer::default();
        for element in &self.data {
            serializer.with_element(element)?;
        }
        serializer.serialize(buffer)
    }
}

impl<T, const N: usize> Deserialize for Vector<T, N>
where
    T: Serializable,
{
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        if N == 0 {
            return Err(TypeError::InvalidBound(N).into());
        }
        if !T::is_variable_size() {
            let expected_length = N * T::size_hint();
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
        }
        let inner = deserialize_homogeneous_composite(encoding)?;
        inner.try_into().map_err(|(_, err)| match err {
            Error::Deserialize(err) => err,
            Error::Instance(err) => DeserializeError::InvalidInstance(err),
            Error::Type(err) => DeserializeError::InvalidType(err),
            _ => unreachable!("no other error variant can be returned at this point"),
        })
    }
}

impl<T, const N: usize> Vector<T, N>
where
    T: Serializable,
{
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        let inner = self.data.iter_mut();
        IterMut { inner }
    }
}

pub struct IterMut<'a, T: 'a> {
    inner: slice::IterMut<'a, T>,
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<T, const N: usize> Vector<T, N>
where
    T: SimpleSerialize,
{
    fn compute_hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
        if T::is_composite_type() {
            let count = self.len();
            let chunks = elements_to_chunks(self.data.iter_mut().enumerate(), count)?;
            merkleize(&chunks, None)
        } else {
            let chunks = pack(&self.data)?;
            merkleize(&chunks, None)
        }
    }
}

impl<T, const N: usize> Merkleized for Vector<T, N>
where
    T: SimpleSerialize,
{
    fn hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
        self.compute_hash_tree_root()
    }
}

impl<T, const N: usize> SimpleSerialize for Vector<T, N> where T: SimpleSerialize {}

#[cfg(feature = "serde")]
struct VectorVisitor<T: Serializable>(PhantomData<Vec<T>>);

#[cfg(feature = "serde")]
impl<'de, T: Serializable + serde::Deserialize<'de>> serde::de::Visitor<'de> for VectorVisitor<T> {
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("sequence")
    }

    fn visit_seq<S>(self, visitor: S) -> Result<Self::Value, S::Error>
    where
        S: serde::de::SeqAccess<'de>,
    {
        serde::Deserialize::deserialize(serde::de::value::SeqAccessDeserializer::new(visitor))
    }
}

#[cfg(feature = "serde")]
impl<'de, T: Serializable + serde::Deserialize<'de>, const N: usize> serde::Deserialize<'de>
    for Vector<T, N>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = deserializer.deserialize_seq(VectorVisitor(PhantomData))?;
        Vector::<T, N>::try_from(data).map_err(|(_, err)| serde::de::Error::custom(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{list::List, serialize};

    const COUNT: usize = 32;

    #[test]
    fn test_try_from() {
        let mut data = vec![2u8; 10];
        data.extend_from_slice(&[0u8; 10]);

        let vector = Vector::<u8, 20>::try_from(data).unwrap();
        assert_eq!(vector[..10], [2u8; 10]);
        assert_eq!(vector[10..], [0u8; 10]);
    }

    #[test]
    #[should_panic]
    fn test_try_from_invalid() {
        let data = vec![2u8; 10];
        let vector = Vector::<u8, 1>::try_from(data).unwrap();
        assert_eq!(vector[0], 2u8);
    }

    #[test]
    fn encode_vector() {
        let data = vec![33u16; COUNT];
        let mut value = Vector::<u16, COUNT>::try_from(data).unwrap();

        value[0] = 34u16;
        assert_eq!(value[0], 34u16);
        value[0] = 33u16;
        let encoding = serialize(&value).expect("can encode");
        let expected = [
            33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8,
            33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8,
            33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8,
            33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8, 33u8, 0u8,
        ];
        assert_eq!(encoding, expected);
    }

    #[test]
    fn decode_vector() {
        let bytes = vec![
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8,
            1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        ];
        let result = Vector::<u8, COUNT>::deserialize(&bytes).expect("can deserialize");
        let expected: Vector<u8, COUNT> = bytes.try_into().expect("test data");
        assert_eq!(result, expected);
    }

    #[test]
    fn decode_vector_with_no_input() {
        let source = vec![];
        let result = Vector::<u8, 6>::deserialize(&source);
        assert!(matches!(result, Err(DeserializeError::ExpectedFurtherInput { .. })));
    }

    #[test]
    fn decode_variable_vector() {
        const COUNT: usize = 4;
        let mut inner: Vec<List<u8, 1>> =
            Vec::from_iter((0..4).map(|i| List::try_from(vec![i]).unwrap()));
        let permutation = &mut inner[3];
        let _ = permutation.pop().expect("test data correct");
        let input: Vector<List<u8, 1>, COUNT> = inner.try_into().expect("test data correct");
        let mut buffer = vec![];
        let _ = input.serialize(&mut buffer).expect("can serialize");
        let expected = vec![16, 0, 0, 0, 17, 0, 0, 0, 18, 0, 0, 0, 19, 0, 0, 0, 0, 1, 2];
        assert_eq!(buffer, expected);
    }

    #[test]
    fn roundtrip_vector() {
        let bytes = vec![
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8,
            1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        ];
        let input: Vector<u8, COUNT> = bytes.try_into().expect("test data");
        let mut buffer = vec![];
        let _ = input.serialize(&mut buffer).expect("can serialize");
        let recovered = Vector::<u8, COUNT>::deserialize(&buffer).expect("can decode");
        assert_eq!(input, recovered);
    }

    #[test]
    fn roundtrip_variable_vector() {
        const COUNT: usize = 4;
        let mut inner: Vec<List<u8, 1>> =
            Vec::from_iter((0..4).map(|i| List::try_from(vec![i]).unwrap()));
        let permutation = &mut inner[3];
        let _ = permutation.pop().expect("test data correct");
        let input: Vector<List<u8, 1>, COUNT> = inner.try_into().expect("test data correct");
        let mut buffer = vec![];
        let _ = input.serialize(&mut buffer).expect("can serialize");
        let recovered = Vector::<List<u8, 1>, COUNT>::deserialize(&buffer).expect("can decode");
        assert_eq!(input, recovered);
    }

    #[test]
    fn can_iter_vector() {
        let bytes = vec![
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8,
            1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        ];
        let mut input: Vector<u8, COUNT> = bytes.try_into().expect("test data");
        for (i, &value) in input.iter().enumerate() {
            assert_eq!(value as usize, i % 8);
        }
        for value in input.iter_mut() {
            *value = 1;
            assert_eq!(*value, 1);
        }
    }

    #[test]
    fn test_serde() {
        type V = Vector<u8, 4>;
        let data = vec![1u8, 0, 22, 33];
        let input = V::try_from(data).unwrap();
        let input_str = serde_json::to_string(&input).unwrap();
        let recovered_input: V = serde_json::from_str(&input_str).unwrap();
        assert_eq!(input, recovered_input);
    }

    #[test]
    #[should_panic]
    fn test_illegal_serde() {
        type V = Vector<u8, 4>;
        let bad_input_str = "[]";
        let _: V = serde_json::from_str(bad_input_str).unwrap();
    }
}
