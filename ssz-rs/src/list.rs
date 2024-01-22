use core::ops::Not;

use crate::{
    de::{deserialize_homogeneous_composite, Deserialize, DeserializeError},
    error::{Error, InstanceError},
    lib::*,
    merkleization::{
        elements_to_chunks, merkleize, mix_in_length, pack, MerkleProof, MerkleizationError,
        Merkleized, Node, BYTES_PER_CHUNK, NUM_BYTES_TO_SQUEEZE,
    },
    ser::{Serialize, SerializeError, Serializer},
    Serializable, SimpleSerialize,
};

// use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
pub const LIST_LEN_IDX: usize = usize::MAX;
/// A homogenous collection of a variable number of values.
#[derive(Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct List<T: Serializable, const N: usize> {
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

impl<T, const N: usize> MerkleProof for List<T, N>
where
    // T: Serializable + Merkleized,
    T: Serializable + Merkleized + MerkleProof + serde::ser::Serialize + Debug,
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
    fn get_proof(&mut self, vec: Vec<usize>) -> serde_json::Map<String, serde_json::Value> {
        let idx = vec[0];
        let roots = self.get_hash_tree();
        let zeroes = self.get_zeroes();

        let (len, tree_depth) = self.get_len_and_tree_depth();

        let scale = get_power_of_two_ceil(self.as_ref().len() / len);

        let element_size = BYTES_PER_CHUNK / scale;

        let total_depth = get_power_of_two_ceil(N / scale);
        let total_depth = log2(total_depth) as usize;

        let idx_to_get = (idx as usize) / scale;

        let base_len = total_depth - tree_depth;
        let mut base_path = vec![vec![0; 32]; base_len + 1];

        let mut len_bytes: Vec<u8> = vec![0; 32];
        let mut len_int = self.as_ref().len();
        for i in 0..32 {
            len_bytes[i] = (len_int % 256) as u8;
            len_int /= 256;
        }

        base_path[0] = len_bytes.clone();
        let mut base_dir = vec![0; base_len + 1];

        let mut root = roots[1].clone();
        for i in 0..base_len {
            // base_path[base_len - i] contains the zero hash along the path
            base_path[base_len - i] = zeroes[tree_depth + i].clone();
            // root is the hash of the current element we are on, eventually will be hash of everything
            let mut root_clone = root.clone();
            // hash root with the corresponding 0
            root_clone.append(&mut base_path[base_len - i].clone());
            root = sha256(root_clone).to_vec();
        }
        let mut root_clone = root.clone();
        let root_copy = root.clone();
        root_clone.append(&mut base_path[0].clone());
        // root is the root of all the validators (including nonexistent ones)
        root = sha256(root_clone).to_vec();

        if idx == LIST_LEN_IDX {
            assert!(vec.len() == 1);
            let mut map = serde_json::Map::new();
            let root = hex::encode(root);
            let proof: Vec<String> = vec![hex::encode(root_copy)];
            let list_len_ind = vec![0];
            let list_item_ind = vec![0];
            let dirs = vec![1];
            let bytes_idx = vec![0, 32];
            let val = hex::encode(len_bytes);

            map.insert("directions".to_owned(), dirs.into());
            map.insert("val".to_owned(), val.clone().into());
            map.insert("root_bytes".to_owned(), root.into());
            map.insert("proof".to_owned(), proof.into());
            map.insert("bytes".to_owned(), bytes_idx.into());
            map.insert("list_len_ind".to_owned(), list_len_ind.into());
            map.insert("list_item_ind".to_owned(), list_item_ind.into());
            map.insert("field_value".to_owned(), val.into());
            return map;
        }

        let mut list_len_ind = vec![0; total_depth + 1];
        list_len_ind[0] = 1;
        let mut list_item_ind = vec![0; total_depth + 1];
        list_item_ind[total_depth] = 1;

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

        let mut map = serde_json::Map::new();

        let root = hex::encode(root);
        let val = hex::encode(val);
        let proof: Vec<String> = base_path.iter().map(|p| hex::encode(p)).collect();
        let bytes_idx = vec![(idx % scale) * element_size, ((idx % scale) + 1) * element_size];

        map.insert("directions".to_owned(), base_dir.into());
        map.insert("val".to_owned(), val.into());
        map.insert("root_bytes".to_owned(), root.into());
        map.insert("proof".to_owned(), proof.into());
        map.insert("bytes".to_owned(), bytes_idx.into());

        map.insert("list_len_ind".to_owned(), list_len_ind.into());
        map.insert("list_item_ind".to_owned(), list_item_ind.into());

        if vec.len() == 1 {
            map.insert("field_value".to_owned(), serde_json::to_value(&self[idx]).unwrap());
            return map;
        } else {
            // Obtain a mutable reference to the field
            let field = &mut self[idx];
            // println!("field PRINTED: {:?}", field);
            let new_proof = field.get_proof(vec[1..].to_vec());

            if let (
                Some(serde_json::Value::Array(ref mut directions)),
                Some(serde_json::Value::Array(new_directions)),
            ) = (map.get_mut("directions"), new_proof.get("directions"))
            {
                directions.extend(new_directions.clone());
            }

            map["val"] = new_proof["val"].clone();
            map.insert("field_value".to_owned(), new_proof["field_value"].clone());
            map["bytes"] = new_proof["bytes"].clone();

            if let (
                Some(serde_json::Value::Array(ref mut proof_map)),
                Some(serde_json::Value::Array(new_proof_map)),
            ) = (map.get_mut("proof"), new_proof.get("proof"))
            {
                proof_map.extend(new_proof_map.clone());
            }

            if let (
                Some(serde_json::Value::Array(ref mut list_len_ind_vec)),
                Some(serde_json::Value::Array(list_len_ind_vec_new)),
            ) = (map.get_mut("list_len_ind"), new_proof.get("list_len_ind"))
            {
                list_len_ind_vec.extend(list_len_ind_vec_new.clone());
            }

            if let (
                Some(serde_json::Value::Array(ref mut list_item_ind_vec)),
                Some(serde_json::Value::Array(list_item_ind_vec_new)),
            ) = (map.get_mut("list_item_ind"), new_proof.get("list_item_ind"))
            {
                list_item_ind_vec.extend(list_item_ind_vec_new.clone());
            }

            return map;
        }
    }
}

impl<T: Serializable, const N: usize> AsRef<[T]> for List<T, N> {
    fn as_ref(&self) -> &[T] {
        &self.data
    }
}

impl<T, const N: usize> fmt::Debug for List<T, N>
where
    T: Serializable + fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        if f.alternate() {
            write!(f, "List<{}, {}>(len={}){:#?}", any::type_name::<T>(), N, self.len(), self.data)
        } else {
            write!(f, "List<{}, {}>(len={}){:?}", any::type_name::<T>(), N, self.len(), self.data)
        }
    }
}

impl<T, const N: usize> Default for List<T, N>
where
    T: Serializable,
{
    fn default() -> Self {
        let data = vec![];
        data.try_into()
            // need to drop data so we do not require it as Debug as required by `expect`
            .map_err(|(_, err)| err)
            .expect("any List can be constructed from an empty Vec")
    }
}

impl<T, const N: usize> PartialEq for List<T, N>
where
    T: Serializable + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<T, const N: usize> Eq for List<T, N> where T: Serializable + Eq {}

impl<T, const N: usize> TryFrom<Vec<T>> for List<T, N>
where
    T: Serializable,
{
    type Error = (Vec<T>, Error);

    fn try_from(data: Vec<T>) -> Result<Self, Self::Error> {
        if data.len() > N {
            let len = data.len();
            Err((data, Error::Instance(InstanceError::Bounded { bound: N, provided: len })))
        } else {
            Ok(Self { data })
        }
    }
}

impl<T, const N: usize> TryFrom<&[T]> for List<T, N>
where
    T: Serializable + Clone,
{
    type Error = Error;

    fn try_from(data: &[T]) -> Result<Self, Self::Error> {
        if data.len() > N {
            let len = data.len();
            Err(Error::Instance(InstanceError::Bounded { bound: N, provided: len }))
        } else {
            Ok(Self { data: data.to_vec() })
        }
    }
}

impl<T, const N: usize> Deref for List<T, N>
where
    T: Serializable,
{
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T, Idx: SliceIndex<[T]>, const N: usize> Index<Idx> for List<T, N>
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
impl<T, Idx: SliceIndex<[T]>, const N: usize> IndexMut<Idx> for List<T, N>
where
    T: Serializable,
{
    fn index_mut(&mut self, index: Idx) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl<T, const N: usize> Serializable for List<T, N>
where
    T: Serializable,
{
    fn is_variable_size() -> bool {
        true
    }

    fn size_hint() -> usize {
        0
    }
}

impl<T, const N: usize> Serialize for List<T, N>
where
    T: Serializable,
{
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        if self.len() > N {
            return Err(InstanceError::Bounded { bound: N, provided: self.len() }.into());
        }
        let mut serializer = Serializer::default();
        for element in &self.data {
            serializer.with_element(element)?;
        }
        serializer.serialize(buffer)
    }
}

impl<T, const N: usize> Deserialize for List<T, N>
where
    T: Serializable,
{
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        if !T::is_variable_size() {
            let remainder = encoding.len() % T::size_hint();
            if remainder != 0 {
                return Err(DeserializeError::AdditionalInput {
                    provided: encoding.len(),
                    // SAFETY: checked subtraction is unnecessary, as encoding.len() > remainder;
                    // qed
                    expected: encoding.len() - remainder,
                });
            }
        }

        let result = deserialize_homogeneous_composite(encoding)?;
        if result.len() > N {
            return Err(InstanceError::Bounded { bound: N, provided: result.len() }.into());
        }
        let result = result.try_into().map_err(|(_, err)| match err {
            Error::Instance(err) => DeserializeError::InvalidInstance(err),
            _ => unreachable!("no other error variant allowed here"),
        })?;
        Ok(result)
    }
}

impl<T, const N: usize> List<T, N>
where
    T: Serializable,
{
    pub fn push(&mut self, element: T) {
        self.data.push(element);
    }

    pub fn pop(&mut self) -> Option<T> {
        self.data.pop()
    }

    pub fn clear(&mut self) {
        self.data.clear();
    }

    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        IterMut { inner: self.data.iter_mut() }
    }
}

pub struct IterMut<'a, T> {
    inner: slice::IterMut<'a, T>,
}

impl<'a, T> Iterator for IterMut<'a, T> {
    type Item = &'a mut T;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner.next()
    }
}

impl<T, const N: usize> List<T, N>
where
    T: SimpleSerialize,
{
    // Number of chunks for this type, rounded up to a complete number of chunks
    fn chunk_count() -> usize {
        (N * T::size_hint() + BYTES_PER_CHUNK - 1) / BYTES_PER_CHUNK
    }

    fn compute_hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
        if T::is_composite_type() {
            let count = self.len();
            let chunks = elements_to_chunks(self.data.iter_mut().enumerate(), count)?;
            let data_root = merkleize(&chunks, Some(N))?;
            Ok(mix_in_length(&data_root, self.len()))
        } else {
            let chunks = pack(self)?;
            let data_root = merkleize(&chunks, Some(Self::chunk_count()))?;
            Ok(mix_in_length(&data_root, self.len()))
        }
    }
}

impl<T, const N: usize> Merkleized for List<T, N>
where
    T: SimpleSerialize,
{
    fn hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
        self.compute_hash_tree_root()
    }
}

impl<T, const N: usize> SimpleSerialize for List<T, N> where T: SimpleSerialize {}

#[cfg(feature = "serde")]
struct ListVisitor<T: Serializable>(PhantomData<Vec<T>>);

#[cfg(feature = "serde")]
impl<'de, T: Serializable + serde::Deserialize<'de>> serde::de::Visitor<'de> for ListVisitor<T> {
    type Value = Vec<T>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("array of objects")
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
    for List<T, N>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let data = deserializer.deserialize_seq(ListVisitor(PhantomData))?;
        List::<T, N>::try_from(data).map_err(|(_, err)| serde::de::Error::custom(err))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialize;

    const COUNT: usize = 32;

    #[test]
    fn encode_list() {
        let mut value: List<u16, COUNT> = List::default();
        for _ in 0..COUNT {
            value.push(33u16);
        }
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
    fn decode_list() {
        let bytes = vec![
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8,
            1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        ];
        let result = List::<u8, COUNT>::deserialize(&bytes).expect("can deserialize");
        let expected: List<u8, COUNT> = bytes.try_into().unwrap();
        assert_eq!(result, expected);
    }

    #[test]
    fn roundtrip_list() {
        let bytes = vec![
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8,
            1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        ];
        let input: List<u8, COUNT> = bytes.try_into().unwrap();
        let mut buffer = vec![];
        let _ = input.serialize(&mut buffer).expect("can serialize");
        let recovered = List::<u8, COUNT>::deserialize(&buffer).expect("can decode");
        assert_eq!(input, recovered);
    }

    #[test]
    fn roundtrip_list_of_list() {
        const COUNT: usize = 4;
        let bytes: Vec<List<u8, 1>> =
            vec![vec![0u8].try_into().unwrap(), Default::default(), vec![1u8].try_into().unwrap()];
        let input: List<List<u8, 1>, COUNT> = bytes.try_into().unwrap();
        let mut buffer = vec![];
        let _ = input.serialize(&mut buffer).expect("can serialize");
        let recovered = List::<List<u8, 1>, COUNT>::deserialize(&buffer).expect("can decode");
        assert_eq!(input, recovered);
    }

    #[test]
    fn test_ssz_of_nested_list() {
        use crate::prelude::*;
        type Foo = List<List<u8, 16>, 32>;

        let mut value = Foo::default();
        value.push(Default::default());
        let encoding = ssz_rs::serialize(&value).unwrap();

        let mut recovered: Foo = ssz_rs::deserialize(&encoding).unwrap();
        assert_eq!(value, recovered);

        let _ = recovered.hash_tree_root().unwrap();
    }

    #[test]
    fn can_iter_list() {
        let bytes = vec![
            0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8,
            1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8, 0u8, 1u8, 2u8, 3u8, 4u8, 5u8, 6u8, 7u8,
        ];
        let mut input: List<u8, COUNT> = bytes.try_into().unwrap();
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
        type L = List<u8, 4>;
        let data = vec![1u8, 22];
        let input = L::try_from(data).unwrap();
        let input_str = serde_json::to_string(&input).unwrap();
        let recovered_input: L = serde_json::from_str(&input_str).unwrap();
        assert_eq!(input, recovered_input);
    }

    #[test]
    #[should_panic]
    fn test_illegal_serde() {
        type L = List<u8, 4>;
        let bad_input_str = "[1, 2, 3, 4, 5]";
        let _: L = serde_json::from_str(bad_input_str).unwrap();
    }
}
