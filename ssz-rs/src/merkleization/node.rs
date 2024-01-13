use crate::{
    lib::*,
    merkleization::BYTES_PER_CHUNK,
    prelude::*,
    utils::{write_bytes_to_lower_hex, write_bytes_to_lower_hex_display},
};

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

fn log2(x: usize) -> u32 {
    if x == 0 {
        0
    } else if x.is_power_of_two() {
        1usize.leading_zeros() - x.leading_zeros()
    } else {
        0usize.leading_zeros() - x.leading_zeros()
    }
}

fn get_power_of_two_ceil(x: usize) -> usize {
    match x {
        x if x <= 1 => 1,
        2 => 2,
        x => 2 * get_power_of_two_ceil((x + 1) / 2),
    }
}

pub fn sha256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes.as_ref());
    let output = hasher.finalize();
    output.into()
}

/// A node in a merkle tree.
#[derive(Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, SimpleSerialize)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Node(
    #[cfg_attr(feature = "serde", serde(with = "crate::serde::as_hex"))] [u8; BYTES_PER_CHUNK],
);

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_bytes_to_lower_hex(f, self.0)
    }
}

impl fmt::Display for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write_bytes_to_lower_hex_display(f, self.0.iter())
    }
}

impl Deref for Node {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for Node {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

impl TryFrom<&[u8]> for Node {
    type Error = TryFromSliceError;

    fn try_from(value: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde() {
        let mut node = Node::default();
        node[2] = 33;
        let node_repr = serde_json::to_string(&node).unwrap();
        let recovered_node: Node = serde_json::from_str(&node_repr).unwrap();
        assert_eq!(node, recovered_node);
    }

    #[test]
    fn test_fmt() {
        let node = Node::try_from([23u8; 32].as_ref()).unwrap();
        let dbg = format!("{node:?}");
        assert_eq!(dbg, "0x1717171717171717171717171717171717171717171717171717171717171717");
        let display = format!("{node}");
        assert_eq!(display, "0x1717…1717");
    }
}
