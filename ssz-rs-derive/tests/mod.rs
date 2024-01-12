use ssz_rs::prelude::*;
use ssz_rs_derive::SimpleSerialize;

// pub fn log2(x: usize) -> u32 {
//     if x == 0 {
//         0
//     } else if x.is_power_of_two() {
//         1usize.leading_zeros() - x.leading_zeros()
//     } else {
//         0usize.leading_zeros() - x.leading_zeros()
//     }
// }

// pub fn get_power_of_two_ceil(x: usize) -> usize {
//     match x {
//         x if x <= 1 => 1,
//         2 => 2,
//         x => 2 * get_power_of_two_ceil((x + 1) / 2),
//     }
// }

// pub fn sha256<T: AsRef<[u8]>>(bytes: T) -> [u8; 32] {
//     let mut hasher = Sha256::new();
//     hasher.update(bytes.as_ref());
//     let output = hasher.finalize();
//     output.into()
// }

#[derive(Debug, SimpleSerialize, PartialEq, Eq)]
struct Foo {
    a: u8,
    b: u32,
}

// #[derive(Debug, SimpleSerialize, PartialEq, Eq)]
// #[ssz(transparent)]
// enum Bar {
//     A(u8),
//     B(Foo),
// }

// #[derive(Debug, SimpleSerialize)]
// struct Wrapper(Foo);

// #[test]
// fn test_transparent_helper() {
//     let mut f = Foo { a: 23, b: 445 };
//     let f_root = f.hash_tree_root().unwrap();
//     let mut bar = Bar::B(f);

//     let mut buf = vec![];
//     let _ = bar.serialize(&mut buf).unwrap();
//     let recovered_bar = Bar::deserialize(&buf).unwrap();
//     assert_eq!(bar, recovered_bar);

//     let bar_root = bar.hash_tree_root().unwrap();
//     assert_eq!(f_root, bar_root);
// }
