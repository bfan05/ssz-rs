use ssz_rs::prelude::*;

// #[derive(Debug, SimpleSerialize, PartialEq, Eq)]
// struct Foo {
//     a: u8,
//     b: u32,
// }

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
