extern crate rabe_bn;
extern crate rand;

// use rabe_bn::{Group, G1, G2};
use rand::Rng;

use crate::parser::Parser;

//
// use access_tree::TreeOperator;
//
// use crate::abe_attribute::AbeAttribute;
// use crate::access_tree::AccessTree::Leaf;
// use crate::access_tree::AccessTree::Operator;
// use crate::crypto::{decrypt, encrypt, keygen, setup};
// use crate::parser::Lexer;

mod abe_attribute;
mod access_tree;
mod aes;
mod crypto;
mod errors;
mod models;
mod parser;

fn main() {
    let input = "A&B|c";
    let mut parser = Parser::new(input);
    let result = parser.parse();
    println!("{:#?}", result);
}

// fn main() {
//     let rng = &mut rand::thread_rng();
//
//     let tree = Operator {
//         operator: TreeOperator::Or,
//         left: Box::from(Operator {
//             operator: TreeOperator::And,
//             left: Box::from(Leaf {
//                 attribute: AbeAttribute::new("A"),
//                 value: None,
//             }),
//             right: Box::from(Leaf {
//                 attribute: AbeAttribute::new("B"),
//                 value: None,
//             }),
//             value: None,
//         }),
//         right: Box::from(Operator {
//             operator: TreeOperator::Or,
//             left: Box::from(Leaf {
//                 attribute: AbeAttribute::new("C"),
//                 value: None,
//             }),
//             right: Box::from(Leaf {
//                 attribute: AbeAttribute::new("D"),
//                 value: None,
//             }),
//             value: None,
//         }),
//         value: None,
//     };
//
//     let secret = rng.gen();
//     let message_bytes = String::from("Hello World!").into_bytes();
//
//     let (public_key, master_key) = setup(tree.clone(), G1::one(), G2::one(), rng);
//     let secret_key = keygen(
//         vec![AbeAttribute::new("A"), AbeAttribute::new("B")],
//         public_key.clone(),
//         master_key.clone(),
//         rng,
//     );
//     let cipher_text = encrypt(
//         secret,
//         &message_bytes,
//         public_key.clone(),
//         tree.clone(),
//         rng,
//     )
//     .unwrap();
//
//     let decrypted = decrypt(cipher_text, secret_key).unwrap();
//
//     // assert that m and _m_prime are equal
//     assert_eq!(secret, decrypted.secret);
//     assert_eq!(message_bytes, decrypted.message);
// }
