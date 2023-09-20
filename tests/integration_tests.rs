use itertools::Itertools;
use rabe_bn::{Fr, Group, Gt, G1, G2};
use rand::Rng;

use crypto_rust::abe_attribute::AbeAttribute;
use crypto_rust::access_tree::TreeOperator::{And, Or};
use crypto_rust::access_tree::{AccessTree, GetAttributes, Leaf, Operator};
use crypto_rust::crypto::{decrypt, encrypt, keygen, setup};
use crypto_rust::parser::AccessTreeParser;

fn encrypt_decrypt(tree: &AccessTree, key_attributes: &Vec<AbeAttribute>) {
    let rng = &mut rand::thread_rng();

    let secret: Gt = rng.gen();
    let message_bytes = String::from("Hello World!").into_bytes();

    let attributes = tree
        .get_attributes()
        .iter()
        .map(|a| a.name.clone())
        .unique()
        .collect();

    let (public_key, master_key) = setup(&attributes, G1::one(), G2::one(), rng);

    let secret_key = keygen(
        &key_attributes.iter().map(|a| a.name.clone()).collect(),
        &public_key,
        &master_key,
        rng,
    )
    .unwrap();
    let cipher_text = encrypt(&secret, &message_bytes, &public_key, &tree, rng).unwrap();

    let decrypted = decrypt(&cipher_text, &secret_key).unwrap();

    assert_eq!(secret, decrypted.secret);
    assert_eq!(message_bytes, decrypted.message);
}

#[test]
fn correctness_test1() {
    let access_tree = AccessTree::Operator(Operator {
        left: Box::from(AccessTree::Operator(Operator {
            left: Box::from(AccessTree::Leaf(Leaf {
                value: None,
                attribute: AbeAttribute::new_with_value("A", Fr::one()),
            })),
            right: Box::from(AccessTree::Leaf(Leaf {
                value: None,
                attribute: AbeAttribute::new_with_value("B", Fr::one()),
            })),
            value: None,
            operator: And,
        })),
        right: Box::from(AccessTree::Operator(Operator {
            left: Box::from(AccessTree::Leaf(Leaf {
                value: None,
                attribute: AbeAttribute::new_with_value("C", Fr::one()),
            })),
            right: Box::from(AccessTree::Leaf(Leaf {
                value: None,
                attribute: AbeAttribute::new_with_value("D", Fr::one()),
            })),
            value: None,
            operator: And,
        })),
        value: None,
        operator: Or,
    });

    encrypt_decrypt(
        &access_tree,
        &vec![AbeAttribute::new("A"), AbeAttribute::new("B")],
    );
}

#[test]
fn correctness_test2() {
    let mut parser = AccessTreeParser::new("A&A");
    let access_tree = parser.parse().unwrap();

    encrypt_decrypt(&access_tree, &vec![AbeAttribute::new("A")]);
}

#[test]
fn correctness_test3() {
    let mut parser = AccessTreeParser::new("(A&A)&A");
    let access_tree = parser.parse().unwrap();

    encrypt_decrypt(&access_tree, &vec![AbeAttribute::new("A")]);
}

#[test]
fn correctness_test4() {
    let mut parser = AccessTreeParser::new("(A&B)|(C&D)");
    let access_tree = parser.parse().unwrap();

    encrypt_decrypt(
        &access_tree,
        &vec![AbeAttribute::new("A"), AbeAttribute::new("B")],
    );
}

#[test]
fn correctness_test_complex() {
    let mut parser = AccessTreeParser::new("((A&B)|(C&D))&((E&F)|(G&H))");
    let access_tree = parser.parse().unwrap();

    encrypt_decrypt(
        &access_tree,
        &vec![
            AbeAttribute::new("A"),
            AbeAttribute::new("B"),
            AbeAttribute::new("E"),
            AbeAttribute::new("F"),
        ],
    );
}

#[test]
fn correctness_test_very_complex() {
    let mut parser = AccessTreeParser::new("((A&B)|(C&D))&((E&F)|(G&H))&((I&J)|(K&L))");
    let access_tree = parser.parse().unwrap();

    encrypt_decrypt(
        &access_tree,
        &vec![
            AbeAttribute::new("A"),
            AbeAttribute::new("B"),
            AbeAttribute::new("E"),
            AbeAttribute::new("F"),
            AbeAttribute::new("I"),
            AbeAttribute::new("J"),
        ],
    );
}

#[test]
fn correctness_test_unbalanced_tree() {
    let mut parser =
        AccessTreeParser::new("((A&B)|(C&D))&((E&F)|(G&H))&((I&J)|(K&L))&((M&N)|(O&P))");
    let access_tree = parser.parse().unwrap();

    encrypt_decrypt(
        &access_tree,
        &vec![
            AbeAttribute::new("A"),
            AbeAttribute::new("B"),
            AbeAttribute::new("E"),
            AbeAttribute::new("F"),
            AbeAttribute::new("I"),
            AbeAttribute::new("J"),
            AbeAttribute::new("M"),
            AbeAttribute::new("N"),
        ],
    );
}

#[test]
fn correctness_test_long_chain() {
    let mut parser = AccessTreeParser::new("A&B&C&D&E&F&G&H&I&J&K&L&M&N&O&P");
    let access_tree = parser.parse().unwrap();

    encrypt_decrypt(
        &access_tree,
        &vec![
            AbeAttribute::new("A"),
            AbeAttribute::new("B"),
            AbeAttribute::new("C"),
            AbeAttribute::new("D"),
            AbeAttribute::new("E"),
            AbeAttribute::new("F"),
            AbeAttribute::new("G"),
            AbeAttribute::new("H"),
            AbeAttribute::new("I"),
            AbeAttribute::new("J"),
            AbeAttribute::new("K"),
            AbeAttribute::new("L"),
            AbeAttribute::new("M"),
            AbeAttribute::new("N"),
            AbeAttribute::new("O"),
            AbeAttribute::new("P"),
        ],
    );
}
