mod access_tree;
mod models;
mod abe_attribute;
mod invalid_argument_error;

extern crate rabe_bn;
extern crate rand;

use std::collections::{HashMap};
use rand::Rng;
use rabe_bn::{Group, Fr, G1, G2, pairing, Gt};
use access_tree::TreeOperator;
use crate::abe_attribute::AbeAttribute;
use crate::access_tree::{AccessTree, AssignValues, GetAttributes, MinimalSetFinder};
use crate::access_tree::AccessTree::Operator;
use crate::access_tree::AccessTree::Leaf;
use crate::invalid_argument_error::InvalidAttributesError;
use crate::models::{AbePublicKey, AbeMasterKey, AbeSecretKey, AbeCipherText};

fn setup<R: Rng + ?Sized>(access_tree: AccessTree, g: G1, g2: G2, rng: &mut R) -> (AbePublicKey, AbeMasterKey) {
    let attributes = access_tree.get_attributes();

    let mut small_t = HashMap::new();
    for i in 0..attributes.len() {
        small_t.insert(attributes[i].name.clone(), rng.gen());
    }

    let alpha: Fr = rng.gen();
    let pair = pairing(g, g2);
    let y = pair.pow(alpha);

    let mut big_t = HashMap::new();
    for i in 0..attributes.len() {
        big_t.insert(attributes[i].name.clone(), g * small_t[&attributes[i].name]);
    }

    (AbePublicKey {
        map: pair,
        g1: g,
        g2,
        y,
        big_t,
    },
     AbeMasterKey {
         alpha,
         small_t,
     })
}

fn keygen<R: Rng + ?Sized>(attributes: Vec<AbeAttribute>, public_key: AbePublicKey, master_key: AbeMasterKey, rng: &mut R) -> AbeSecretKey {
    let r = rng.gen();
    let d_0 = public_key.g2 * (master_key.alpha - r);

    let arr_d = attributes.iter().map(|a| (a.name.clone(), public_key.g2 * (r * master_key.small_t[&a.name].inverse().unwrap()))).collect::<HashMap<String, G2>>();

    AbeSecretKey {
        d_0,
        arr_d,
    }
}

fn encrypt<R: Rng + ?Sized>(message: Gt, public_key: AbePublicKey, access_tree: AccessTree, rng: &mut R) -> AbeCipherText {
    let s = rng.gen();
    let c_0 = public_key.g1 * s;
    let c_1 = message * public_key.y.pow(s);
    let filled_tree = access_tree.assign_values(s, None, rng);
    let c_j = filled_tree.get_attributes().iter().map(|x| (x.name.clone(), public_key.big_t[&x.name] * x.value.unwrap())).collect::<HashMap<String, G1>>();

    AbeCipherText {
        access_tree: Box::new(filled_tree),
        c_0,
        c_1,
        arr_c: c_j,
    }
}

fn decrypt(cipher_text: AbeCipherText, secret_key: AbeSecretKey) -> Result<Gt, InvalidAttributesError> {
    let original_set = secret_key.arr_d.iter().map(|(name, _)| AbeAttribute::new(name)).collect::<Vec<AbeAttribute>>();
    let minimal_set = cipher_text.access_tree.find_minimal_set(&original_set)?;

    let mut product = None;
    for (name, d) in secret_key.arr_d.iter().filter(|(name, _)| minimal_set.contains(&AbeAttribute::new(name))) {
        if product == None {
            product = Some(pairing(cipher_text.arr_c[name], *d));
        } else {
            product = Some(product.unwrap() * pairing(cipher_text.arr_c[name], *d));
        }
    }

    let egsga = pairing(cipher_text.c_0, secret_key.d_0) * product.unwrap();
    let m_prime = cipher_text.c_1 * egsga.inverse();

    Ok(m_prime)
}

fn main() {
    let rng = &mut rand::thread_rng();

    let tree = Operator {
        operator: TreeOperator::Or,
        left: Box::from(Operator {
            operator: TreeOperator::And,
            left: Box::from(Leaf { attribute: AbeAttribute::new("A"), value: None }),
            right: Box::from(Leaf { attribute: AbeAttribute::new("B"), value: None }),
            value: None,
        }),
        right: Box::from(Operator {
            operator: TreeOperator::Or,
            left: Box::from(Leaf { attribute: AbeAttribute::new("C"), value: None }),
            right: Box::from(Leaf { attribute: AbeAttribute::new("D"), value: None }),
            value: None,
        }),
        value: None,
    };

    let m = rng.gen();

    let (public_key, master_key) = setup(tree.clone(), G1::one(), G2::one(), rng);
    let secret_key = keygen(vec![AbeAttribute::new("A"), AbeAttribute::new("B")], public_key.clone(), master_key.clone(), rng);
    let cipher_text = encrypt(m, public_key.clone(), tree.clone(), rng);
    let m_prime = decrypt(cipher_text, secret_key);

    // assert that m and _m_prime are equal
    assert_eq!(m, m_prime.unwrap());
}