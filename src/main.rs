mod access_tree;
mod models;
mod abe_attribute;
mod errors;
mod aes;

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
use crate::errors::{AbeError};
use crate::models::{AbePublicKey, AbeMasterKey, AbeSecretKey, AbeCipherText, AbeDecrypted};

fn setup<R: Rng + ?Sized>(access_tree: AccessTree, g: G1, g2: G2, rng: &mut R) -> (AbePublicKey, AbeMasterKey) {
    let attributes = access_tree.get_attributes();

    // Generate random elements for each attribute
    // tj = random field element
    let mut small_t = HashMap::new();
    for i in 0..attributes.len() {
        small_t.insert(attributes[i].name.clone(), rng.gen());
    }
    let alpha: Fr = rng.gen();

    // y=e(g1,g2)^alpha
    let pair = pairing(g, g2);
    let y = pair.pow(alpha);

    // Tj = g^tj
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

    // d0 = g2^(alpha-r)
    let d_0 = public_key.g2 * (master_key.alpha - r);

    // dj = g2^(r * tj^-1)
    let arr_d = attributes.iter()
        .map(|a| (a.name.clone(), public_key.g2 * (r * master_key.small_t[&a.name].inverse().unwrap())))
        .collect::<HashMap<String, G2>>();

    AbeSecretKey {
        d_0,
        arr_d,
    }
}

fn encrypt<R: Rng + ?Sized>(secret: Gt, message: &Vec<u8>, public_key: AbePublicKey, access_tree: AccessTree, rng: &mut R) -> Result<AbeCipherText, AbeError> {
    // s = random field element
    let s = rng.gen();

    // c0 = g1^s
    let c_0 = public_key.g1 * s;

    // c1 = m * y^s
    let c_1 = secret * public_key.y.pow(s);

    // assign values to the tree according to scheme
    let filled_tree = access_tree.assign_values(s, None, rng);

    // cj = g1^tj * sj
    let c_j = filled_tree
        .get_attributes().iter()
        .map(|x| (x.name.clone(), public_key.big_t[&x.name] * x.value.unwrap()))
        .collect::<HashMap<String, G1>>();

    let message = aes::encrypt_symmetric(secret, message)?;

    Ok(AbeCipherText {
        access_tree: Box::new(filled_tree),
        c_0,
        c_1,
        arr_c: c_j,
        message
    })
}

fn decrypt(cipher_text: AbeCipherText, secret_key: AbeSecretKey) -> Result<AbeDecrypted, AbeError> {
    // find minimal set of attributes required to decrypt
    let original_set = secret_key.arr_d.iter().map(|(name, _)| AbeAttribute::new(name)).collect::<Vec<AbeAttribute>>();
    let minimal_set = cipher_text.access_tree.find_minimal_set(&original_set)?;

    // e(g,g)^rs = product of e(cj,dj)
    let mut product = None;
    for (name, d) in secret_key.arr_d.iter().filter(|(name, _)| minimal_set.contains(&AbeAttribute::new(name))) {
        if product == None {
            product = Some(pairing(cipher_text.arr_c[name], *d));
        } else {
            product = Some(product.unwrap() * pairing(cipher_text.arr_c[name], *d));
        }
    }

    // e(g^s,g^a) = e(c0,d0) * e(g,g)^rs
    let egsga = pairing(cipher_text.c_0, secret_key.d_0) * product.unwrap();

    // m' = c1 / e(g^s,g^a)
    let m_prime = cipher_text.c_1 * egsga.inverse();

    let message_bytes = aes::decrypt_symmetric(m_prime, &cipher_text.message)?;

    Ok(AbeDecrypted {
        secret: m_prime,
        message: message_bytes,
    })
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

    let secret = rng.gen();
    let message_bytes = String::from("Hello World!").into_bytes();

    let (public_key, master_key) = setup(tree.clone(), G1::one(), G2::one(), rng);
    let secret_key = keygen(vec![AbeAttribute::new("A"), AbeAttribute::new("B")], public_key.clone(), master_key.clone(), rng);
    let cipher_text = encrypt(secret, &message_bytes, public_key.clone(), tree.clone(), rng).unwrap();

    let decrypted = decrypt(cipher_text, secret_key).unwrap();

    // assert that m and _m_prime are equal
    assert_eq!(secret, decrypted.secret);
    assert_eq!(message_bytes, decrypted.message);
}