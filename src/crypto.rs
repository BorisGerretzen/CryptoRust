use std::collections::HashMap;

use rabe_bn::{pairing, Fr, Gt, G1, G2};
use rand::Rng;

use crate::abe_attribute::AbeAttribute;
use crate::access_tree::{AccessTree, AssignValues, GetAttributes, MinimalSetFinder};
use crate::aes;
use crate::errors::AbeError;
use crate::models::{AbeCipherText, AbeDecrypted, AbeMasterKey, AbePublicKey, AbeSecretKey};

pub fn setup<R: Rng + ?Sized>(
    attributes: &Vec<String>,
    g: G1,
    g2: G2,
    rng: &mut R,
) -> (AbePublicKey, AbeMasterKey) {
    // Generate random elements for each attribute
    // tj = random field element
    let mut small_t = HashMap::new();
    for i in 0..attributes.len() {
        small_t.insert(attributes[i].clone(), rng.gen());
    }
    let alpha: Fr = rng.gen();

    // y=e(g1,g2)^alpha
    let pair = pairing(g, g2);
    let y = pair.pow(alpha);

    // Tj = g^tj
    let mut big_t = HashMap::new();
    for i in 0..attributes.len() {
        big_t.insert(attributes[i].clone(), g * small_t[&attributes[i]]);
    }

    (
        AbePublicKey {
            map: pair,
            g1: g,
            g2,
            y,
            big_t,
        },
        AbeMasterKey { alpha, small_t },
    )
}

pub fn keygen<R: Rng + ?Sized>(
    attributes: &Vec<String>,
    public_key: &AbePublicKey,
    master_key: &AbeMasterKey,
    rng: &mut R,
) -> AbeSecretKey {
    let r = rng.gen();

    // d0 = g2^(alpha-r)
    let d_0 = public_key.g2 * (master_key.alpha - r);

    // dj = g2^(r * tj^-1)
    let arr_d = attributes
        .iter()
        .map(|a| {
            (
                a.clone(),
                public_key.g2 * (r * master_key.small_t[a].inverse().unwrap()),
            )
        })
        .collect::<HashMap<String, G2>>();

    AbeSecretKey { d_0, arr_d }
}

pub fn encrypt<R: Rng + ?Sized>(
    secret: &Gt,
    message: &Vec<u8>,
    public_key: &AbePublicKey,
    access_tree: &AccessTree,
    rng: &mut R,
) -> Result<AbeCipherText, AbeError> {
    // s = random field element
    let s = rng.gen();

    // c0 = g1^s
    let c_0 = public_key.g1 * s;

    // c1 = m * y^s
    let c_1 = *secret * public_key.y.pow(s);

    // assign values to the tree according to scheme
    let filled_tree = access_tree.assign_values(s, None, rng);

    // cj = g1^tj * sj
    let c_j = filled_tree
        .get_attributes()
        .iter()
        .map(|x| (x.name.clone(), public_key.big_t[&x.name] * x.value.unwrap()))
        .collect::<HashMap<String, G1>>();

    let message = aes::encrypt_symmetric(*secret, message)?;

    Ok(AbeCipherText {
        access_tree: Box::new(filled_tree),
        c_0,
        c_1,
        arr_c: c_j,
        message,
    })
}

pub fn decrypt(
    cipher_text: &AbeCipherText,
    secret_key: &AbeSecretKey,
) -> Result<AbeDecrypted, AbeError> {
    // find minimal set of attributes required to decrypt
    let original_set = secret_key
        .arr_d
        .iter()
        .map(|(name, _)| AbeAttribute::new(name))
        .collect::<Vec<AbeAttribute>>();
    let minimal_set = cipher_text.access_tree.find_minimal_set(&original_set)?;

    // e(g,g)^rs = product of e(cj,dj)
    let mut product = None;
    for (name, d) in secret_key
        .arr_d
        .iter()
        .filter(|(name, _)| minimal_set.contains(&AbeAttribute::new(name)))
    {
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

mod tests {
    use rabe_bn::Group;

    use crate::access_tree::TreeOperator::{And, Or};
    use crate::access_tree::{Leaf, Operator};

    use super::*;

    #[test]
    fn correctness_test1() {
        let rng = &mut rand::thread_rng();

        let access_tree = AccessTree::Operator(Operator {
            left: Box::from(AccessTree::Operator(Operator {
                left: Box::from(AccessTree::Leaf(Leaf {
                    value: None,
                    attribute: AbeAttribute {
                        name: "A".to_string(),
                        value: Some(Fr::one()),
                    },
                })),
                right: Box::from(AccessTree::Leaf(Leaf {
                    value: None,
                    attribute: AbeAttribute {
                        name: "B".to_string(),
                        value: Some(Fr::one()),
                    },
                })),
                value: None,
                operator: And,
            })),
            right: Box::from(AccessTree::Operator(Operator {
                left: Box::from(AccessTree::Leaf(Leaf {
                    value: None,
                    attribute: AbeAttribute {
                        name: "C".to_string(),
                        value: Some(Fr::one()),
                    },
                })),
                right: Box::from(AccessTree::Leaf(Leaf {
                    value: None,
                    attribute: AbeAttribute {
                        name: "D".to_string(),
                        value: Some(Fr::one()),
                    },
                })),
                value: None,
                operator: And,
            })),
            value: None,
            operator: Or,
        });

        let secret: Gt = rng.gen();
        let message_bytes = String::from("Hello World!").into_bytes();

        let (public_key, master_key) = setup(
            &access_tree
                .get_attributes()
                .iter()
                .map(|a| a.name.clone())
                .collect(),
            G1::one(),
            G2::one(),
            rng,
        );
        let secret_key = keygen(
            &vec!["A".to_string(), "B".to_string()],
            &public_key,
            &master_key,
            rng,
        );
        let cipher_text = encrypt(&secret, &message_bytes, &public_key, &access_tree, rng).unwrap();

        let decrypted = decrypt(&cipher_text, &secret_key).unwrap();

        // assert that m and _m_prime are equal
        assert_eq!(secret, decrypted.secret);
        assert_eq!(message_bytes, decrypted.message);
    }
}
