use std::collections::HashMap;

use linked_hash_map::LinkedHashMap;
use rabe_bn::{pairing, Fr, Gt, G1, G2};
use rand::Rng;

use crate::abe_attribute::{AbeAttribute, AbeIdentifier};
use crate::access_tree::{AccessTree, AssignValues, GetAttributes, MinimalSetFinder};
use crate::aes;
use crate::errors::abe_error::AbeError;
use crate::models::{
    AbeCipherText, AbeClientKey, AbeDecrypted, AbeMasterKey, AbeMediatorKey, AbePublicKey,
};

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

// pub fn adapt<R: Rng + ?Sized>(
//     public_key: &AbePublicKey,
//     master_key: &AbeMasterKey,
//     new_attributes: &Vec<String>,
//     rng: &mut R,
// ) -> (AbePublicKey, AbeMasterKey) {
//     // Generate random elements for each attribute
//     // tj = random field element
//     let mut small_t = master_key.small_t.clone();
//     for i in 0..new_attributes.len() {
//         small_t.insert(new_attributes[i].clone(), rng.gen());
//     }
//
//     // y=e(g1,g2)^alpha
//     let pair = pairing(public_key.g1, public_key.g2);
//     let y = pair.pow(master_key.alpha);
//
//     // Tj = g^tj
//     let mut big_t = public_key.big_t.clone();
//     for i in 0..new_attributes.len() {
//         big_t.insert(
//             new_attributes[i].clone(),
//             public_key.g1 * small_t[&new_attributes[i]],
//         );
//     }
//
//     (
//         AbePublicKey {
//             map: pair,
//             g1: public_key.g1,
//             g2: public_key.g2,
//             y,
//             big_t,
//         },
//         AbeMasterKey {
//             alpha: master_key.alpha,
//             small_t,
//         },
//     )
// }

pub fn keygen<R: Rng + ?Sized>(
    attributes: &Vec<String>,
    public_key: &AbePublicKey,
    master_key: &AbeMasterKey,
    rng: &mut R,
) -> Result<(AbeClientKey, AbeMediatorKey), AbeError> {
    let identifier = rng.gen();

    // d0 = g2^(alpha-identifer)
    let d_0 = public_key.g2 * (master_key.alpha - identifier);

    let mut inverses = Vec::new();
    for a in attributes {
        if !master_key.small_t.contains_key(a) {
            return Err(AbeError::new(
                format!("Attribute {} not found in master key", a).as_str(),
            ));
        }

        let inverse = master_key.small_t[a].inverse().ok_or(AbeError::new(
            format!("Could not calculate inverse of {}", a).as_str(),
        ));

        match inverse {
            Ok(inverse) => inverses.push((a, inverse)),
            Err(e) => return Err(e),
        }
    }

    let randoms: Vec<(&String, Fr)> = attributes
        .iter()
        .map(|a| {
            let random = rng.gen();
            (a, random)
        })
        .collect();

    // dj = g2 ^ uj / tj
    let mut arr_d_1 = Vec::new();

    // dj = g2 ^ (uid - uj) / tj
    let mut arr_d_2 = Vec::new();

    for a in attributes {
        let inverse = inverses
            .iter()
            .find(|x| *x.0 == *a)
            .ok_or(AbeError::new(
                format!("Could not find inverse for {}", a).as_str(),
            ))?
            .1;
        let uj = randoms
            .iter()
            .find(|x| *x.0 == *a)
            .ok_or(AbeError::new(
                format!("Could not find random for {}", a).as_str(),
            ))?
            .1;

        let val1 = (a.clone(), public_key.g2 * (uj * inverse));
        let val2 = (a.clone(), public_key.g2 * ((identifier - uj) * inverse));

        arr_d_1.push(val1);
        arr_d_2.push(val2);
    }

    Ok((
        AbeClientKey {
            unique_secret: identifier,
            d_0,
            arr_d_2: arr_d_2.into_iter().collect::<LinkedHashMap<String, G2>>(),
        },
        AbeMediatorKey {
            arr_d_1: arr_d_1.into_iter().collect::<LinkedHashMap<String, G2>>(),
        },
    ))
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
    let mut plain_tree = access_tree.clone();
    plain_tree.assign_indices();

    let mut filled_tree = access_tree.assign_values(s, None, rng);
    filled_tree.assign_indices();

    // cj = g1^tj * sj
    let attributes = filled_tree.get_attributes();
    let c_j = attributes.iter().map(|x| {
        let value = x.value.ok_or(AbeError::new(
            format!("Expected value for {} but got None", x.name).as_str(),
        ));

        match value {
            Ok(value) => Ok((
                AbeIdentifier::from(x.clone()),
                public_key.big_t[&x.name] * value,
            )),
            Err(e) => Err(e),
        }
    });

    let errors = c_j
        .clone()
        .filter(|d| d.is_err())
        .map(|d| d.clone().err().unwrap())
        .collect::<Vec<AbeError>>();

    if errors.len() > 0 {
        let mut error_message = String::from("Could not calculate cj for attributes: ");
        for error in errors {
            error_message.push_str(&format!("{:?}, ", error));
        }
        return Err(AbeError::new(error_message.as_str()));
    }

    let message = aes::encrypt_symmetric(*secret, message)?;

    Ok(AbeCipherText {
        access_tree: Box::new(filled_tree),
        c_0,
        c_1,
        arr_c: c_j
            .map(|c| c.clone().unwrap())
            .collect::<Vec<(AbeIdentifier, G1)>>(),
        message,
    })
}

pub fn m_decrypt(cipher_text: &AbeCipherText, secret_key: &AbeMediatorKey) -> Result<Gt, AbeError> {
    let original_set = secret_key
        .arr_d_1
        .iter()
        .map(|(name, _)| AbeAttribute::new(name))
        .collect::<Vec<AbeAttribute>>();

    let minimal_set = cipher_text.access_tree.find_minimal_set(&original_set)?;

    let product = cipher_text
        .arr_c
        .iter()
        .filter(|(identifier, _)| {
            minimal_set.contains(&AbeAttribute::new(identifier.name.as_str()))
        })
        .map(|(identifier, c)| pairing(*c, secret_key.arr_d_1[&identifier.name]))
        .fold(None, |acc, e| match acc {
            None => Some(e),
            Some(acc) => Some(acc * e),
        })
        .ok_or(AbeError::new("Could not calculate product of e(cj,dj)"))?;

    Ok(product)
}

pub fn decrypt(
    cipher_text: &AbeCipherText,
    secret_key: &AbeClientKey,
    mediated_value: &Gt,
) -> Result<AbeDecrypted, AbeError> {
    let original_set = secret_key
        .arr_d_2
        .iter()
        .map(|(name, _)| AbeAttribute::new(name))
        .collect::<Vec<AbeAttribute>>();

    let minimal_set = cipher_text.access_tree.find_minimal_set(&original_set)?;

    let product = cipher_text
        .arr_c
        .iter()
        .filter(|(identifier, _)| {
            minimal_set.contains(&AbeAttribute::new(identifier.name.as_str()))
        })
        .map(|(identifier, c)| pairing(*c, secret_key.arr_d_2[&identifier.name]))
        .fold(None, |acc, e| match acc {
            None => Some(e),
            Some(acc) => Some(acc * e),
        })
        .ok_or(AbeError::new("Could not calculate product of e(cj,dj)"))?;

    let egsga = pairing(cipher_text.c_0, secret_key.d_0) * *mediated_value * product;

    let m_prime = cipher_text.c_1 * egsga.inverse();
    let message_bytes = aes::decrypt_symmetric(m_prime, &cipher_text.message)?;

    Ok(AbeDecrypted {
        secret: m_prime,
        message: message_bytes,
    })
}
