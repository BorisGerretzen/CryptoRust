use std::collections::HashMap;

use rabe_bn::{pairing, Fr, Gt, G1, G2};
use rand::Rng;

use crate::abe_attribute::{AbeAttribute, AbeIdentifier};
use crate::access_tree::{AccessTree, AssignValues, GetAttributes, MinimalSetFinder};
use crate::aes;
use crate::errors::abe_error::AbeError;
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
) -> Result<AbeSecretKey, AbeError> {
    let r = rng.gen();

    // d0 = g2^(alpha-r)
    let d_0 = public_key.g2 * (master_key.alpha - r);

    // dj = g2^(r * tj^-1)
    let arr_d = attributes.iter().map(|a| {
        let clone = a.clone();
        let inverse = master_key.small_t[a].inverse().ok_or(AbeError::new(
            format!("Could not calculate inverse of {}", a).as_str(),
        ));
        match inverse {
            Ok(inverse) => Ok((clone, public_key.g2 * (r * inverse))),
            Err(e) => Err(e),
        }
    });

    // get errors if any
    let errors = arr_d
        .clone()
        .filter(|d| d.is_err())
        .map(|d| d.err().unwrap())
        .collect::<Vec<AbeError>>();

    if errors.len() > 0 {
        let mut error_message = String::from("Could not calculate dj for attributes: ");
        for error in errors {
            error_message.push_str(&format!("{:?}, ", error));
        }
        return Err(AbeError::new(error_message.as_str()));
    }

    Ok(AbeSecretKey {
        d_0,
        arr_d: arr_d.map(|d| d.unwrap()).collect::<HashMap<String, G2>>(),
    })
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
            .collect::<HashMap<AbeIdentifier, G1>>(),
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

    let product = cipher_text
        .arr_c
        .iter()
        .filter(|(identifier, _)| {
            minimal_set.contains(&AbeAttribute::new(identifier.name.as_str()))
        })
        .map(|(identifier, c)| pairing(*c, secret_key.arr_d[&identifier.name]))
        .fold(None, |acc, e| match acc {
            None => Some(e),
            Some(acc) => Some(acc * e),
        })
        .ok_or(AbeError::new("Could not calculate product of e(cj,dj)"))?;

    // e(g,g)^rs = product of e(cj,dj)
    // let p2 = secret_key
    //     .arr_d
    //     .iter()
    //     .filter(|(name, _)| minimal_set.contains(&AbeAttribute::new(name)))
    //     .map(|(name, d)| pairing(cipher_text.arr_c[name], *d))
    //     .fold(None, |acc, e| match acc {
    //         None => Some(e),
    //         Some(acc) => Some(acc * e),
    //     }).ok_or(AbeError::new("Could not calculate product of e(cj,dj)"))?;

    // e(g^s,g^a) = e(c0,d0) * e(g,g)^rs
    let egsga = pairing(cipher_text.c_0, secret_key.d_0) * product;

    // m' = c1 / e(g^s,g^a)
    let m_prime = cipher_text.c_1 * egsga.inverse();

    let message_bytes = aes::decrypt_symmetric(m_prime, &cipher_text.message)?;

    Ok(AbeDecrypted {
        secret: m_prime,
        message: message_bytes,
    })
}
