use std::collections::HashMap;

use rabe_bn::{Fr, Gt, G1, G2};
use serde::{Deserialize, Serialize};

use crate::access_tree::AccessTree;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbePublicKey {
    pub map: Gt,
    pub g1: G1,
    pub g2: G2,
    pub y: Gt,
    pub big_t: HashMap<String, G1>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbeMasterKey {
    pub alpha: Fr,
    pub small_t: HashMap<String, Fr>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbeSecretKey {
    pub d_0: G2,
    pub arr_d: HashMap<String, G2>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AbeCipherText {
    pub access_tree: Box<AccessTree>,
    pub c_0: G1,
    pub c_1: Gt,
    pub arr_c: HashMap<String, G1>,
    pub message: Vec<u8>,
}

pub struct AbeDecrypted {
    pub message: Vec<u8>,
    pub secret: Gt,
}
