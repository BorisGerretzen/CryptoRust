use std::collections::HashMap;
use rabe_bn::{Fr, G1, G2, Gt};
use crate::access_tree::AccessTree;

#[derive(Debug, Clone, PartialEq)]
pub struct AbePublicKey {
    pub map: Gt,
    pub g1: G1,
    pub g2: G2,
    pub y: Gt,
    pub big_t: HashMap<String, G1>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AbeMasterKey {
    pub alpha: Fr,
    pub small_t: HashMap<String, Fr>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AbeSecretKey {
    pub d_0: G2,
    pub arr_d: HashMap<String, G2>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct AbeCipherText {
    pub access_tree: Box<AccessTree>,
    pub c_0: G1,
    pub c_1: Gt,
    pub arr_c: HashMap<String, G1>,
}