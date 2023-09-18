mod access_tree_node;

extern crate rabe_bn;
extern crate rand;

use std::ops::Mul;
use rand::Rng;
use rabe_bn::{Group, Fr, G1, G2, pairing, Gt};
use rabe_bn::arith::U256;
use access_tree_node::TreeOperator;
use crate::access_tree_node::{GetAttributes};
use crate::access_tree_node::AccessTree::Operator;
use crate::access_tree_node::AccessTree::Leaf;

fn main() {
    let rng = &mut rand::thread_rng();

    let g:G1 = rng.gen();
    let g2:G2 = rng.gen();


    let tree = Operator {
        operator: TreeOperator::Or,
        left: Box::from(Operator {
            operator: TreeOperator::Or,
            left: Box::from(Leaf { attribute: "A".to_string(), value: None }),
            right: Box::from(Leaf { attribute: "B".to_string(), value: None }),
            value: None
        }),
        right: Box::from(Operator {
            operator: TreeOperator::Or,
            left: Box::from(Leaf { attribute: "C".to_string(), value:None }),
            right: Box::from(Leaf { attribute: "D".to_string(), value:None }),
            value: None,
        }),
        value: None,
    };

    // SETUP
    // Create a vector containing 3 strings
    let attributes = vec!["A", "B", "C", "D"];

    let mut small_t:Vec<Fr> = Vec::new();
    for _ in 0..attributes.len() {
        small_t.push(rng.gen());
    }

    let alpha:Fr = rng.gen();
    let pair = pairing(g, g2);
    let y = pair.pow(alpha);

    let mut big_t = Vec::new();
    for i in 0..attributes.len() {
        big_t.push(g * small_t[i]);
    }

    // KEYGEN
    let my_attributes = vec!["A"];
    let r = rng.gen();
    let d_0 = g2 * (alpha - r);

    let mut arr_d = Vec::new();
    for i in 0..my_attributes.len() {
        arr_d.push(g2 * (r * small_t[i].inverse().unwrap()));
    }


    // ENCRYPT
    let m:Gt = rng.gen();
    let s = rng.gen();
    let c_0 = g * s;
    let c_1 = m * y.pow(s);
    let c_j = tree.get_attributes().iter().enumerate().map(|x| g * (small_t[x.0] * s)).collect::<Vec<G1>>();

    // DECRYPT
    let mut product= None;
    for i in 0..my_attributes.len() {
        if product == None {
            product = Some(pairing(c_j[i], arr_d[i]));
        }
        else {
            product = Some(product.unwrap() * pairing(c_j[i], arr_d[i]));
        }
    }

    let _egsga = pairing(c_0, d_0) * product.unwrap();
    let _m_prime = c_1 * _egsga.inverse();


    // assert that m and _m_prime are equal
    assert_eq!(m, _m_prime);
}