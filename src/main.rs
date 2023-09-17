mod access_tree_node;

extern crate substrate_bn;
extern crate rand;

use substrate_bn::{Group, Fr, G1, G2, pairing};
use access_tree_node::TreeOperator;
use crate::access_tree_node::TreeNode::Operator;
use crate::access_tree_node::TreeNode::Leaf;

fn main() {
    let rng = &mut rand::thread_rng();
    let g = G1::one();
    let pair = pairing(g, G2::one());

    // Access Tree
    let _tree = Operator {
        operator: TreeOperator::Or,
        left: Box::from(Operator {
            operator: TreeOperator::And,
            left: Box::from(Leaf { attribute: "A".to_string() }),
            right: Box::from(Leaf { attribute: "B".to_string() }),
        }),
        right: Box::from(Operator {
            operator: TreeOperator::And,
            left: Box::from(Leaf { attribute: "C".to_string() }),
            right: Box::from(Leaf { attribute: "D".to_string() }),
        }),
    };

    // SETUP
    // Create a vector containing 3 strings
    let attributes = vec!["A", "B", "C", "D"];
    let _n_attributes = attributes.len();

    let mut small_t = Vec::new();
    for _ in 0..attributes.len() {
        small_t.push(Fr::random(rng));
    }

    // Generate alpha
    let alpha = Fr::random(rng);

    // e(g,g)^alpha
    let _y = pair.pow(alpha);

    let mut big_t = Vec::new();
    for i in 0..attributes.len() {
        big_t.push(g * small_t[i]);
    }

    // KEYGEN
    let r = Fr::random(rng);

    // d_j = g * (r * (t_j)^-1)
    let _d_0 = g * (alpha - r);
    let mut arr_d = Vec::new();
    for i in 0..attributes.len() {
        arr_d.push(g * (r * (small_t[i].inverse().unwrap())));
    }

    // ENCRYPT
    let m = Fr::random(rng);

    let s = Fr::random(rng);
    let _c = g * s;
    let _c_1 = pair.pow(alpha * s).pow(m);
}