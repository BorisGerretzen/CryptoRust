mod access_tree_node;

extern crate bn;
extern crate rand;

use bn::{Group, Fr, G1, G2, pairing};
use access_tree_node::{TreeOperator, TreeNode};
use crate::access_tree_node::TreeNode::Operator;

fn main() {
    let rng = &mut rand::thread_rng();
    let g = G1::one();
    let pair = pairing(g, G2::one());

    // Access Tree
    let tree = Operator {
        operator: TreeOperator::Or,
        left: Box::from(Operator {
            operator: TreeOperator::And,
            left: Box::from(TreeNode::Leaf { attribute: "A".to_string() }),
            right: Box::from(TreeNode::Leaf { attribute: "B".to_string() }),
        }),
        right: Box::from(Operator {
            operator: TreeOperator::And,
            left: Box::from(TreeNode::Leaf { attribute: "C".to_string() }),
            right: Box::from(TreeNode::Leaf { attribute: "D".to_string() }),
        }),
    };

    // SETUP
    // Create a vector containing 3 strings
    let attributes = vec!["A", "B", "C", "D"];
    let n_attributes = attributes.len();

    let mut arr_t = Vec::new();
    for _ in 0..attributes.len() {
        arr_t.push(Fr::random(rng));
    }

    // Generate alpha
    let alpha = Fr::random(rng);

    // e(g,g)^alpha
    let y = pair.pow(alpha);

    let mut arr_T = Vec::new();
    for i in 0..attributes.len() {
        arr_T.push(g * arr_t[i]);
    }

    // KEYGEN
    let r = Fr::random(rng);

    // d_j = g * (r * (t_j)^-1)
    let d_0 = g * (alpha - r);
    let mut arr_d = Vec::new();
    for i in 0..attributes.len() {
        arr_d.push(g * (r * (arr_t[i].inverse().unwrap())));
    }

    // ENCRYPT
    let m = Fr::random(rng);

    let s = Fr::random(rng);
    let c = g * s;
    let c_1 = pair.pow(alpha * s).pow(m);
}