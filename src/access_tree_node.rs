use rand::Rng;
use rabe_bn::Fr;
use crate::access_tree_node::TreeOperator::{Or};

#[derive(Debug, Clone, PartialEq)]
pub enum TreeOperator {
    Or,
}

pub enum AccessTree {
    Operator {
        operator: TreeOperator,
        left: Box<AccessTree>,
        right: Box<AccessTree>,
        value: Option<Fr>,
    },
    Leaf {
        attribute: String,
        value: Option<Fr>,
    },
}

pub trait GetAttributes {
    fn get_attributes(&self) -> Vec<String>;
}

impl GetAttributes for AccessTree {
    fn get_attributes(&self) -> Vec<String> {
        match self {
            AccessTree::Operator { left, right, .. } => {
                let mut left_attributes = left.get_attributes();
                let mut right_attributes = right.get_attributes();
                left_attributes.append(&mut right_attributes);
                left_attributes
            }
            AccessTree::Leaf { attribute, .. } => {
                vec![attribute.clone()]
            }
        }
    }
}

pub trait AssignValues {
    fn assign_values<R: Rng>(&self, s: Fr, s_i: Option<Fr>, rng: &mut R);
}

impl AssignValues for AccessTree {
    fn assign_values<R: Rng>(&self, s: Fr, s_i: Option<Fr>, rng: &mut R) {
        match self {
            AccessTree::Operator { left, right, mut value, operator } => {
                if s_i.is_some() {
                    value = s_i;
                }

                if operator == &Or {
                    left.assign_values(s, None, rng);
                    right.assign_values(s, None, rng);
                }
            }
            AccessTree::Leaf { .. } => {}
        }
    }
}

pub struct EncryptionTree {
    pub node: Box<AccessTree>,
    pub value: Fr,
}