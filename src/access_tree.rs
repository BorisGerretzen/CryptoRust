use itertools::Itertools;
use rand::Rng;
use rabe_bn::Fr;
use crate::abe_attribute::AbeAttribute;
use crate::access_tree::TreeOperator::{And, Or};
use crate::errors::AbeError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TreeOperator {
    Or,
    And,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AccessTree {
    Operator {
        operator: TreeOperator,
        left: Box<AccessTree>,
        right: Box<AccessTree>,
        value: Option<Fr>,
    },
    Leaf {
        attribute: AbeAttribute,
        value: Option<Fr>,
    },
}

pub trait GetAttributes {
    /// Returns a vector of all attributes in the tree
    fn get_attributes(&self) -> Vec<AbeAttribute>;
}

impl GetAttributes for AccessTree {
    fn get_attributes(&self) -> Vec<AbeAttribute> {
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
    /// Assigns values to the tree according to the encryption scheme
    fn assign_values<R: Rng + ?Sized>(&self, s: Fr, s_i: Option<Fr>, rng: &mut R) -> AccessTree;
}

impl AssignValues for AccessTree {
    fn assign_values<R: Rng + ?Sized>(&self, s: Fr, to_set: Option<Fr>, rng: &mut R) -> AccessTree {
        match self {
            AccessTree::Operator { left, right, operator, .. } => {
                let mut set_left = None;
                let mut set_right = None;

                if operator == &Or {
                    set_left = Some(s);
                    set_right = Some(s);
                }

                if operator == &And {
                    let s_i1 = rng.gen();
                    let s_i2 = s - s_i1;

                    set_left = Some(s_i1);
                    set_right = Some(s_i2);
                }

                AccessTree::Operator {
                    value: to_set,
                    operator: operator.clone(),
                    left: Box::from(left.assign_values(s, set_left, rng)),
                    right: Box::from(right.assign_values(s, set_right, rng)),
                }
            }
            AccessTree::Leaf { attribute, .. } => {
                AccessTree::Leaf {
                    value: to_set,
                    attribute: AbeAttribute {
                        name: attribute.name.clone(),
                        value: to_set,
                    },
                }
            }
        }
    }
}

pub trait MinimalSetFinder {
    /// Checks if the given set of attributes satisfies the tree
    fn is_satisfiable(&self, attributes: &Vec<AbeAttribute>) -> bool;

    /// Finds the minimal set of attributes that satisfies the tree, starting from the given set
    fn find_minimal_set(&self, attributes: &Vec<AbeAttribute>) -> Result<Vec<AbeAttribute>, AbeError>;
}

impl MinimalSetFinder for AccessTree {
    fn is_satisfiable(&self, attributes: &Vec<AbeAttribute>) -> bool {
        match self {
            AccessTree::Operator { operator, left, right, .. } => match operator {
                And => {
                    left.is_satisfiable(attributes) && right.is_satisfiable(attributes)
                }
                Or => {
                    left.is_satisfiable(attributes) || right.is_satisfiable(attributes)
                }
            },
            AccessTree::Leaf { attribute, .. } => attributes.contains(&attribute),
        }
    }

    fn find_minimal_set(&self, attributes: &Vec<AbeAttribute>) -> Result<Vec<AbeAttribute>, AbeError> {
        // If initial set does not satisfy we immediately return
        if !self.is_satisfiable(attributes) {
            return Err(AbeError::new("Initial attribute set does not satisfy the tree"));
        }

        // Find all combinations of attributes
        let combinations: Vec<Vec<AbeAttribute>> = (1..attributes.len()).flat_map(|i| attributes.iter().cloned().combinations(i)).collect();
        for combination in combinations {
            if self.is_satisfiable(&combination) {
                return Ok(combination);
            }
        }

        return Ok(attributes.clone());
    }

}

#[cfg(test)]
mod tests {
    use crate::abe_attribute::AbeAttribute;
    use crate::access_tree::{AccessTree, MinimalSetFinder};
    use crate::access_tree::TreeOperator::{And, Or};
    use crate::errors::AbeError;

    #[test]
    fn test_access_tree_equality() {
        let a = AccessTree::Leaf {
            value: Some(rabe_bn::Fr::one()),
            attribute: AbeAttribute {
                name: "A".to_string(),
                value: Some(rabe_bn::Fr::one()),
            },
        };
        let b = AccessTree::Leaf {
            value: Some(rabe_bn::Fr::one()),
            attribute: AbeAttribute {
                name: "B".to_string(),
                value: Some(rabe_bn::Fr::one()),
            },
        };
        let c = AccessTree::Leaf {
            value: Some(rabe_bn::Fr::one()),
            attribute: AbeAttribute {
                name: "A".to_string(),
                value: Some(rabe_bn::Fr::one()),
            },
        };

        assert_eq!(a, c);
        assert_ne!(a, b);
    }

    #[test]
    fn test_access_tree_is_satisfiable_or() {
        let tree = AccessTree::Operator {
            left: Box::from(AccessTree::Leaf {
                value: None,
                attribute: AbeAttribute {
                    name: "A".to_string(),
                    value: Some(rabe_bn::Fr::one()),
                },
            }),
            right: Box::from(AccessTree::Leaf {
                value: None,
                attribute: AbeAttribute {
                    name: "B".to_string(),
                    value: Some(rabe_bn::Fr::one()),
                },
            }),
            value: None,
            operator: Or
        };

        assert_eq!(tree.is_satisfiable(&vec![AbeAttribute::new("A")]), true);
        assert_eq!(tree.is_satisfiable(&vec![AbeAttribute::new("B")]), true);
        assert_eq!(tree.is_satisfiable(&vec![AbeAttribute::new("C")]), false);
    }

    #[test]
    fn test_access_tree_is_satisfiable_and() {
        let tree = AccessTree::Operator {
            left: Box::from(AccessTree::Leaf {
                value: None,
                attribute: AbeAttribute {
                    name: "A".to_string(),
                    value: Some(rabe_bn::Fr::one()),
                },
            }),
            right: Box::from(AccessTree::Leaf {
                value: None,
                attribute: AbeAttribute {
                    name: "B".to_string(),
                    value: Some(rabe_bn::Fr::one()),
                },
            }),
            value: None,
            operator: And
        };

        assert_eq!(tree.is_satisfiable(&vec![AbeAttribute::new("A")]), false);
        assert_eq!(tree.is_satisfiable(&vec![AbeAttribute::new("B")]), false);
        assert_eq!(tree.is_satisfiable(&vec![AbeAttribute::new("C")]), false);
        assert_eq!(tree.is_satisfiable(&vec![AbeAttribute::new("A"), AbeAttribute::new("B")]), true);
    }

    #[test]
    fn test_access_tree_find_minimal_set_or() {
        let tree = AccessTree::Operator {
            left: Box::from(AccessTree::Leaf {
                value: None,
                attribute: AbeAttribute {
                    name: "A".to_string(),
                    value: Some(rabe_bn::Fr::one()),
                },
            }),
            right: Box::from(AccessTree::Leaf {
                value: None,
                attribute: AbeAttribute {
                    name: "B".to_string(),
                    value: Some(rabe_bn::Fr::one()),
                },
            }),
            value: None,
            operator: Or
        };

        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A")]).unwrap(), vec![AbeAttribute::new("A")]);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("B")]).unwrap(), vec![AbeAttribute::new("B")]);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("C")]).unwrap_err(), AbeError::new("Initial attribute set does not satisfy the tree"));
    }

    #[test]
    fn test_access_tree_find_minimal_set_and() {
        let tree = AccessTree::Operator {
            left: Box::from(AccessTree::Leaf {
                value: None,
                attribute: AbeAttribute {
                    name: "A".to_string(),
                    value: Some(rabe_bn::Fr::one()),
                },
            }),
            right: Box::from(AccessTree::Leaf {
                value: None,
                attribute: AbeAttribute {
                    name: "B".to_string(),
                    value: Some(rabe_bn::Fr::one()),
                },
            }),
            value: None,
            operator: And
        };

        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A")]).unwrap_err(), AbeError::new("Initial attribute set does not satisfy the tree"));
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("B")]).unwrap_err(), AbeError::new("Initial attribute set does not satisfy the tree"));
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("C")]).unwrap_err(), AbeError::new("Initial attribute set does not satisfy the tree"));
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A"), AbeAttribute::new("B")]).unwrap(), vec![AbeAttribute::new("A"), AbeAttribute::new("B")]);
    }

    #[test]
    fn test_access_tree_find_minimal_set_complex() {
        let tree = AccessTree::Operator {
            left: Box::from(AccessTree::Operator  {
                left: Box::from(AccessTree::Leaf {
                    value: None,
                    attribute: AbeAttribute {
                        name: "A".to_string(),
                        value: Some(rabe_bn::Fr::one()),
                    },
                }),
                right: Box::from(AccessTree::Leaf {
                    value: None,
                    attribute: AbeAttribute {
                        name: "B".to_string(),
                        value: Some(rabe_bn::Fr::one()),
                    },
                }),
                value: None,
                operator: And
            }),
            right: Box::from(AccessTree::Operator {
                left: Box::from(AccessTree::Leaf {
                    value: None,
                    attribute: AbeAttribute {
                        name: "C".to_string(),
                        value: Some(rabe_bn::Fr::one()),
                    },
                }),
                right: Box::from(AccessTree::Leaf {
                    value: None,
                    attribute: AbeAttribute {
                        name: "D".to_string(),
                        value: Some(rabe_bn::Fr::one()),
                    },
                }),
                value: None,
                operator: And
            }),
            value: None,
            operator: Or
        };

        let abe_error = AbeError::new("Initial attribute set does not satisfy the tree");

        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A")]).unwrap_err(), abe_error);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("B")]).unwrap_err(), abe_error);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("C")]).unwrap_err(), abe_error);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("D")]).unwrap_err(), abe_error);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A"), AbeAttribute::new("B")]).unwrap(), vec![AbeAttribute::new("A"), AbeAttribute::new("B")]);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A"), AbeAttribute::new("C")]).unwrap_err(), abe_error);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A"), AbeAttribute::new("D")]).unwrap_err(), abe_error);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("B"), AbeAttribute::new("C")]).unwrap_err(), abe_error);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("B"), AbeAttribute::new("D")]).unwrap_err(), abe_error);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("C"), AbeAttribute::new("D")]).unwrap(), vec![AbeAttribute::new("C"), AbeAttribute::new("D")]);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A"), AbeAttribute::new("B"), AbeAttribute::new("C")]).unwrap(), vec![AbeAttribute::new("A"), AbeAttribute::new("B")]);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A"), AbeAttribute::new("B"), AbeAttribute::new("D")]).unwrap(), vec![AbeAttribute::new("A"), AbeAttribute::new("B")]);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A"), AbeAttribute::new("C"), AbeAttribute::new("D")]).unwrap(), vec![AbeAttribute::new("C"), AbeAttribute::new("D")]);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("B"), AbeAttribute::new("C"), AbeAttribute::new("D")]).unwrap(), vec![AbeAttribute::new("C"), AbeAttribute::new("D")]);
        assert_eq!(tree.find_minimal_set(&vec![AbeAttribute::new("A"), AbeAttribute::new("B"), AbeAttribute::new("C"), AbeAttribute::new("D")]).unwrap(), vec![AbeAttribute::new("A"), AbeAttribute::new("B")]);
    }
}