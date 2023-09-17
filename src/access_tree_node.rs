pub enum TreeNode {
    Operator {
        operator: TreeOperator,
        left: Box<TreeNode>,
        right: Box<TreeNode>,
    },
    Leaf {
        attribute: String
    },
}

pub trait GetAttributes {
    fn get_attributes(&self) -> Vec<String>;
}

impl GetAttributes for TreeNode {
    fn get_attributes(&self) -> Vec<String> {
        match self {
            TreeNode::Operator { left, right, .. } => {
                let mut left_attributes = left.get_attributes();
                let mut right_attributes = right.get_attributes();
                left_attributes.append(&mut right_attributes);
                left_attributes
            }
            TreeNode::Leaf { attribute } => {
                vec![attribute.clone()]
            }
        }
    }
}

pub enum TreeOperator {
    And,
    Or,
}