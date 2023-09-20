use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbeAttribute {
    pub name: String,
    pub value: Option<rabe_bn::Fr>,
}
impl AbeAttribute {
    pub fn new(name: &str) -> AbeAttribute {
        AbeAttribute {
            name: name.to_string(),
            value: None,
        }
    }
}

impl PartialEq for AbeAttribute {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_abe_attribute_equality() {
        let a = crate::abe_attribute::AbeAttribute {
            value: Some(rabe_bn::Fr::one()),
            name: "A".to_string(),
        };
        let b = crate::abe_attribute::AbeAttribute::new("B");
        let c = crate::abe_attribute::AbeAttribute::new("A");

        assert_eq!(a, c);
        assert_ne!(a, b);
    }
}
