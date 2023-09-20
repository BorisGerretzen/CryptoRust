use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AbeIdentifier {
    pub index: Option<usize>,
    pub name: String,
}

impl From<AbeAttribute> for AbeIdentifier {
    fn from(value: AbeAttribute) -> Self {
        AbeIdentifier {
            index: value.index,
            name: value.name,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AbeAttribute {
    pub index: Option<usize>,
    pub name: String,
    pub value: Option<rabe_bn::Fr>,
}

impl AbeAttribute {
    pub fn new(name: &str) -> AbeAttribute {
        AbeAttribute {
            index: None,
            name: name.to_string(),
            value: None,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_value(name: &str, value: rabe_bn::Fr) -> AbeAttribute {
        AbeAttribute {
            index: None,
            name: name.to_string(),
            value: Some(value),
        }
    }
}

impl PartialEq for AbeAttribute {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.index == other.index
    }
}

impl PartialEq<AbeIdentifier> for AbeAttribute {
    fn eq(&self, other: &AbeIdentifier) -> bool {
        self.name == other.name && self.index == other.index
    }

    fn ne(&self, other: &AbeIdentifier) -> bool {
        !self.eq(other)
    }
}

impl PartialEq<AbeAttribute> for AbeIdentifier {
    fn eq(&self, other: &AbeAttribute) -> bool {
        self.name == other.name && self.index == other.index
    }

    fn ne(&self, other: &AbeAttribute) -> bool {
        !self.eq(other)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_abe_attribute_equality() {
        let a = crate::abe_attribute::AbeAttribute {
            index: None,
            value: Some(rabe_bn::Fr::one()),
            name: "A".to_string(),
        };
        let b = crate::abe_attribute::AbeAttribute::new("B");
        let c = crate::abe_attribute::AbeAttribute::new("A");

        assert_eq!(a, c);
        assert_ne!(a, b);
    }

    #[test]
    fn test_identifier_attribute_equality() {
        let a = crate::abe_attribute::AbeIdentifier {
            index: Some(1),
            name: "A".to_string(),
        };
        let b = crate::abe_attribute::AbeAttribute {
            index: Some(1),
            name: "A".to_string(),
            value: None,
        };

        assert_eq!(a, b);
    }
}
