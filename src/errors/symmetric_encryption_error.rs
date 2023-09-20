use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SymmetricEncryptionError {
    pub message: String,
}

impl SymmetricEncryptionError {
    pub fn new(message: &str) -> SymmetricEncryptionError {
        SymmetricEncryptionError {
            message: message.to_string(),
        }
    }
}

impl Display for SymmetricEncryptionError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricEncryptionError: {}", self.message)
    }
}
