use std::fmt::{Display, Formatter};

use crate::errors::parse_error::ParseError;
use crate::errors::symmetric_encryption_error::SymmetricEncryptionError;

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AbeError {
    pub message: String,
}

impl AbeError {
    pub fn new(message: &str) -> AbeError {
        AbeError {
            message: message.to_string(),
        }
    }
}

impl Display for AbeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Encryption error: {}", self.message)
    }
}

impl From<SymmetricEncryptionError> for AbeError {
    fn from(value: SymmetricEncryptionError) -> Self {
        AbeError::new(&format!("Symmetric encryption error: {}", value))
    }
}

impl From<ParseError> for AbeError {
    fn from(value: ParseError) -> Self {
        AbeError::new(&format!("Parse error: {}", value))
    }
}
