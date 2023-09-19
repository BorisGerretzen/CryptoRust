use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AbeError{
    pub message: String,
}
impl AbeError {
    pub fn new(message: &str) -> AbeError {
        AbeError {
            message: message.to_string()
        }
    }
}

impl Display for AbeError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "SymmetricEncryptionError: {}", self.message)
    }
}