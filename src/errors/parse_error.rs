use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParseError {
    pub message: String,
    pub position: usize,
}

impl ParseError {
    pub fn new(message: &str, position: usize) -> ParseError {
        ParseError {
            message: message.to_string(),
            position,
        }
    }
}

impl Display for ParseError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ParseError: {} at position {}",
            self.message, self.position
        )
    }
}
