use crate::abe_attribute::AbeAttribute;
use crate::access_tree;
use crate::errors::parse_error::ParseError;

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Variable(String),
    And,
    Or,
    OpenParen,
    CloseParen,
}

#[derive(Debug, PartialEq, Clone)]
pub enum AstNode {
    Variable(String),
    BinaryOp(char, Box<AstNode>, Box<AstNode>),
}

pub struct AccessTreeParser {
    tokens: Vec<Token>,
    current_token: Option<Token>,
    position: usize,
}

impl AccessTreeParser {
    pub fn new(input: &str) -> AccessTreeParser {
        // simple lexer
        let mut tokens = Vec::new();
        let mut accumulator = String::new();

        for c in input.chars() {
            let token = match c {
                '&' => Some(Token::And),
                '|' => Some(Token::Or),
                '(' => Some(Token::OpenParen),
                ')' => Some(Token::CloseParen),
                _ => {
                    accumulator.push(c);
                    None
                }
            };

            if let Some(token) = token {
                if accumulator.len() > 0 {
                    tokens.push(Token::Variable(accumulator.clone()));
                    accumulator.clear();
                }
                tokens.push(token);
            }
        }
        if accumulator.len() > 0 {
            tokens.push(Token::Variable(accumulator.clone()));
        }

        println!("Tokens: {:?}", tokens);
        AccessTreeParser {
            tokens,
            current_token: None,
            position: 0,
        }
    }

    fn advance(&mut self) {
        self.position += 1;
        if self.position <= self.tokens.len() {
            self.current_token = Some(self.tokens[self.position - 1].clone());
        } else {
            self.current_token = None;
        }
    }

    fn parse_variable(&mut self) -> Result<AstNode, ParseError> {
        let node = self.current_token.clone();
        match node {
            Some(Token::Variable(c)) => {
                self.advance();
                Ok(AstNode::Variable(c))
            }
            Some(token) => Err(ParseError::new(
                format!("Invalid token {:?}", token).as_str(),
                self.position,
            )),
            None => Err(ParseError::new(
                "Expected variable but got None",
                self.position,
            )),
        }
    }

    fn parse_factor(&mut self) -> Result<AstNode, ParseError> {
        match self.current_token {
            Some(Token::OpenParen) => {
                self.advance();
                let expr = self.parse_expr();
                if self.current_token == Some(Token::CloseParen) {
                    self.advance();
                }
                expr
            }
            _ => self.parse_variable(),
        }
    }

    fn parse_term(&mut self) -> Result<AstNode, ParseError> {
        let mut left = self.parse_factor()?;
        while let Some(Token::And) = self.current_token {
            self.advance();
            let right = self.parse_factor()?;
            left = AstNode::BinaryOp('&', Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn parse_expr(&mut self) -> Result<AstNode, ParseError> {
        let mut left = self.parse_term()?;
        while let Some(Token::Or) = self.current_token {
            self.advance();
            let right = self.parse_term()?;
            left = AstNode::BinaryOp('|', Box::new(left), Box::new(right));
        }
        Ok(left)
    }

    fn ast_to_access_tree(&self, ast: AstNode) -> Result<access_tree::AccessTree, ParseError> {
        Ok(match ast {
            AstNode::Variable(c) => access_tree::AccessTree::Leaf(access_tree::Leaf {
                attribute: AbeAttribute::new(&c.to_string()),
                value: None,
            }),
            AstNode::BinaryOp(op, left, right) => {
                access_tree::AccessTree::Operator(access_tree::Operator {
                    operator: match op {
                        '|' => access_tree::TreeOperator::Or,
                        '&' => access_tree::TreeOperator::And,
                        _ => {
                            return Err(ParseError::new(
                                format!("Invalid operator '{}'", op).as_str(),
                                self.position,
                            ));
                        }
                    },
                    left: Box::from(self.ast_to_access_tree(*left)?),
                    right: Box::from(self.ast_to_access_tree(*right)?),
                    value: None,
                })
            }
        })
    }

    fn generate_ast(&mut self) -> Result<AstNode, ParseError> {
        self.advance();
        let ast = self.parse_expr()?;

        if self.current_token.is_some() {
            return Err(ParseError::new(
                "Unexpected tokens after parsing was complete",
                self.position,
            ));
        }

        Ok(ast)
    }

    pub fn parse(&mut self) -> Result<access_tree::AccessTree, ParseError> {
        let ast = self.generate_ast()?;
        self.ast_to_access_tree(ast)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_longer_names() {
        let input = "patient|doctor";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(
            result,
            AstNode::BinaryOp(
                '|',
                Box::new(AstNode::Variable(String::from("patient"))),
                Box::new(AstNode::Variable(String::from("doctor"))),
            )
        );
    }

    #[test]
    fn test_parser() {
        let input = "a&b|c";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(
            result,
            AstNode::BinaryOp(
                '|',
                Box::new(AstNode::BinaryOp(
                    '&',
                    Box::new(AstNode::Variable(String::from('a'))),
                    Box::new(AstNode::Variable(String::from('b'))),
                )),
                Box::new(AstNode::Variable(String::from('c'))),
            )
        );
    }

    #[test]
    fn test_parser2() {
        let input = "a&(b|c)";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(
            result,
            AstNode::BinaryOp(
                '&',
                Box::new(AstNode::Variable(String::from('a'))),
                Box::new(AstNode::BinaryOp(
                    '|',
                    Box::new(AstNode::Variable(String::from('b'))),
                    Box::new(AstNode::Variable(String::from('c'))),
                ),),
            )
        );
    }

    #[test]
    fn test_parser_or() {
        let input = "a|b";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(
            result,
            AstNode::BinaryOp(
                '|',
                Box::new(AstNode::Variable(String::from('a'))),
                Box::new(AstNode::Variable(String::from('b'))),
            )
        );
    }

    #[test]
    fn test_parser_and() {
        let input = "a&b";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(
            result,
            AstNode::BinaryOp(
                '&',
                Box::new(AstNode::Variable(String::from('a'))),
                Box::new(AstNode::Variable(String::from('b'))),
            )
        );
    }

    #[test]
    fn test_parser_paren() {
        let input = "(a)";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(result, AstNode::Variable(String::from('a')));
    }

    #[test]
    fn test_parser_paren_and() {
        let input = "(a&b)";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(
            result,
            AstNode::BinaryOp(
                '&',
                Box::new(AstNode::Variable(String::from('a'))),
                Box::new(AstNode::Variable(String::from('b'))),
            )
        );
    }

    #[test]
    fn test_parser_paren_or() {
        let input = "(a|b)";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(
            result,
            AstNode::BinaryOp(
                '|',
                Box::new(AstNode::Variable(String::from('a'))),
                Box::new(AstNode::Variable(String::from('b'))),
            )
        );
    }

    #[test]
    fn test_parser_complex2() {
        let input = "(A|D)&(B|E)&C&A";
        let mut parser = AccessTreeParser::new(input);
        let result = parser.generate_ast().unwrap();

        assert_eq!(
            result,
            AstNode::BinaryOp(
                '&',
                Box::new(AstNode::BinaryOp(
                    '&',
                    Box::new(AstNode::BinaryOp(
                        '&',
                        Box::new(AstNode::BinaryOp(
                            '|',
                            Box::new(AstNode::Variable(String::from('A'))),
                            Box::new(AstNode::Variable(String::from('D'))),
                        )),
                        Box::new(AstNode::BinaryOp(
                            '|',
                            Box::new(AstNode::Variable(String::from('B'))),
                            Box::new(AstNode::Variable(String::from('E'))),
                        )),
                    )),
                    Box::new(AstNode::Variable(String::from('C'))),
                )),
                Box::new(AstNode::Variable(String::from('A')))
            )
        );
    }
}
