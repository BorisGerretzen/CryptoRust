use crate::abe_attribute::AbeAttribute;
use crate::access_tree;
use crate::errors::AbeError;

#[derive(Debug, Clone, PartialEq)]
enum Token {
    Variable(char),
    And,
    Or,
    OpenParen,
    CloseParen,
}

#[derive(Debug, PartialEq, Clone)]
pub enum AstNode {
    Variable(char),
    BinaryOp(char, Box<AstNode>, Box<AstNode>),
}

pub struct Parser {
    tokens: Vec<Token>,
    current_token: Option<Token>,
    position: usize,
}

impl Parser {
    pub fn new(input: &str) -> Parser {
        // simple lexer
        let mut tokens = Vec::new();
        for c in input.chars() {
            match c {
                'a'..='z' | 'A'..='Z' => tokens.push(Token::Variable(c)),
                '&' => tokens.push(Token::And),
                '|' => tokens.push(Token::Or),
                '(' => tokens.push(Token::OpenParen),
                ')' => tokens.push(Token::CloseParen),
                _ => {}
            }
        }

        Parser {
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

    fn parse_variable(&mut self) -> Option<AstNode> {
        match self.current_token {
            Some(Token::Variable(c)) => {
                self.advance();
                Some(AstNode::Variable(c))
            }
            _ => None,
        }
    }

    fn parse_factor(&mut self) -> Option<AstNode> {
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

    fn parse_term(&mut self) -> Option<AstNode> {
        let mut left = self.parse_factor();
        while let Some(Token::And) = self.current_token {
            self.advance();
            let right = self.parse_factor();
            left = Some(AstNode::BinaryOp(
                '&',
                Box::new(left.unwrap()),
                Box::new(right.unwrap()),
            ));
        }
        left
    }

    fn parse_expr(&mut self) -> Option<AstNode> {
        let mut left = self.parse_term();
        while let Some(Token::Or) = self.current_token {
            self.advance();
            let right = self.parse_term();
            left = Some(AstNode::BinaryOp(
                '|',
                Box::new(left.unwrap()),
                Box::new(right.unwrap()),
            ));
        }
        left
    }

    fn ast_to_access_tree(&self, ast: AstNode) -> Result<access_tree::AccessTree, AbeError> {
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
                            return Err(AbeError::new(
                                format!("Invalid operator '{}'", op).as_str(),
                            ))
                        }
                    },
                    left: Box::from(self.ast_to_access_tree(*left)?),
                    right: Box::from(self.ast_to_access_tree(*right)?),
                    value: None,
                })
            }
        })
    }

    pub fn parse(&mut self) -> Result<access_tree::AccessTree, AbeError> {
        self.advance();
        let ast = self.parse_expr();

        if self.current_token.is_some() {
            return Err(AbeError::new("Invalid expression"));
        }

        self.ast_to_access_tree(ast.unwrap())
    }
}

mod tests {
    use super::*;

    #[test]
    fn test_parser() {
        let input = "a&b|c";
        let mut parser = Parser::new(input);
        let result = parser.parse();

        assert_eq!(
            result,
            Some(AstNode::BinaryOp(
                '|',
                Box::new(AstNode::BinaryOp(
                    '&',
                    Box::new(AstNode::Variable('a')),
                    Box::new(AstNode::Variable('b')),
                )),
                Box::new(AstNode::Variable('c')),
            ))
        );
    }

    #[test]
    fn test_parser2() {
        let input = "a&(b|c)";
        let mut parser = Parser::new(input);
        let result = parser.parse();

        assert_eq!(
            result,
            Some(AstNode::BinaryOp(
                '&',
                Box::new(AstNode::Variable('a')),
                Box::new(AstNode::BinaryOp(
                    '|',
                    Box::new(AstNode::Variable('b')),
                    Box::new(AstNode::Variable('c')),
                )),
            ))
        );
    }

    #[test]
    fn test_parser_or() {
        let input = "a|b";
        let mut parser = Parser::new(input);
        let result = parser.parse();

        assert_eq!(
            result,
            Some(AstNode::BinaryOp(
                '|',
                Box::new(AstNode::Variable('a')),
                Box::new(AstNode::Variable('b')),
            ))
        );
    }

    #[test]
    fn test_parser_and() {
        let input = "a&b";
        let mut parser = Parser::new(input);
        let result = parser.parse();

        assert_eq!(
            result,
            Some(AstNode::BinaryOp(
                '&',
                Box::new(AstNode::Variable('a')),
                Box::new(AstNode::Variable('b')),
            ))
        );
    }

    #[test]
    fn test_parser_paren() {
        let input = "(a)";
        let mut parser = Parser::new(input);
        let result = parser.parse();

        assert_eq!(result, Some(AstNode::Variable('a')));
    }

    #[test]
    fn test_parser_paren_and() {
        let input = "(a&b)";
        let mut parser = Parser::new(input);
        let result = parser.parse();

        assert_eq!(
            result,
            Some(AstNode::BinaryOp(
                '&',
                Box::new(AstNode::Variable('a')),
                Box::new(AstNode::Variable('b')),
            ))
        );
    }

    #[test]
    fn test_parser_paren_or() {
        let input = "(a|b)";
        let mut parser = Parser::new(input);
        let result = parser.parse();

        assert_eq!(
            result,
            Some(AstNode::BinaryOp(
                '|',
                Box::new(AstNode::Variable('a')),
                Box::new(AstNode::Variable('b')),
            ))
        );
    }
}
