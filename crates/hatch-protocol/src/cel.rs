use std::collections::BTreeMap;
use std::fmt;

use regex::Regex;
use serde_json::Value;

#[derive(Debug, thiserror::Error)]
pub enum CelError {
    #[error("parse: {0}")]
    Parse(String),
    #[error("runtime: {0}")]
    Runtime(String),
    #[error("regex: {0}")]
    Regex(#[from] regex::Error),
}

#[derive(Debug, Clone)]
pub enum CelValue {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<CelValue>),
    Map(BTreeMap<String, CelValue>),
}

impl CelValue {
    pub fn from_json(v: &Value) -> Self {
        match v {
            Value::Null => CelValue::Null,
            Value::Bool(b) => CelValue::Bool(*b),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    CelValue::Int(i)
                } else {
                    CelValue::Float(n.as_f64().unwrap_or(0.0))
                }
            }
            Value::String(s) => CelValue::Str(s.clone()),
            Value::Array(a) => CelValue::List(a.iter().map(CelValue::from_json).collect()),
            Value::Object(o) => {
                let mut m = BTreeMap::new();
                for (k, v) in o {
                    m.insert(k.clone(), CelValue::from_json(v));
                }
                CelValue::Map(m)
            }
        }
    }

    pub fn truthy(&self) -> bool {
        match self {
            CelValue::Null => false,
            CelValue::Bool(b) => *b,
            CelValue::Int(i) => *i != 0,
            CelValue::Float(f) => *f != 0.0,
            CelValue::Str(s) => !s.is_empty(),
            CelValue::List(l) => !l.is_empty(),
            CelValue::Map(m) => !m.is_empty(),
        }
    }

    pub fn type_name(&self) -> &'static str {
        match self {
            CelValue::Null => "null",
            CelValue::Bool(_) => "bool",
            CelValue::Int(_) => "int",
            CelValue::Float(_) => "float",
            CelValue::Str(_) => "string",
            CelValue::List(_) => "list",
            CelValue::Map(_) => "map",
        }
    }
}

impl fmt::Display for CelValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CelValue::Null => write!(f, "null"),
            CelValue::Bool(b) => write!(f, "{b}"),
            CelValue::Int(i) => write!(f, "{i}"),
            CelValue::Float(x) => write!(f, "{x}"),
            CelValue::Str(s) => write!(f, "\"{s}\""),
            CelValue::List(l) => {
                write!(f, "[")?;
                for (i, v) in l.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{v}")?;
                }
                write!(f, "]")
            }
            CelValue::Map(m) => {
                write!(f, "{{")?;
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{k}: {v}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

pub struct Context {
    pub vars: BTreeMap<String, CelValue>,
}

impl Context {
    pub fn new() -> Self {
        Self {
            vars: BTreeMap::new(),
        }
    }

    pub fn with_tool_call(tool: &str, args: &Value, server: &str, caller: &str) -> Self {
        let mut vars = BTreeMap::new();
        vars.insert("tool".into(), CelValue::Str(tool.into()));
        vars.insert("args".into(), CelValue::from_json(args));
        vars.insert("server".into(), CelValue::Str(server.into()));
        vars.insert("caller".into(), CelValue::Str(caller.into()));
        Self { vars }
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug, Clone)]
enum Tok {
    Ident(String),
    Str(String),
    Int(i64),
    Float(f64),
    LParen,
    RParen,
    LBrack,
    RBrack,
    Dot,
    Comma,
    Bang,
    AmpAmp,
    PipePipe,
    EqEq,
    NotEq,
    Lt,
    Le,
    Gt,
    Ge,
    Plus,
    Minus,
    Star,
    Slash,
    Percent,
    True,
    False,
    Null,
    In,
}

fn tokenize(src: &str) -> Result<Vec<Tok>, CelError> {
    let bytes = src.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            '[' => {
                out.push(Tok::LBrack);
                i += 1;
            }
            ']' => {
                out.push(Tok::RBrack);
                i += 1;
            }
            '.' => {
                out.push(Tok::Dot);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '+' => {
                out.push(Tok::Plus);
                i += 1;
            }
            '-' => {
                out.push(Tok::Minus);
                i += 1;
            }
            '*' => {
                out.push(Tok::Star);
                i += 1;
            }
            '/' => {
                out.push(Tok::Slash);
                i += 1;
            }
            '%' => {
                out.push(Tok::Percent);
                i += 1;
            }
            '!' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(Tok::NotEq);
                    i += 2;
                } else {
                    out.push(Tok::Bang);
                    i += 1;
                }
            }
            '=' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(Tok::EqEq);
                    i += 2;
                } else {
                    return Err(CelError::Parse(format!("unexpected '=' at {i}")));
                }
            }
            '<' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(Tok::Le);
                    i += 2;
                } else {
                    out.push(Tok::Lt);
                    i += 1;
                }
            }
            '>' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'=' {
                    out.push(Tok::Ge);
                    i += 2;
                } else {
                    out.push(Tok::Gt);
                    i += 1;
                }
            }
            '&' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'&' {
                    out.push(Tok::AmpAmp);
                    i += 2;
                } else {
                    return Err(CelError::Parse(format!("unexpected '&' at {i}")));
                }
            }
            '|' => {
                if i + 1 < bytes.len() && bytes[i + 1] == b'|' {
                    out.push(Tok::PipePipe);
                    i += 2;
                } else {
                    return Err(CelError::Parse(format!("unexpected '|' at {i}")));
                }
            }
            '\'' | '"' => {
                let quote = c;
                let start = i + 1;
                let mut end = start;
                let mut escaped = false;
                while end < bytes.len() {
                    let b = bytes[end] as char;
                    if escaped {
                        escaped = false;
                        end += 1;
                        continue;
                    }
                    if b == '\\' {
                        escaped = true;
                        end += 1;
                        continue;
                    }
                    if b == quote {
                        break;
                    }
                    end += 1;
                }
                if end == bytes.len() {
                    return Err(CelError::Parse("unterminated string".into()));
                }
                let raw = &src[start..end];
                let mut s = String::with_capacity(raw.len());
                let mut esc = false;
                for ch in raw.chars() {
                    if esc {
                        s.push(match ch {
                            'n' => '\n',
                            't' => '\t',
                            'r' => '\r',
                            '\\' => '\\',
                            '\'' => '\'',
                            '"' => '"',
                            other => other,
                        });
                        esc = false;
                    } else if ch == '\\' {
                        esc = true;
                    } else {
                        s.push(ch);
                    }
                }
                out.push(Tok::Str(s));
                i = end + 1;
            }
            d if d.is_ascii_digit() => {
                let mut end = i;
                let mut is_float = false;
                while end < bytes.len() && (bytes[end].is_ascii_digit() || bytes[end] == b'.') {
                    if bytes[end] == b'.' {
                        if is_float {
                            break;
                        }
                        is_float = true;
                    }
                    end += 1;
                }
                let slice = &src[i..end];
                if is_float {
                    out.push(Tok::Float(slice.parse().map_err(
                        |e: std::num::ParseFloatError| CelError::Parse(e.to_string()),
                    )?));
                } else {
                    out.push(Tok::Int(slice.parse().map_err(
                        |e: std::num::ParseIntError| CelError::Parse(e.to_string()),
                    )?));
                }
                i = end;
            }
            a if a.is_ascii_alphabetic() || a == '_' => {
                let mut end = i;
                while end < bytes.len()
                    && (bytes[end].is_ascii_alphanumeric() || bytes[end] == b'_')
                {
                    end += 1;
                }
                let word = &src[i..end];
                match word {
                    "true" => out.push(Tok::True),
                    "false" => out.push(Tok::False),
                    "null" => out.push(Tok::Null),
                    "in" => out.push(Tok::In),
                    other => out.push(Tok::Ident(other.to_string())),
                }
                i = end;
            }
            other => return Err(CelError::Parse(format!("unexpected '{other}' at {i}"))),
        }
    }
    Ok(out)
}

#[derive(Debug, Clone)]
enum Node {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    List(Vec<Node>),
    Ident(String),
    Field(Box<Node>, String),
    Index(Box<Node>, Box<Node>),
    MethodCall(Box<Node>, String, Vec<Node>),
    FreeCall(String, Vec<Node>),
    Neg(Box<Node>),
    Not(Box<Node>),
    Bin(BinOp, Box<Node>, Box<Node>),
    In(Box<Node>, Box<Node>),
}

#[derive(Debug, Clone, Copy)]
enum BinOp {
    And,
    Or,
    Eq,
    Ne,
    Lt,
    Le,
    Gt,
    Ge,
    Add,
    Sub,
    Mul,
    Div,
    Mod,
}

#[derive(Debug, Clone)]
pub struct Program {
    root: Node,
}

impl Program {
    pub fn compile(src: &str) -> Result<Self, CelError> {
        let toks = tokenize(src)?;
        let mut p = Parser { toks, pos: 0 };
        let root = p.parse_or()?;
        if p.pos != p.toks.len() {
            return Err(CelError::Parse(format!(
                "unexpected trailing tokens at {}",
                p.pos
            )));
        }
        Ok(Program { root })
    }

    pub fn run(&self, ctx: &Context) -> Result<CelValue, CelError> {
        run_node(&self.root, ctx)
    }

    pub fn run_bool(&self, ctx: &Context) -> Result<bool, CelError> {
        Ok(self.run(ctx)?.truthy())
    }
}

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }

    fn bump(&mut self) -> Option<Tok> {
        let t = self.toks.get(self.pos).cloned();
        self.pos += 1;
        t
    }

    fn parse_or(&mut self) -> Result<Node, CelError> {
        let mut lhs = self.parse_and()?;
        while matches!(self.peek(), Some(Tok::PipePipe)) {
            self.pos += 1;
            let rhs = self.parse_and()?;
            lhs = Node::Bin(BinOp::Or, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_and(&mut self) -> Result<Node, CelError> {
        let mut lhs = self.parse_eq()?;
        while matches!(self.peek(), Some(Tok::AmpAmp)) {
            self.pos += 1;
            let rhs = self.parse_eq()?;
            lhs = Node::Bin(BinOp::And, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_eq(&mut self) -> Result<Node, CelError> {
        let mut lhs = self.parse_rel()?;
        loop {
            match self.peek() {
                Some(Tok::EqEq) => {
                    self.pos += 1;
                    let rhs = self.parse_rel()?;
                    lhs = Node::Bin(BinOp::Eq, Box::new(lhs), Box::new(rhs));
                }
                Some(Tok::NotEq) => {
                    self.pos += 1;
                    let rhs = self.parse_rel()?;
                    lhs = Node::Bin(BinOp::Ne, Box::new(lhs), Box::new(rhs));
                }
                Some(Tok::In) => {
                    self.pos += 1;
                    let rhs = self.parse_rel()?;
                    lhs = Node::In(Box::new(lhs), Box::new(rhs));
                }
                _ => break,
            }
        }
        Ok(lhs)
    }

    fn parse_rel(&mut self) -> Result<Node, CelError> {
        let mut lhs = self.parse_add()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Lt) => BinOp::Lt,
                Some(Tok::Le) => BinOp::Le,
                Some(Tok::Gt) => BinOp::Gt,
                Some(Tok::Ge) => BinOp::Ge,
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_add()?;
            lhs = Node::Bin(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_add(&mut self) -> Result<Node, CelError> {
        let mut lhs = self.parse_mul()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Plus) => BinOp::Add,
                Some(Tok::Minus) => BinOp::Sub,
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_mul()?;
            lhs = Node::Bin(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_mul(&mut self) -> Result<Node, CelError> {
        let mut lhs = self.parse_unary()?;
        loop {
            let op = match self.peek() {
                Some(Tok::Star) => BinOp::Mul,
                Some(Tok::Slash) => BinOp::Div,
                Some(Tok::Percent) => BinOp::Mod,
                _ => break,
            };
            self.pos += 1;
            let rhs = self.parse_unary()?;
            lhs = Node::Bin(op, Box::new(lhs), Box::new(rhs));
        }
        Ok(lhs)
    }

    fn parse_unary(&mut self) -> Result<Node, CelError> {
        match self.peek() {
            Some(Tok::Bang) => {
                self.pos += 1;
                Ok(Node::Not(Box::new(self.parse_unary()?)))
            }
            Some(Tok::Minus) => {
                self.pos += 1;
                Ok(Node::Neg(Box::new(self.parse_unary()?)))
            }
            _ => self.parse_postfix(),
        }
    }

    fn parse_postfix(&mut self) -> Result<Node, CelError> {
        let mut e = self.parse_primary()?;
        loop {
            match self.peek() {
                Some(Tok::Dot) => {
                    self.pos += 1;
                    let name = match self.bump() {
                        Some(Tok::Ident(n)) => n,
                        other => {
                            return Err(CelError::Parse(format!(
                                "expected ident after '.', got {other:?}"
                            )))
                        }
                    };
                    if matches!(self.peek(), Some(Tok::LParen)) {
                        self.pos += 1;
                        let args = self.parse_args()?;
                        e = Node::MethodCall(Box::new(e), name, args);
                    } else {
                        e = Node::Field(Box::new(e), name);
                    }
                }
                Some(Tok::LBrack) => {
                    self.pos += 1;
                    let inner = self.parse_or()?;
                    if !matches!(self.bump(), Some(Tok::RBrack)) {
                        return Err(CelError::Parse("expected ']'".into()));
                    }
                    e = Node::Index(Box::new(e), Box::new(inner));
                }
                _ => break,
            }
        }
        Ok(e)
    }

    fn parse_args(&mut self) -> Result<Vec<Node>, CelError> {
        let mut out = Vec::new();
        if matches!(self.peek(), Some(Tok::RParen)) {
            self.pos += 1;
            return Ok(out);
        }
        loop {
            out.push(self.parse_or()?);
            match self.bump() {
                Some(Tok::Comma) => continue,
                Some(Tok::RParen) => break,
                other => {
                    return Err(CelError::Parse(format!(
                        "expected ',' or ')', got {other:?}"
                    )))
                }
            }
        }
        Ok(out)
    }

    fn parse_primary(&mut self) -> Result<Node, CelError> {
        match self.bump() {
            Some(Tok::Null) => Ok(Node::Null),
            Some(Tok::True) => Ok(Node::Bool(true)),
            Some(Tok::False) => Ok(Node::Bool(false)),
            Some(Tok::Int(i)) => Ok(Node::Int(i)),
            Some(Tok::Float(f)) => Ok(Node::Float(f)),
            Some(Tok::Str(s)) => Ok(Node::Str(s)),
            Some(Tok::Ident(name)) => {
                if matches!(self.peek(), Some(Tok::LParen)) {
                    self.pos += 1;
                    let args = self.parse_args()?;
                    Ok(Node::FreeCall(name, args))
                } else {
                    Ok(Node::Ident(name))
                }
            }
            Some(Tok::LParen) => {
                let e = self.parse_or()?;
                if !matches!(self.bump(), Some(Tok::RParen)) {
                    return Err(CelError::Parse("expected ')'".into()));
                }
                Ok(e)
            }
            Some(Tok::LBrack) => {
                let mut items = Vec::new();
                if matches!(self.peek(), Some(Tok::RBrack)) {
                    self.pos += 1;
                    return Ok(Node::List(items));
                }
                loop {
                    items.push(self.parse_or()?);
                    match self.bump() {
                        Some(Tok::Comma) => continue,
                        Some(Tok::RBrack) => break,
                        other => {
                            return Err(CelError::Parse(format!(
                                "expected ',' or ']', got {other:?}"
                            )))
                        }
                    }
                }
                Ok(Node::List(items))
            }
            other => Err(CelError::Parse(format!("unexpected token {other:?}"))),
        }
    }
}

fn run_node(node: &Node, ctx: &Context) -> Result<CelValue, CelError> {
    match node {
        Node::Null => Ok(CelValue::Null),
        Node::Bool(b) => Ok(CelValue::Bool(*b)),
        Node::Int(i) => Ok(CelValue::Int(*i)),
        Node::Float(f) => Ok(CelValue::Float(*f)),
        Node::Str(s) => Ok(CelValue::Str(s.clone())),
        Node::Ident(n) => ctx
            .vars
            .get(n)
            .cloned()
            .ok_or_else(|| CelError::Runtime(format!("undefined: {n}"))),
        Node::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(run_node(it, ctx)?);
            }
            Ok(CelValue::List(out))
        }
        Node::Field(base, name) => {
            let v = run_node(base, ctx)?;
            match v {
                CelValue::Map(m) => Ok(m.get(name).cloned().unwrap_or(CelValue::Null)),
                other => Err(CelError::Runtime(format!(
                    "field access on non-map {}",
                    other.type_name()
                ))),
            }
        }
        Node::Index(base, key) => {
            let v = run_node(base, ctx)?;
            let k = run_node(key, ctx)?;
            match (&v, &k) {
                (CelValue::Map(m), CelValue::Str(s)) => {
                    Ok(m.get(s).cloned().unwrap_or(CelValue::Null))
                }
                (CelValue::List(l), CelValue::Int(i)) => {
                    let idx = if *i < 0 {
                        return Ok(CelValue::Null);
                    } else {
                        *i as usize
                    };
                    Ok(l.get(idx).cloned().unwrap_or(CelValue::Null))
                }
                _ => Err(CelError::Runtime(format!(
                    "cannot index {} with {}",
                    v.type_name(),
                    k.type_name()
                ))),
            }
        }
        Node::MethodCall(target, method, args) => {
            let recv = run_node(target, ctx)?;
            let argv: Vec<CelValue> = args
                .iter()
                .map(|a| run_node(a, ctx))
                .collect::<Result<_, _>>()?;
            call_method(&recv, method, &argv)
        }
        Node::FreeCall(name, args) => {
            let argv: Vec<CelValue> = args
                .iter()
                .map(|a| run_node(a, ctx))
                .collect::<Result<_, _>>()?;
            call_function(name, &argv)
        }
        Node::Neg(inner) => match run_node(inner, ctx)? {
            CelValue::Int(i) => Ok(CelValue::Int(-i)),
            CelValue::Float(f) => Ok(CelValue::Float(-f)),
            other => Err(CelError::Runtime(format!("- on {}", other.type_name()))),
        },
        Node::Not(inner) => Ok(CelValue::Bool(!run_node(inner, ctx)?.truthy())),
        Node::Bin(op, l, r) => match op {
            BinOp::And => Ok(CelValue::Bool(
                run_node(l, ctx)?.truthy() && run_node(r, ctx)?.truthy(),
            )),
            BinOp::Or => Ok(CelValue::Bool(
                run_node(l, ctx)?.truthy() || run_node(r, ctx)?.truthy(),
            )),
            _ => {
                let lv = run_node(l, ctx)?;
                let rv = run_node(r, ctx)?;
                eval_bin(*op, &lv, &rv)
            }
        },
        Node::In(needle, haystack) => {
            let n = run_node(needle, ctx)?;
            let h = run_node(haystack, ctx)?;
            match h {
                CelValue::List(items) => {
                    Ok(CelValue::Bool(items.iter().any(|x| values_equal(x, &n))))
                }
                CelValue::Map(m) => match n {
                    CelValue::Str(k) => Ok(CelValue::Bool(m.contains_key(&k))),
                    _ => Err(CelError::Runtime("map key must be string".into())),
                },
                CelValue::Str(s) => match n {
                    CelValue::Str(sub) => Ok(CelValue::Bool(s.contains(&sub))),
                    _ => Err(CelError::Runtime("'in' on string needs string".into())),
                },
                _ => Err(CelError::Runtime(
                    "'in' requires list, map, or string".into(),
                )),
            }
        }
    }
}

fn eval_bin(op: BinOp, l: &CelValue, r: &CelValue) -> Result<CelValue, CelError> {
    match (l, r) {
        (CelValue::Int(a), CelValue::Int(b)) => match op {
            BinOp::Eq => Ok(CelValue::Bool(a == b)),
            BinOp::Ne => Ok(CelValue::Bool(a != b)),
            BinOp::Lt => Ok(CelValue::Bool(a < b)),
            BinOp::Le => Ok(CelValue::Bool(a <= b)),
            BinOp::Gt => Ok(CelValue::Bool(a > b)),
            BinOp::Ge => Ok(CelValue::Bool(a >= b)),
            BinOp::Add => Ok(CelValue::Int(a + b)),
            BinOp::Sub => Ok(CelValue::Int(a - b)),
            BinOp::Mul => Ok(CelValue::Int(a * b)),
            BinOp::Div => {
                if *b == 0 {
                    Err(CelError::Runtime("integer divide by zero".into()))
                } else {
                    Ok(CelValue::Int(a / b))
                }
            }
            BinOp::Mod => {
                if *b == 0 {
                    Err(CelError::Runtime("integer modulo by zero".into()))
                } else {
                    Ok(CelValue::Int(a % b))
                }
            }
            _ => unreachable!(),
        },
        (CelValue::Float(a), CelValue::Float(b)) => match op {
            BinOp::Eq => Ok(CelValue::Bool(a == b)),
            BinOp::Ne => Ok(CelValue::Bool(a != b)),
            BinOp::Lt => Ok(CelValue::Bool(a < b)),
            BinOp::Le => Ok(CelValue::Bool(a <= b)),
            BinOp::Gt => Ok(CelValue::Bool(a > b)),
            BinOp::Ge => Ok(CelValue::Bool(a >= b)),
            BinOp::Add => Ok(CelValue::Float(a + b)),
            BinOp::Sub => Ok(CelValue::Float(a - b)),
            BinOp::Mul => Ok(CelValue::Float(a * b)),
            BinOp::Div => Ok(CelValue::Float(a / b)),
            BinOp::Mod => Ok(CelValue::Float(a % b)),
            _ => unreachable!(),
        },
        (CelValue::Int(a), CelValue::Float(b)) => {
            eval_bin(op, &CelValue::Float(*a as f64), &CelValue::Float(*b))
        }
        (CelValue::Float(a), CelValue::Int(b)) => {
            eval_bin(op, &CelValue::Float(*a), &CelValue::Float(*b as f64))
        }
        (CelValue::Str(a), CelValue::Str(b)) => match op {
            BinOp::Eq => Ok(CelValue::Bool(a == b)),
            BinOp::Ne => Ok(CelValue::Bool(a != b)),
            BinOp::Lt => Ok(CelValue::Bool(a < b)),
            BinOp::Le => Ok(CelValue::Bool(a <= b)),
            BinOp::Gt => Ok(CelValue::Bool(a > b)),
            BinOp::Ge => Ok(CelValue::Bool(a >= b)),
            BinOp::Add => Ok(CelValue::Str(format!("{a}{b}"))),
            _ => Err(CelError::Runtime("unsupported op on strings".into())),
        },
        (CelValue::Bool(a), CelValue::Bool(b)) => match op {
            BinOp::Eq => Ok(CelValue::Bool(a == b)),
            BinOp::Ne => Ok(CelValue::Bool(a != b)),
            _ => Err(CelError::Runtime("unsupported op on bools".into())),
        },
        (CelValue::Null, CelValue::Null) => match op {
            BinOp::Eq => Ok(CelValue::Bool(true)),
            BinOp::Ne => Ok(CelValue::Bool(false)),
            _ => Err(CelError::Runtime("null op".into())),
        },
        (a, b) => match op {
            BinOp::Eq => Ok(CelValue::Bool(values_equal(a, b))),
            BinOp::Ne => Ok(CelValue::Bool(!values_equal(a, b))),
            _ => Err(CelError::Runtime(format!(
                "type mismatch: {} vs {}",
                a.type_name(),
                b.type_name()
            ))),
        },
    }
}

fn values_equal(a: &CelValue, b: &CelValue) -> bool {
    match (a, b) {
        (CelValue::Null, CelValue::Null) => true,
        (CelValue::Bool(x), CelValue::Bool(y)) => x == y,
        (CelValue::Int(x), CelValue::Int(y)) => x == y,
        (CelValue::Float(x), CelValue::Float(y)) => x == y,
        (CelValue::Int(x), CelValue::Float(y)) | (CelValue::Float(y), CelValue::Int(x)) => {
            (*x as f64) == *y
        }
        (CelValue::Str(x), CelValue::Str(y)) => x == y,
        (CelValue::List(x), CelValue::List(y)) => {
            x.len() == y.len() && x.iter().zip(y.iter()).all(|(a, b)| values_equal(a, b))
        }
        (CelValue::Map(x), CelValue::Map(y)) => {
            x.len() == y.len()
                && x.iter()
                    .all(|(k, v)| y.get(k).map(|w| values_equal(v, w)).unwrap_or(false))
        }
        _ => false,
    }
}

fn call_method(recv: &CelValue, method: &str, args: &[CelValue]) -> Result<CelValue, CelError> {
    match (recv, method) {
        (CelValue::Str(s), "startsWith") => {
            let prefix = string_arg(args, 0)?;
            Ok(CelValue::Bool(s.starts_with(&prefix)))
        }
        (CelValue::Str(s), "endsWith") => {
            let suffix = string_arg(args, 0)?;
            Ok(CelValue::Bool(s.ends_with(&suffix)))
        }
        (CelValue::Str(s), "contains") => {
            let needle = string_arg(args, 0)?;
            Ok(CelValue::Bool(s.contains(&needle)))
        }
        (CelValue::Str(s), "matches") => {
            let pat = string_arg(args, 0)?;
            let re = Regex::new(&pat)?;
            Ok(CelValue::Bool(re.is_match(s)))
        }
        (CelValue::Str(s), "lower") | (CelValue::Str(s), "lowerAscii") => {
            Ok(CelValue::Str(s.to_ascii_lowercase()))
        }
        (CelValue::Str(s), "upper") | (CelValue::Str(s), "upperAscii") => {
            Ok(CelValue::Str(s.to_ascii_uppercase()))
        }
        (CelValue::Str(s), "size") => Ok(CelValue::Int(s.chars().count() as i64)),
        (CelValue::List(l), "size") => Ok(CelValue::Int(l.len() as i64)),
        (CelValue::Map(m), "size") => Ok(CelValue::Int(m.len() as i64)),
        (CelValue::List(l), "contains") => {
            let needle = args
                .first()
                .cloned()
                .ok_or_else(|| CelError::Runtime("contains(x) needs arg".into()))?;
            Ok(CelValue::Bool(l.iter().any(|x| values_equal(x, &needle))))
        }
        (recv, m) => Err(CelError::Runtime(format!(
            "no method {m:?} on {}",
            recv.type_name()
        ))),
    }
}

fn call_function(name: &str, args: &[CelValue]) -> Result<CelValue, CelError> {
    match name {
        "size" => {
            let v = args
                .first()
                .ok_or_else(|| CelError::Runtime("size() needs arg".into()))?;
            match v {
                CelValue::Str(s) => Ok(CelValue::Int(s.chars().count() as i64)),
                CelValue::List(l) => Ok(CelValue::Int(l.len() as i64)),
                CelValue::Map(m) => Ok(CelValue::Int(m.len() as i64)),
                other => Err(CelError::Runtime(format!(
                    "size() does not support {}",
                    other.type_name()
                ))),
            }
        }
        "string" => Ok(CelValue::Str(format!(
            "{}",
            args.first()
                .ok_or_else(|| CelError::Runtime("string() needs arg".into()))?
        ))),
        "int" => match args.first() {
            Some(CelValue::Int(i)) => Ok(CelValue::Int(*i)),
            Some(CelValue::Float(f)) => Ok(CelValue::Int(*f as i64)),
            Some(CelValue::Str(s)) => s
                .parse()
                .map(CelValue::Int)
                .map_err(|e: std::num::ParseIntError| CelError::Runtime(e.to_string())),
            _ => Err(CelError::Runtime("int() needs value".into())),
        },
        "matches" => {
            let s = string_arg(args, 0)?;
            let p = string_arg(args, 1)?;
            let re = Regex::new(&p)?;
            Ok(CelValue::Bool(re.is_match(&s)))
        }
        other => Err(CelError::Runtime(format!("unknown function {other}"))),
    }
}

fn string_arg(args: &[CelValue], idx: usize) -> Result<String, CelError> {
    match args.get(idx) {
        Some(CelValue::Str(s)) => Ok(s.clone()),
        Some(other) => Err(CelError::Runtime(format!(
            "expected string arg, got {}",
            other.type_name()
        ))),
        None => Err(CelError::Runtime("missing string arg".into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn ctx(args: Value) -> Context {
        Context::with_tool_call("filesystem.write", &args, "fs", "claude-desktop")
    }

    #[test]
    fn literals_and_arithmetic() {
        let p = Program::compile("1 + 2 * 3").unwrap();
        match p.run(&Context::new()).unwrap() {
            CelValue::Int(7) => {}
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn args_field_access_startswith() {
        let p = Program::compile("args.path.startsWith('/etc/')").unwrap();
        assert!(p.run_bool(&ctx(json!({"path": "/etc/passwd"}))).unwrap());
        assert!(!p.run_bool(&ctx(json!({"path": "/tmp/x"}))).unwrap());
    }

    #[test]
    fn in_list_literal() {
        let p = Program::compile("args.branch in ['main', 'master']").unwrap();
        assert!(p.run_bool(&ctx(json!({"branch": "main"}))).unwrap());
        assert!(!p.run_bool(&ctx(json!({"branch": "feature"}))).unwrap());
    }

    #[test]
    fn regex_matches() {
        let p = Program::compile("args.command.matches('(rm|dd|mkfs)')").unwrap();
        assert!(p.run_bool(&ctx(json!({"command": "rm -rf /"}))).unwrap());
        assert!(!p.run_bool(&ctx(json!({"command": "ls"}))).unwrap());
    }

    #[test]
    fn logical_combinations() {
        let p = Program::compile("args.x > 0 && args.y < 10 || args.flag").unwrap();
        assert!(p
            .run_bool(&ctx(json!({"x": 5, "y": 5, "flag": false})))
            .unwrap());
        assert!(p
            .run_bool(&ctx(json!({"x": 0, "y": 100, "flag": true})))
            .unwrap());
        assert!(!p
            .run_bool(&ctx(json!({"x": 0, "y": 100, "flag": false})))
            .unwrap());
    }

    #[test]
    fn size_compares() {
        let p = Program::compile("args.size_bytes > 1048576").unwrap();
        assert!(p.run_bool(&ctx(json!({"size_bytes": 2000000}))).unwrap());
        assert!(!p.run_bool(&ctx(json!({"size_bytes": 50}))).unwrap());
    }

    #[test]
    fn parse_error_reported() {
        let err = Program::compile("args. .x").unwrap_err();
        assert!(matches!(err, CelError::Parse(_)));
    }
}
