#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

impl Value {
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Object(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(value) => Some(value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&Vec<Value>> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }
}

pub fn parse(text: &str) -> Option<Value> {
    let mut parser = Parser { data: text.as_bytes(), position: 0 };
    let value = parser.value()?;
    parser.whitespace();
    Some(value)
}

struct Parser<'a> {
    data: &'a [u8],
    position: usize,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while self.position < self.data.len() && self.data[self.position].is_ascii_whitespace() {
            self.position += 1;
        }
    }

    fn value(&mut self) -> Option<Value> {
        self.whitespace();
        match *self.data.get(self.position)? {
            b'{' => {
                self.position += 1;
                let mut entries = Vec::new();
                loop {
                    self.whitespace();
                    if self.data.get(self.position) == Some(&b'}') {
                        self.position += 1;
                        return Some(Value::Object(entries));
                    }
                    let key = match self.value()? {
                        Value::String(key) => key,
                        _ => return None,
                    };
                    self.whitespace();
                    if self.data.get(self.position) != Some(&b':') {
                        return None;
                    }
                    self.position += 1;
                    let value = self.value()?;
                    entries.push((key, value));
                    self.whitespace();
                    match self.data.get(self.position) {
                        Some(b',') => self.position += 1,
                        Some(b'}') => {}
                        _ => return None,
                    }
                }
            }
            b'[' => {
                self.position += 1;
                let mut items = Vec::new();
                loop {
                    self.whitespace();
                    if self.data.get(self.position) == Some(&b']') {
                        self.position += 1;
                        return Some(Value::Array(items));
                    }
                    items.push(self.value()?);
                    self.whitespace();
                    match self.data.get(self.position) {
                        Some(b',') => self.position += 1,
                        Some(b']') => {}
                        _ => return None,
                    }
                }
            }
            b'"' => {
                self.position += 1;
                let mut out = String::new();
                while let Some(&byte) = self.data.get(self.position) {
                    self.position += 1;
                    match byte {
                        b'"' => return Some(Value::String(out)),
                        b'\\' => {
                            let escaped = *self.data.get(self.position)?;
                            self.position += 1;
                            out.push(match escaped {
                                b'n' => '\n',
                                b't' => '\t',
                                other => other as char,
                            });
                        }
                        other => out.push(other as char),
                    }
                }
                None
            }
            b't' if self.data[self.position..].starts_with(b"true") => {
                self.position += 4;
                Some(Value::Bool(true))
            }
            b'f' if self.data[self.position..].starts_with(b"false") => {
                self.position += 5;
                Some(Value::Bool(false))
            }
            b'n' if self.data[self.position..].starts_with(b"null") => {
                self.position += 4;
                Some(Value::Null)
            }
            _ => {
                let start = self.position;
                while let Some(&byte) = self.data.get(self.position) {
                    if byte.is_ascii_digit() || matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E') {
                        self.position += 1;
                    } else {
                        break;
                    }
                }
                std::str::from_utf8(&self.data[start..self.position]).ok()?.parse().ok().map(Value::Number)
            }
        }
    }
}
