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

    pub fn to_json(&self) -> String {
        let mut out = String::new();
        self.write(&mut out);
        out
    }

    fn write(&self, out: &mut String) {
        match self {
            Value::Null => out.push_str("null"),
            Value::Bool(value) => out.push_str(if *value { "true" } else { "false" }),
            Value::Number(value) if !value.is_finite() => out.push_str("null"),
            Value::Number(value) if value.fract() == 0.0 && value.abs() < 9.0e15 => {
                out.push_str(&format!("{}", *value as i64));
            }
            Value::Number(value) => out.push_str(&format!("{value}")),
            Value::String(text) => write_string(text, out),
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    item.write(out);
                }
                out.push(']');
            }
            Value::Object(entries) => {
                out.push('{');
                for (index, (key, value)) in entries.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write_string(key, out);
                    out.push(':');
                    value.write(out);
                }
                out.push('}');
            }
        }
    }
}

fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", character as u32)),
            character => out.push(character),
        }
    }
    out.push('"');
}

pub fn parse(text: &str) -> Option<Value> {
    let mut parser = Parser { data: text.as_bytes(), position: 0 };
    let value = parser.value()?;
    parser.whitespace();
    (parser.position == parser.data.len()).then_some(value)
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
                let mut out = Vec::new();
                while let Some(&byte) = self.data.get(self.position) {
                    self.position += 1;
                    match byte {
                        b'"' => return String::from_utf8(out).ok().map(Value::String),
                        b'\\' => {
                            let escaped = *self.data.get(self.position)?;
                            self.position += 1;
                            let character = match escaped {
                                b'n' => '\n',
                                b't' => '\t',
                                b'r' => '\r',
                                b'b' => '\u{8}',
                                b'f' => '\u{c}',
                                b'u' => self.escaped_unicode()?,
                                b'"' | b'\\' | b'/' => escaped as char,
                                _ => return None,
                            };
                            let mut buffer = [0u8; 4];
                            out.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
                        }
                        other => out.push(other),
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

    fn hex4(&mut self) -> Option<u32> {
        let digits = self.data.get(self.position..self.position + 4)?;
        if !digits.iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        self.position += 4;
        u32::from_str_radix(std::str::from_utf8(digits).ok()?, 16).ok()
    }

    fn escaped_unicode(&mut self) -> Option<char> {
        let unit = self.hex4()?;
        if !(0xd800..0xdc00).contains(&unit) {
            return char::from_u32(unit);
        }
        if self.data.get(self.position..self.position + 2)? != b"\\u" {
            return None;
        }
        self.position += 2;
        let low = self.hex4()?;
        if !(0xdc00..0xe000).contains(&low) {
            return None;
        }
        char::from_u32(0x10000 + ((unit - 0xd800) << 10) + (low - 0xdc00))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_round_trip_through_the_writer_and_the_parser() {
        let text = "rtt\u{2264}128ms \"quoted\" back\\slash\n\r\t\u{8}\u{c}\u{1} \u{1f600}";
        let value = Value::Array(vec![Value::String(text.into())]);
        assert_eq!(parse(&value.to_json()), Some(value));
    }

    #[test]
    fn escaped_code_points_and_surrogate_pairs_are_decoded() {
        assert_eq!(parse(r#""\u2264 \ud83d\ude00 \/""#), Some(Value::String("\u{2264} \u{1f600} /".into())));
        assert_eq!(parse(r#""\ud83d""#), None);
        assert_eq!(parse(r#""\q""#), None);
    }
}
