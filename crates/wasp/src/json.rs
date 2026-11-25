//! A small, strict JSON reader for what clients send (the messenger's
//! frames): RFC 8259 values, with a depth and a size cap, numbers as whole
//! numbers only, and no duplicate keys in an object. Anything else is
//! refused, never guessed at.

/// A JSON value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A whole number (`-12`, `3`); fractions and exponents are refused.
    Int(i64),
    /// A string.
    Str(String),
    /// An array.
    Arr(Vec<Value>),
    /// An object, its keys in order.
    Obj(Vec<(String, Value)>),
}

impl Value {
    /// The member `key` of an object.
    #[must_use]
    pub fn get(&self, key: &str) -> Option<&Value> {
        match self {
            Value::Obj(members) => members.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// The string, when it is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }

    /// The number, when it is one.
    #[must_use]
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(n) => Some(*n),
            _ => None,
        }
    }

    /// The boolean, when it is one.
    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    /// The array, when it is one.
    #[must_use]
    pub fn as_arr(&self) -> Option<&[Value]> {
        match self {
            Value::Arr(a) => Some(a),
            _ => None,
        }
    }
}

/// How deep arrays and objects may nest.
pub const MAX_DEPTH: usize = 16;

/// The longest text read, in bytes.
pub const MAX_LEN: usize = 1 << 20;

/// The most items in one array.
pub const MAX_ITEMS: usize = 1_000;

/// The most members in one object: frames and stored bodies have a few
/// keys each.
pub const MAX_MEMBERS: usize = 32;

/// Reads `text` as one JSON value (whitespace around it allowed).
///
/// # Errors
///
/// Why it is not such a value, in a few words.
pub fn parse(text: &str) -> Result<Value, &'static str> {
    if text.len() > MAX_LEN {
        return Err("too long");
    }
    let mut r = Reader {
        b: text.as_bytes(),
        at: 0,
    };
    r.ws();
    let v = r.value(0)?;
    r.ws();
    if r.at != r.b.len() {
        return Err("text after the value");
    }
    Ok(v)
}

struct Reader<'a> {
    b: &'a [u8],
    at: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.at).copied()
    }

    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\n' | b'\r')) {
            self.at += 1;
        }
    }

    fn eat(&mut self, word: &[u8]) -> bool {
        if self.b.get(self.at..self.at + word.len()) == Some(word) {
            self.at += word.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, &'static str> {
        match self.peek() {
            Some(b'{') => self.object(depth + 1),
            Some(b'[') => self.array(depth + 1),
            Some(b'"') => self.string().map(Value::Str),
            Some(b't') if self.eat(b"true") => Ok(Value::Bool(true)),
            Some(b'f') if self.eat(b"false") => Ok(Value::Bool(false)),
            Some(b'n') if self.eat(b"null") => Ok(Value::Null),
            Some(b'-' | b'0'..=b'9') => self.number(),
            Some(_) => Err("not a value"),
            None => Err("the text ends early"),
        }
    }

    fn object(&mut self, depth: usize) -> Result<Value, &'static str> {
        if depth > MAX_DEPTH {
            return Err("nested too deep");
        }
        self.at += 1;
        let mut members: Vec<(String, Value)> = Vec::new();
        let mut keys: std::collections::HashSet<String> = std::collections::HashSet::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.at += 1;
            return Ok(Value::Obj(members));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err("an object key must be a string");
            }
            let key = self.string()?;
            if members.len() == MAX_MEMBERS {
                return Err("too many members");
            }
            if !keys.insert(key.clone()) {
                return Err("a key appears twice");
            }
            self.ws();
            if self.peek() != Some(b':') {
                return Err("':' expected");
            }
            self.at += 1;
            self.ws();
            let v = self.value(depth)?;
            members.push((key, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b'}') => {
                    self.at += 1;
                    return Ok(Value::Obj(members));
                }
                _ => return Err("',' or '}' expected"),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, &'static str> {
        if depth > MAX_DEPTH {
            return Err("nested too deep");
        }
        self.at += 1;
        let mut items = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.at += 1;
            return Ok(Value::Arr(items));
        }
        loop {
            self.ws();
            items.push(self.value(depth)?);
            if items.len() > MAX_ITEMS {
                return Err("too many items");
            }
            self.ws();
            match self.peek() {
                Some(b',') => self.at += 1,
                Some(b']') => {
                    self.at += 1;
                    return Ok(Value::Arr(items));
                }
                _ => return Err("',' or ']' expected"),
            }
        }
    }

    fn number(&mut self) -> Result<Value, &'static str> {
        let start = self.at;
        if self.peek() == Some(b'-') {
            self.at += 1;
        }
        match self.peek() {
            Some(b'0') => self.at += 1,
            Some(b'1'..=b'9') => {
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.at += 1;
                }
            }
            _ => return Err("not a number"),
        }
        if matches!(self.peek(), Some(b'.' | b'e' | b'E')) {
            return Err("only whole numbers");
        }
        std::str::from_utf8(&self.b[start..self.at])
            .ok()
            .and_then(|s| s.parse().ok())
            .map(Value::Int)
            .ok_or("a number out of range")
    }

    fn hex4(&mut self) -> Result<u32, &'static str> {
        let digits = self
            .b
            .get(self.at..self.at + 4)
            .ok_or("a short \\u escape")?;
        let text = std::str::from_utf8(digits).map_err(|_| "a bad \\u escape")?;
        let n = u32::from_str_radix(text, 16).map_err(|_| "a bad \\u escape")?;
        self.at += 4;
        Ok(n)
    }

    fn string(&mut self) -> Result<String, &'static str> {
        self.at += 1;
        let mut out = String::new();
        loop {
            let start = self.at;
            while let Some(c) = self.peek() {
                if c == b'"' || c == b'\\' || c < 0x20 {
                    break;
                }
                self.at += 1;
            }
            // The input is a `str`, and the run stops only at ASCII: whole
            // characters.
            out.push_str(std::str::from_utf8(&self.b[start..self.at]).map_err(|_| "bad UTF-8")?);
            match self.peek() {
                Some(b'"') => {
                    self.at += 1;
                    return Ok(out);
                }
                Some(b'\\') => {
                    self.at += 1;
                    let c = self.peek().ok_or("the text ends early")?;
                    self.at += 1;
                    match c {
                        b'"' => out.push('"'),
                        b'\\' => out.push('\\'),
                        b'/' => out.push('/'),
                        b'b' => out.push('\u{8}'),
                        b'f' => out.push('\u{c}'),
                        b'n' => out.push('\n'),
                        b'r' => out.push('\r'),
                        b't' => out.push('\t'),
                        b'u' => {
                            let hi = self.hex4()?;
                            let code = if (0xD800..0xDC00).contains(&hi) {
                                if !self.eat(b"\\u") {
                                    return Err("a lone surrogate");
                                }
                                let lo = self.hex4()?;
                                if !(0xDC00..0xE000).contains(&lo) {
                                    return Err("a lone surrogate");
                                }
                                0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00)
                            } else if (0xDC00..0xE000).contains(&hi) {
                                return Err("a lone surrogate");
                            } else {
                                hi
                            };
                            out.push(char::from_u32(code).ok_or("a bad \\u escape")?);
                        }
                        _ => return Err("a bad escape"),
                    }
                }
                Some(_) => return Err("a control character in a string"),
                None => return Err("the text ends early"),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values_are_read_strictly() {
        let v = parse(r#" {"op":"send","n":-12,"ok":true,"no":null,"body":[{"text":"h\u00e9\n\ud83d\ude00"}]} "#)
            .expect("parses");
        assert_eq!(v.get("op").and_then(Value::as_str), Some("send"));
        assert_eq!(v.get("n").and_then(Value::as_int), Some(-12));
        assert_eq!(v.get("ok").and_then(Value::as_bool), Some(true));
        assert_eq!(v.get("no"), Some(&Value::Null));
        let text = v.get("body").and_then(Value::as_arr).expect("arr")[0]
            .get("text")
            .and_then(Value::as_str)
            .map(str::to_owned);
        assert_eq!(text.as_deref(), Some("hé\n😀"));
        for bad in [
            "",
            "{",
            "[1,]",
            "{\"a\":1,}",
            "{\"a\":1,\"a\":2}",
            "01",
            "1.5",
            "1e3",
            "\"\\x\"",
            "\"a\nb\"",
            "\"\\ud800\"",
            "\"\\udc00\"",
            "tru",
            "nul",
            "{} {}",
            "{a:1}",
            "99999999999999999999",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
        let deep = format!("{}{}", "[".repeat(MAX_DEPTH + 1), "]".repeat(MAX_DEPTH + 1));
        assert!(parse(&deep).is_err());
        let ok = format!("{}{}", "[".repeat(MAX_DEPTH), "]".repeat(MAX_DEPTH));
        assert!(parse(&ok).is_ok());
    }

    #[test]
    fn big_objects_are_refused_early() {
        let object = |n: usize| {
            let members: Vec<String> = (0..n).map(|i| format!("\"k{i}\":1")).collect();
            format!("{{{}}}", members.join(","))
        };
        assert!(parse(&object(MAX_MEMBERS)).is_ok());
        assert_eq!(parse(&object(MAX_MEMBERS + 1)), Err("too many members"));
        // A frame as big as a WebSocket message allows, all keys: refused
        // after a few dozen, not checked pair by pair.
        let t = std::time::Instant::now();
        assert!(parse(&object(20_000)).is_err());
        assert!(t.elapsed() < std::time::Duration::from_millis(50));
        let items = |n: usize| format!("[{}]", vec!["1"; n].join(","));
        assert!(parse(&items(MAX_ITEMS)).is_ok());
        assert_eq!(parse(&items(MAX_ITEMS + 1)), Err("too many items"));
    }
}
