//! A minimal JSON object writer for the CLI's machine-readable output
//! (`--json`, JSONL exports). Field names are stable: they are the
//! documented schema (`docs/esp32c6-diagnostics.md`).

use std::fmt::Write as _;

/// A JSON object under construction.
#[derive(Default)]
pub(crate) struct Obj {
    out: String,
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

impl Obj {
    pub(crate) fn new() -> Self {
        Obj::default()
    }

    fn key(&mut self, k: &str) {
        self.out.push(if self.out.is_empty() { '{' } else { ',' });
        escape(k, &mut self.out);
        self.out.push(':');
    }

    /// A string field.
    pub(crate) fn str(mut self, k: &str, v: &str) -> Self {
        self.key(k);
        escape(v, &mut self.out);
        self
    }

    /// A 64-bit integer field (exact, not through f64).
    pub(crate) fn int(mut self, k: &str, v: i128) -> Self {
        self.key(k);
        let _ = write!(self.out, "{v}");
        self
    }

    /// A boolean field.
    pub(crate) fn bool(mut self, k: &str, v: bool) -> Self {
        self.key(k);
        self.out.push_str(if v { "true" } else { "false" });
        self
    }

    /// An optional integer field: `null` when absent (unavailable).
    pub(crate) fn opt(mut self, k: &str, v: Option<i128>) -> Self {
        self.key(k);
        match v {
            Some(v) => {
                let _ = write!(self.out, "{v}");
            }
            None => self.out.push_str("null"),
        }
        self
    }

    /// An optional string field.
    pub(crate) fn opt_str(mut self, k: &str, v: Option<&str>) -> Self {
        self.key(k);
        match v {
            Some(v) => escape(v, &mut self.out),
            None => self.out.push_str("null"),
        }
        self
    }

    /// A field holding already-encoded JSON.
    pub(crate) fn raw(mut self, k: &str, json: &str) -> Self {
        self.key(k);
        self.out.push_str(json);
        self
    }

    /// The object's text.
    pub(crate) fn finish(mut self) -> String {
        if self.out.is_empty() {
            self.out.push('{');
        }
        self.out.push('}');
        self.out
    }
}

/// A JSON array of already-encoded items.
pub(crate) fn array(items: &[String]) -> String {
    let mut s = String::from("[");
    for (i, it) in items.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(it);
    }
    s.push(']');
    s
}

/// A string as a JSON value.
pub(crate) fn string(v: &str) -> String {
    let mut s = String::new();
    escape(v, &mut s);
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_are_valid_json() {
        let o = Obj::new()
            .str("name", "a\"b\\c\n")
            .int("ieee", 0x0011_2233_4455_6677)
            .opt("rssi", None)
            .bool("ok", true)
            .raw("list", &array(&[string("x"), "1".into()]))
            .finish();
        assert_eq!(
            o,
            r#"{"name":"a\"b\\c\n","ieee":4822678189205111,"rssi":null,"ok":true,"list":["x",1]}"#
        );
        assert_eq!(Obj::new().finish(), "{}");
    }
}
