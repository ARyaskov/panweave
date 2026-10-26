//! Telegram Bot API `sendMessage` over HTTPS
//! (<https://core.telegram.org/bots/api#sendmessage>): the request and
//! the interpretation of the response.
//!
//! The bot token is part of the request *line* (`/bot<token>/…`): the
//! request buffer is therefore secret — it is never logged, captured or
//! returned, and the caller wipes it after the attempt
//! ([`wipe`]). Only the TLS layer sees it in clear.

/// API host (for DNS, SNI and certificate host name verification).
pub const HOST: &str = "api.telegram.org";
/// HTTPS port.
pub const PORT: u16 = 443;

/// Why a request could not be built.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BuildError {
    /// The output buffer is too small.
    TooLong,
    /// The token or chat identifier contains characters that cannot be
    /// sent as they are.
    InvalidSetting,
}

/// What the response says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reply {
    /// HTTP 200 with `"ok":true` and a `message_id`: delivered.
    Delivered {
        /// The published message.
        message_id: i64,
    },
    /// Rate limited (HTTP 429 / `retry_after`).
    RetryAfter {
        /// HTTP status.
        status: u16,
        /// Seconds to wait.
        seconds: u32,
    },
    /// Refused for good (wrong token, chat, missing permission: 4xx):
    /// the settings must be fixed; events stay queued.
    Rejected {
        /// HTTP status.
        status: u16,
        /// Telegram's `error_code`, when given.
        error_code: Option<u32>,
    },
    /// A server error (5xx) or an `"ok":false` without detail: retried.
    ServerError {
        /// HTTP status.
        status: u16,
    },
    /// Not an HTTP response this client understands, or `"ok":true`
    /// without a `message_id`. The request may have been processed, so
    /// this counts as an ambiguous outcome.
    Malformed,
}

/// Overwrites a buffer that held the token.
pub fn wipe(buf: &mut [u8]) {
    buf.fill(0);
    // Keeps the zeroed buffer observable so the stores are not elided.
    core::hint::black_box(&*buf);
}

struct Out<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Out<'_> {
    fn push(&mut self, s: &[u8]) -> Result<(), BuildError> {
        let end = self.len.checked_add(s.len()).ok_or(BuildError::TooLong)?;
        self.buf
            .get_mut(self.len..end)
            .ok_or(BuildError::TooLong)?
            .copy_from_slice(s);
        self.len = end;
        Ok(())
    }

    fn json_str(&mut self, s: &str) -> Result<(), BuildError> {
        self.push(b"\"")?;
        for c in s.chars() {
            match c {
                '"' => self.push(b"\\\"")?,
                '\\' => self.push(b"\\\\")?,
                '\n' => self.push(b"\\n")?,
                '\r' => self.push(b"\\r")?,
                '\t' => self.push(b"\\t")?,
                c if u32::from(c) < 0x20 => {
                    let hex = b"0123456789abcdef";
                    let v = u32::from(c);
                    self.push(b"\\u00")?;
                    self.push(&[hex[(v >> 4) as usize], hex[(v & 15) as usize]])?;
                }
                c => {
                    let mut tmp = [0u8; 4];
                    self.push(c.encode_utf8(&mut tmp).as_bytes())?;
                }
            }
        }
        self.push(b"\"")
    }
}

fn json_len(s: &str) -> usize {
    s.chars()
        .map(|c| match c {
            '"' | '\\' | '\n' | '\r' | '\t' => 2,
            c if u32::from(c) < 0x20 => 6,
            c => c.len_utf8(),
        })
        .sum::<usize>()
        + 2
}

fn valid_token(t: &[u8]) -> bool {
    // `<digits>:<base64url>`: nothing that could break the request line.
    !t.is_empty()
        && t.iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b':' | b'_' | b'-'))
}

fn valid_chat(c: &[u8]) -> bool {
    !c.is_empty()
        && c.iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'@'))
}

fn decimal(mut v: usize, out: &mut [u8; 20]) -> &[u8] {
    let mut i = out.len();
    loop {
        i -= 1;
        #[allow(clippy::cast_possible_truncation)]
        {
            out[i] = b'0' + (v % 10) as u8;
        }
        v /= 10;
        if v == 0 {
            break;
        }
    }
    &out[i..]
}

/// Builds the complete HTTP/1.1 `sendMessage` request into `out`;
/// returns its length. The body is JSON (`chat_id` as a string works for
/// numeric identifiers and `@channel` names alike).
///
/// # Errors
///
/// [`BuildError`].
pub fn build_request(
    token: &[u8],
    chat_id: &[u8],
    text: &str,
    out: &mut [u8],
) -> Result<usize, BuildError> {
    if !valid_token(token) || !valid_chat(chat_id) {
        return Err(BuildError::InvalidSetting);
    }
    let chat = core::str::from_utf8(chat_id).map_err(|_| BuildError::InvalidSetting)?;
    let body_len =
        br#"{"chat_id":"#.len() + json_len(chat) + br#","text":"#.len() + json_len(text) + 1;
    let mut o = Out { buf: out, len: 0 };
    o.push(b"POST /bot")?;
    o.push(token)?;
    o.push(b"/sendMessage HTTP/1.1\r\nHost: ")?;
    o.push(HOST.as_bytes())?;
    o.push(b"\r\nContent-Type: application/json\r\nConnection: close\r\nContent-Length: ")?;
    let mut digits = [0u8; 20];
    o.push(decimal(body_len, &mut digits))?;
    o.push(b"\r\n\r\n")?;
    let body_start = o.len;
    o.push(br#"{"chat_id":"#)?;
    o.json_str(chat)?;
    o.push(br#","text":"#)?;
    o.json_str(text)?;
    o.push(b"}")?;
    debug_assert_eq!(o.len - body_start, body_len);
    Ok(o.len)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn skip_ws(b: &[u8], mut i: usize) -> usize {
    while b.get(i).is_some_and(u8::is_ascii_whitespace) {
        i += 1;
    }
    i
}

/// The value after `"name":` in a JSON text (`b"true"`, a number…).
fn json_field<'a>(body: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut start = 0;
    while let Some(p) = body.get(start..).and_then(|b| find(b, name)) {
        let at = start + p;
        let before_quote = at.checked_sub(1).and_then(|i| body.get(i)) == Some(&b'"');
        let after = at + name.len();
        if before_quote && body.get(after) == Some(&b'"') {
            let i = skip_ws(body, after + 1);
            if body.get(i) == Some(&b':') {
                let v = skip_ws(body, i + 1);
                let end = body
                    .get(v..)?
                    .iter()
                    .position(|c| matches!(c, b',' | b'}' | b']') || c.is_ascii_whitespace())
                    .map_or(body.len(), |e| v + e);
                return body.get(v..end);
            }
        }
        start = after;
    }
    None
}

fn json_int(body: &[u8], name: &[u8]) -> Option<i64> {
    let v = json_field(body, name)?;
    let s = core::str::from_utf8(v).ok()?;
    s.parse().ok()
}

fn dechunk(body: &[u8], out: &mut [u8]) -> Option<usize> {
    let mut i = 0;
    let mut n = 0;
    loop {
        let line_end = find(body.get(i..)?, b"\r\n")? + i;
        let size_txt = core::str::from_utf8(body.get(i..line_end)?).ok()?;
        let size_txt = size_txt.split(';').next()?.trim();
        let size = usize::from_str_radix(size_txt, 16).ok()?;
        i = line_end + 2;
        if size == 0 {
            return Some(n);
        }
        let chunk = body.get(i..i.checked_add(size)?)?;
        out.get_mut(n..n + size)?.copy_from_slice(chunk);
        n += size;
        i += size + 2;
    }
}

/// Interprets a complete HTTP response (the connection was closed by
/// the server or the body is complete). `scratch` is used to de-chunk.
pub fn parse_response(resp: &[u8], scratch: &mut [u8]) -> (Option<u16>, Reply) {
    let Some(status) = resp
        .strip_prefix(b"HTTP/1.1 ")
        .or_else(|| resp.strip_prefix(b"HTTP/1.0 "))
        .and_then(|r| r.get(..3))
        .and_then(|d| core::str::from_utf8(d).ok())
        .and_then(|d| d.parse::<u16>().ok())
    else {
        return (None, Reply::Malformed);
    };
    let Some(head_end) = find(resp, b"\r\n\r\n") else {
        return (Some(status), Reply::Malformed);
    };
    let head = &resp[..head_end];
    let mut body = &resp[head_end + 4..];
    let chunked = head.split(|b| *b == b'\n').any(|l| {
        l.get(..18)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"transfer-encoding:"))
            && l.windows(7).any(|w| w.eq_ignore_ascii_case(b"chunked"))
    });
    if chunked {
        match dechunk(body, scratch) {
            Some(n) => body = &scratch[..n],
            None => return (Some(status), Reply::Malformed),
        }
    }
    let ok = json_field(body, b"ok");
    let retry_after = json_int(body, b"retry_after");
    let error_code = json_int(body, b"error_code").and_then(|c| u32::try_from(c).ok());
    let reply = if status == 200 && ok == Some(b"true".as_slice()) {
        match json_int(body, b"message_id") {
            Some(message_id) => Reply::Delivered { message_id },
            None => Reply::Malformed,
        }
    } else if status == 429 || retry_after.is_some() {
        Reply::RetryAfter {
            status,
            seconds: retry_after
                .and_then(|s| u32::try_from(s).ok())
                .unwrap_or(30),
        }
    } else if (400..500).contains(&status) {
        Reply::Rejected { status, error_code }
    } else if status >= 500 || ok == Some(b"false".as_slice()) {
        Reply::ServerError { status }
    } else {
        Reply::Malformed
    };
    (Some(status), reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &[u8] = b"123456:ABC-def_ghi";

    #[test]
    fn the_request_is_well_formed_json_with_the_token_only_in_the_request_line() {
        let mut out = [0u8; 512];
        let text = "Water leak detected.\nSensor: \"bath\" \\ 1";
        let n = build_request(TOKEN, b"-1001234567890", text, &mut out).unwrap();
        let req = core::str::from_utf8(&out[..n]).unwrap();
        assert!(req.starts_with("POST /bot123456:ABC-def_ghi/sendMessage HTTP/1.1\r\n"));
        assert_eq!(req.matches("123456:ABC").count(), 1);
        let (head, body) = req.split_once("\r\n\r\n").unwrap();
        assert!(head.contains("Host: api.telegram.org"));
        let len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(len, body.len());
        assert_eq!(
            body,
            r#"{"chat_id":"-1001234567890","text":"Water leak detected.\nSensor: \"bath\" \\ 1"}"#
        );
    }

    #[test]
    fn settings_that_could_inject_into_the_request_are_refused() {
        let mut out = [0u8; 256];
        assert_eq!(
            build_request(b"1:a b", b"1", "x", &mut out),
            Err(BuildError::InvalidSetting)
        );
        assert_eq!(
            build_request(b"1:a\r\nX: y", b"1", "x", &mut out),
            Err(BuildError::InvalidSetting)
        );
        assert_eq!(
            build_request(TOKEN, b"1\"", "x", &mut out),
            Err(BuildError::InvalidSetting)
        );
        assert_eq!(
            build_request(TOKEN, b"@chan", "x", &mut [0u8; 40]),
            Err(BuildError::TooLong)
        );
    }

    #[test]
    fn a_successful_response_yields_the_message_id() {
        let r = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"ok\":true,\"result\":{\"message_id\":4242,\"chat\":{\"id\":-100},\"date\":1}}";
        assert_eq!(
            parse_response(r, &mut [0u8; 256]),
            (Some(200), Reply::Delivered { message_id: 4242 })
        );
        // Chunked, with whitespace.
        let body = "{ \"ok\" : true, \"result\": { \"message_id\" : 7 } }";
        let chunked = format!(
            "HTTP/1.1 200 OK\r\ntransfer-encoding: Chunked\r\n\r\n{:x}\r\n{}\r\n0\r\n\r\n",
            body.len(),
            body
        );
        assert_eq!(
            parse_response(chunked.as_bytes(), &mut [0u8; 256]).1,
            Reply::Delivered { message_id: 7 }
        );
    }

    #[test]
    fn failures_are_classified() {
        let mut s = [0u8; 256];
        let r = b"HTTP/1.1 429 Too Many Requests\r\n\r\n{\"ok\":false,\"error_code\":429,\"description\":\"Too Many Requests: retry after 35\",\"parameters\":{\"retry_after\":35}}";
        assert_eq!(
            parse_response(r, &mut s).1,
            Reply::RetryAfter {
                status: 429,
                seconds: 35
            }
        );
        let r = b"HTTP/1.1 403 Forbidden\r\n\r\n{\"ok\":false,\"error_code\":403,\"description\":\"Forbidden: bot is not a member of the channel chat\"}";
        assert_eq!(
            parse_response(r, &mut s).1,
            Reply::Rejected {
                status: 403,
                error_code: Some(403)
            }
        );
        let r = b"HTTP/1.1 502 Bad Gateway\r\n\r\n<html>";
        assert_eq!(
            parse_response(r, &mut s).1,
            Reply::ServerError { status: 502 }
        );
        // ok:true without a message id, truncated, not HTTP.
        let r = b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true,\"result\":{}}";
        assert_eq!(parse_response(r, &mut s).1, Reply::Malformed);
        assert_eq!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-", &mut s).1,
            Reply::Malformed
        );
        assert_eq!(parse_response(b"garbage", &mut s), (None, Reply::Malformed));
        // A field name inside a string value is not the field.
        let r = b"HTTP/1.1 200 OK\r\n\r\n{\"ok\":true,\"result\":{\"text\":\"\\\"message_id\\\":1\",\"message_id\":9}}";
        assert_eq!(
            parse_response(r, &mut s).1,
            Reply::Delivered { message_id: 9 }
        );
    }

    #[test]
    fn wiping_clears_the_buffer() {
        let mut out = [0u8; 256];
        let n = build_request(TOKEN, b"1", "x", &mut out).unwrap();
        wipe(&mut out[..n]);
        assert!(out.iter().all(|b| *b == 0));
    }
}
