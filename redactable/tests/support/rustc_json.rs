//! Minimal structural reader for Cargo's newline-delimited rustc JSON messages.

use std::collections::HashSet;

fn string_end(bytes: &[u8], start: usize) -> Option<usize> {
    if bytes.get(start) != Some(&b'"') {
        return None;
    }
    let mut escaped = false;
    for (offset, byte) in bytes[start + 1..].iter().enumerate() {
        if escaped {
            escaped = false;
        } else if *byte == b'\\' {
            escaped = true;
        } else if *byte == b'"' {
            return Some(start + offset + 2);
        }
    }
    None
}

fn value_end(bytes: &[u8], start: usize) -> Option<usize> {
    match *bytes.get(start)? {
        b'"' => string_end(bytes, start),
        b'{' | b'[' => {
            let mut closers = vec![if bytes[start] == b'{' { b'}' } else { b']' }];
            let mut index = start + 1;
            while index < bytes.len() {
                match bytes[index] {
                    b'"' => index = string_end(bytes, index)?,
                    b'{' => {
                        closers.push(b'}');
                        index += 1;
                    }
                    b'[' => {
                        closers.push(b']');
                        index += 1;
                    }
                    byte if Some(&byte) == closers.last() => {
                        closers.pop();
                        index += 1;
                        if closers.is_empty() {
                            return Some(index);
                        }
                    }
                    _ => index += 1,
                }
            }
            None
        }
        _ => Some(
            bytes[start..]
                .iter()
                .position(|byte| matches!(byte, b',' | b'}' | b']' | b' ' | b'\n' | b'\r'))
                .map_or(bytes.len(), |offset| start + offset),
        ),
    }
}

fn field<'a>(object: &'a str, key: &str) -> Option<&'a str> {
    let bytes = object.as_bytes();
    if bytes.first() != Some(&b'{') {
        return None;
    }
    let mut index = 1;
    while index < bytes.len() {
        while matches!(bytes.get(index), Some(b' ' | b'\n' | b'\r' | b',')) {
            index += 1;
        }
        if bytes.get(index) == Some(&b'}') {
            return None;
        }
        let key_end = string_end(bytes, index)?;
        let candidate = &object[index + 1..key_end - 1];
        index = key_end;
        while bytes.get(index) == Some(&b' ') {
            index += 1;
        }
        if bytes.get(index) != Some(&b':') {
            return None;
        }
        index += 1;
        while bytes.get(index) == Some(&b' ') {
            index += 1;
        }
        let value_start = index;
        let value_end = value_end(bytes, value_start)?;
        if candidate == key {
            return Some(&object[value_start..value_end]);
        }
        index = value_end;
    }
    None
}

fn string(value: &str) -> Option<&str> {
    value.strip_prefix('"')?.strip_suffix('"')
}

fn line_starts(json: &str) -> HashSet<usize> {
    let bytes = json.as_bytes();
    let mut lines = HashSet::new();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'"' {
            index += 1;
            continue;
        }
        let Some(key_end) = string_end(bytes, index) else {
            break;
        };
        if &json[index + 1..key_end - 1] != "line_start" {
            index = key_end;
            continue;
        }
        index = key_end;
        while matches!(bytes.get(index), Some(b' ' | b':')) {
            index += 1;
        }
        let number_end = bytes[index..]
            .iter()
            .position(|byte| !byte.is_ascii_digit())
            .map_or(bytes.len(), |offset| index + offset);
        if let Ok(line) = json[index..number_end].parse() {
            lines.insert(line);
        }
        index = number_end;
    }
    lines
}

/// Returns source lines attributable to one error-level rustc compiler message.
pub(super) fn compiler_error_lines(json: &str) -> Option<HashSet<usize>> {
    if string(field(json, "reason")?)? != "compiler-message" {
        return None;
    }
    let message = field(json, "message")?;
    if string(field(message, "level")?)? != "error" {
        return None;
    }
    Some(line_starts(field(message, "spans")?))
}
