//! Minimal hex helpers so the crate needs no extra dependency.

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim().trim_start_matches("0x");
    if s.len() % 2 != 0 {
        return Err(format!("odd-length hex string: {s}"));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).map_err(|e| format!("bad hex: {e}")))
        .collect()
}

pub fn unhex32(s: &str) -> Result<[u8; 32], String> {
    let v = unhex(s)?;
    v.try_into().map_err(|v: Vec<u8>| format!("expected 32 bytes, got {}", v.len()))
}
