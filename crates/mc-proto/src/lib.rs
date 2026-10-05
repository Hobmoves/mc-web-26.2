//! Minecraft: Java Edition wire-protocol primitives.
//!
//! Written from the public protocol documentation; contains no Mojang code.
//! Pure `std`, so it compiles unchanged for native and `wasm32`.

use std::fmt;

/// Game version this crate targets.
pub const GAME_VERSION: &str = "26.2";
/// Protocol version number for [`GAME_VERSION`] (from the release's `version.json`).
pub const PROTOCOL_VERSION: i32 = 776;

/// `next_state` values for the handshake packet.
pub const STATE_STATUS: i32 = 1;
pub const STATE_LOGIN: i32 = 2;

const MAX_VARINT_BYTES: usize = 5;
/// Packets are limited to 2^21 - 1 bytes (3-byte VarInt length prefix).
pub const MAX_PACKET_LEN: usize = 2_097_151;

#[derive(Debug, PartialEq, Eq)]
pub enum ProtoError {
    VarIntTooLong,
    BadLength(i32),
    PacketTooLarge(usize),
    InvalidUtf8,
    UnexpectedEof,
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VarIntTooLong => write!(f, "VarInt longer than 5 bytes"),
            Self::BadLength(n) => write!(f, "invalid length {n}"),
            Self::PacketTooLarge(n) => write!(f, "packet of {n} bytes exceeds limit"),
            Self::InvalidUtf8 => write!(f, "string is not valid UTF-8"),
            Self::UnexpectedEof => write!(f, "unexpected end of packet"),
        }
    }
}

impl std::error::Error for ProtoError {}

pub fn write_varint(buf: &mut Vec<u8>, value: i32) {
    let mut v = value as u32;
    loop {
        if v & !0x7F == 0 {
            buf.push(v as u8);
            return;
        }
        buf.push((v & 0x7F) as u8 | 0x80);
        v >>= 7;
    }
}

/// Reads a VarInt. `Ok(None)` means more bytes are needed.
pub fn read_varint(buf: &[u8]) -> Result<Option<(i32, usize)>, ProtoError> {
    let mut value: u32 = 0;
    for (i, &b) in buf.iter().enumerate() {
        if i >= MAX_VARINT_BYTES {
            return Err(ProtoError::VarIntTooLong);
        }
        value |= u32::from(b & 0x7F) << (7 * i);
        if b & 0x80 == 0 {
            return Ok(Some((value as i32, i + 1)));
        }
    }
    if buf.len() >= MAX_VARINT_BYTES {
        return Err(ProtoError::VarIntTooLong);
    }
    Ok(None)
}

pub fn write_string(buf: &mut Vec<u8>, s: &str) {
    write_varint(buf, s.len() as i32);
    buf.extend_from_slice(s.as_bytes());
}

pub fn read_string(buf: &[u8]) -> Result<(String, usize), ProtoError> {
    let (len, n) = read_varint(buf)?.ok_or(ProtoError::UnexpectedEof)?;
    if len < 0 {
        return Err(ProtoError::BadLength(len));
    }
    let end = n + len as usize;
    let bytes = buf.get(n..end).ok_or(ProtoError::UnexpectedEof)?;
    let s = std::str::from_utf8(bytes).map_err(|_| ProtoError::InvalidUtf8)?;
    Ok((s.to_owned(), end))
}

/// Wraps `payload` as an uncompressed packet: `VarInt(len) | VarInt(id) | payload`.
pub fn frame(packet_id: i32, payload: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(payload.len() + 5);
    write_varint(&mut body, packet_id);
    body.extend_from_slice(payload);
    let mut out = Vec::with_capacity(body.len() + 3);
    write_varint(&mut out, body.len() as i32);
    out.extend_from_slice(&body);
    out
}

/// A decoded uncompressed packet.
#[derive(Debug, PartialEq, Eq)]
pub struct Packet {
    pub id: i32,
    pub payload: Vec<u8>,
}

/// Tries to split one packet off the front of `buf`.
/// Returns the packet and the number of bytes consumed, or `None` if incomplete.
pub fn parse_frame(buf: &[u8]) -> Result<Option<(Packet, usize)>, ProtoError> {
    let Some((len, n)) = read_varint(buf)? else {
        return Ok(None);
    };
    if len < 0 {
        return Err(ProtoError::BadLength(len));
    }
    let len = len as usize;
    if len > MAX_PACKET_LEN {
        return Err(ProtoError::PacketTooLarge(len));
    }
    let Some(body) = buf.get(n..n + len) else {
        return Ok(None);
    };
    let (id, idn) = read_varint(body)?.ok_or(ProtoError::UnexpectedEof)?;
    Ok(Some((
        Packet {
            id,
            payload: body[idn..].to_vec(),
        },
        n + len,
    )))
}

/// Serverbound handshake (id 0x00 in the handshake state).
pub fn handshake(protocol: i32, host: &str, port: u16, next_state: i32) -> Vec<u8> {
    let mut p = Vec::new();
    write_varint(&mut p, protocol);
    write_string(&mut p, host);
    p.extend_from_slice(&port.to_be_bytes());
    write_varint(&mut p, next_state);
    frame(0x00, &p)
}

/// Serverbound status request (id 0x00 in the status state, empty payload).
pub fn status_request() -> Vec<u8> {
    frame(0x00, &[])
}

/// Serverbound ping request (id 0x01, one i64).
pub fn ping_request(nonce: i64) -> Vec<u8> {
    frame(0x01, &nonce.to_be_bytes())
}

/// Extracts the JSON string from a clientbound status response packet.
pub fn parse_status_response(packet: &Packet) -> Result<String, ProtoError> {
    if packet.id != 0x00 {
        return Err(ProtoError::BadLength(packet.id));
    }
    Ok(read_string(&packet.payload)?.0)
}

/// Incremental parser for a byte stream arriving in arbitrary chunks.
#[derive(Default)]
pub struct StreamParser {
    buf: Vec<u8>,
}

impl StreamParser {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    pub fn next_packet(&mut self) -> Result<Option<Packet>, ProtoError> {
        match parse_frame(&self.buf)? {
            Some((pkt, used)) => {
                self.buf.drain(..used);
                Ok(Some(pkt))
            }
            None => Ok(None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_known_vectors() {
        // Vectors from the protocol documentation.
        let cases: &[(i32, &[u8])] = &[
            (0, &[0x00]),
            (1, &[0x01]),
            (127, &[0x7f]),
            (128, &[0x80, 0x01]),
            (255, &[0xff, 0x01]),
            (25565, &[0xdd, 0xc7, 0x01]),
            (2097151, &[0xff, 0xff, 0x7f]),
            (i32::MAX, &[0xff, 0xff, 0xff, 0xff, 0x07]),
            (-1, &[0xff, 0xff, 0xff, 0xff, 0x0f]),
            (i32::MIN, &[0x80, 0x80, 0x80, 0x80, 0x08]),
        ];
        for &(v, bytes) in cases {
            let mut out = Vec::new();
            write_varint(&mut out, v);
            assert_eq!(out, bytes, "encode {v}");
            assert_eq!(read_varint(bytes).unwrap(), Some((v, bytes.len())), "decode {v}");
        }
    }

    #[test]
    fn varint_incomplete_and_overlong() {
        assert_eq!(read_varint(&[0x80]).unwrap(), None);
        assert_eq!(read_varint(&[]).unwrap(), None);
        assert_eq!(
            read_varint(&[0x80, 0x80, 0x80, 0x80, 0x80, 0x01]),
            Err(ProtoError::VarIntTooLong)
        );
        assert_eq!(
            read_varint(&[0x80, 0x80, 0x80, 0x80, 0x80]),
            Err(ProtoError::VarIntTooLong)
        );
    }

    #[test]
    fn handshake_layout() {
        let pkt = handshake(PROTOCOL_VERSION, "localhost", 25565, STATE_STATUS);
        let (parsed, used) = parse_frame(&pkt).unwrap().unwrap();
        assert_eq!(used, pkt.len());
        assert_eq!(parsed.id, 0x00);
        let (proto, n) = read_varint(&parsed.payload).unwrap().unwrap();
        assert_eq!(proto, 776);
        let (host, m) = read_string(&parsed.payload[n..]).unwrap();
        assert_eq!(host, "localhost");
        let rest = &parsed.payload[n + m..];
        assert_eq!(&rest[..2], &25565u16.to_be_bytes());
        assert_eq!(rest[2], STATE_STATUS as u8);
    }

    #[test]
    fn stream_parser_handles_split_chunks() {
        let json = r#"{"version":{"name":"26.2","protocol":776}}"#;
        let mut payload = Vec::new();
        write_string(&mut payload, json);
        let wire = frame(0x00, &payload);

        let mut p = StreamParser::default();
        for b in &wire[..wire.len() - 1] {
            p.push(&[*b]);
            assert_eq!(p.next_packet().unwrap(), None);
        }
        p.push(&wire[wire.len() - 1..]);
        let pkt = p.next_packet().unwrap().unwrap();
        assert_eq!(parse_status_response(&pkt).unwrap(), json);
        assert_eq!(p.next_packet().unwrap(), None);
    }

    #[test]
    fn rejects_oversized_and_negative_lengths() {
        let mut buf = Vec::new();
        write_varint(&mut buf, (MAX_PACKET_LEN + 1) as i32);
        assert!(matches!(parse_frame(&buf), Err(ProtoError::PacketTooLarge(_))));
        let mut neg = Vec::new();
        write_varint(&mut neg, -5);
        assert!(matches!(parse_frame(&neg), Err(ProtoError::BadLength(-5))));
    }
}
