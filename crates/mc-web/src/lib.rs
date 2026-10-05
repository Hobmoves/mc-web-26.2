//! WASM entry points. JS owns the WebSocket; Rust owns protocol encoding/decoding.

use mc_proto::{Packet, StreamParser};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn game_version() -> String {
    mc_proto::GAME_VERSION.to_owned()
}

#[wasm_bindgen]
pub fn protocol_version() -> i32 {
    mc_proto::PROTOCOL_VERSION
}

/// Handshake(status) + status request, ready to send as one binary frame.
#[wasm_bindgen]
pub fn status_handshake(host: &str, port: u16) -> Vec<u8> {
    let mut out = mc_proto::handshake(mc_proto::PROTOCOL_VERSION, host, port, mc_proto::STATE_STATUS);
    out.extend_from_slice(&mc_proto::status_request());
    out
}

/// Feeds server bytes in; yields the status JSON once the response is complete.
#[wasm_bindgen]
#[derive(Default)]
pub struct StatusReader {
    parser: StreamParser,
}

#[wasm_bindgen]
impl StatusReader {
    #[wasm_bindgen(constructor)]
    pub fn new() -> StatusReader {
        StatusReader::default()
    }

    /// Returns the JSON string when the status response has fully arrived,
    /// `undefined` while more data is needed. Throws on protocol errors.
    pub fn push(&mut self, bytes: &[u8]) -> Result<Option<String>, JsError> {
        self.parser.push(bytes);
        match self.parser.next_packet().map_err(|e| JsError::new(&e.to_string()))? {
            Some(Packet { id: 0x00, payload }) => {
                let pkt = Packet { id: 0x00, payload };
                Ok(Some(mc_proto::parse_status_response(&pkt).map_err(|e| JsError::new(&e.to_string()))?))
            }
            Some(p) => Err(JsError::new(&format!("unexpected packet id {:#x}", p.id))),
            None => Ok(None),
        }
    }
}
