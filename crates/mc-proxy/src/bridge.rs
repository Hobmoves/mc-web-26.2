//! WebSocket <-> TCP bridge. Browsers cannot open raw sockets, so the page
//! speaks the Minecraft protocol as binary WebSocket frames and this relays
//! the bytes to the target server.

use crate::error::AppError;
use axum::extract::ws::{Message, WebSocket};
use axum::http::StatusCode;
use futures_util::{SinkExt, StreamExt};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{lookup_host, TcpStream};

/// True for addresses that are safe to dial on behalf of an untrusted browser.
fn is_public(ip: IpAddr) -> bool {
    match ip.to_canonical() {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_multicast()
                || v4.is_documentation()
                || (o[0] == 100 && (o[1] & 0xC0) == 64) // CGNAT 100.64.0.0/10
                || o[0] == 0)
        }
        IpAddr::V6(v6) => {
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
    }
}

/// Resolves `host:port` and returns the first dialable address. The returned
/// address is what gets connected to, so DNS can't be swapped after the check.
pub async fn resolve_target(host: &str, port: u16, allow_private: bool) -> Result<SocketAddr, AppError> {
    if host.is_empty() || host.len() > 253 || port == 0 {
        return Err(AppError::new(StatusCode::BAD_REQUEST, "bad host or port"));
    }
    let addrs: Vec<SocketAddr> = lookup_host((host, port))
        .await
        .map_err(|_| AppError::new(StatusCode::BAD_GATEWAY, "could not resolve host"))?
        .collect();
    addrs
        .into_iter()
        .find(|a| allow_private || is_public(a.ip()))
        .ok_or_else(|| AppError::new(StatusCode::FORBIDDEN, "target address is not allowed"))
}

pub async fn pump(mut ws: WebSocket, target: SocketAddr) {
    let tcp = match tokio::time::timeout(Duration::from_secs(10), TcpStream::connect(target)).await {
        Ok(Ok(s)) => s,
        _ => {
            let _ = ws.close().await;
            return;
        }
    };
    let _ = tcp.set_nodelay(true);
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let (mut ws_tx, mut ws_rx) = ws.split();

    let up = async {
        while let Some(Ok(msg)) = ws_rx.next().await {
            match msg {
                Message::Binary(b) => {
                    if tcp_w.write_all(&b).await.is_err() {
                        break;
                    }
                }
                Message::Close(_) => break,
                _ => {}
            }
        }
        let _ = tcp_w.shutdown().await;
    };
    let down = async {
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match tcp_r.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if ws_tx.send(Message::Binary(buf[..n].to_vec().into())).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = ws_tx.close().await;
    };
    tokio::select! { _ = up => {}, _ = down => {} }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_internal_ranges() {
        for ip in [
            "127.0.0.1", "10.1.2.3", "192.168.0.5", "172.16.0.1", "169.254.169.254", "100.64.0.1",
            "0.0.0.0", "::1", "fd00::1", "fe80::1", "::ffff:127.0.0.1", "::ffff:10.0.0.1",
        ] {
            assert!(!is_public(ip.parse().unwrap()), "{ip} should be blocked");
        }
        for ip in ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"] {
            assert!(is_public(ip.parse().unwrap()), "{ip} should be allowed");
        }
    }

    #[tokio::test]
    async fn resolve_rejects_loopback_by_default() {
        assert!(resolve_target("127.0.0.1", 25565, false).await.is_err());
        assert!(resolve_target("127.0.0.1", 25565, true).await.is_ok());
        assert!(resolve_target("127.0.0.1", 0, true).await.is_err());
    }
}
