//! Microsoft device-code login -> Xbox Live -> XSTS -> Minecraft services,
//! followed by an ownership check against the Minecraft entitlements API.
//!
//! The Minecraft access token never leaves the server; the browser only gets
//! an opaque session id.

use crate::error::AppError;
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const DEVICE_CODE_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/devicecode";
const TOKEN_URL: &str = "https://login.microsoftonline.com/consumers/oauth2/v2.0/token";
const XBL_URL: &str = "https://user.auth.xboxlive.com/user/authenticate";
const XSTS_URL: &str = "https://xsts.auth.xboxlive.com/xsts/authorize";
const MC_LOGIN_URL: &str = "https://api.minecraftservices.com/authentication/login_with_xbox";
const MC_ENTITLEMENTS_URL: &str = "https://api.minecraftservices.com/entitlements/mcstore";
const MC_PROFILE_URL: &str = "https://api.minecraftservices.com/minecraft/profile";
const SESSION_JOIN_URL: &str = "https://sessionserver.mojang.com/session/minecraft/join";
const SCOPE: &str = "XboxLive.signin offline_access";

#[derive(Clone)]
pub struct Session {
    pub name: String,
    pub uuid: String,
    pub owns_java: bool,
    mc_token: String,
    expires_at: Instant,
}

#[derive(Clone, Default)]
pub struct Sessions(Arc<Mutex<HashMap<String, Session>>>);

impl Sessions {
    pub fn insert(&self, s: Session) -> String {
        let id = format!("{:032x}{:032x}", rand::random::<u128>(), rand::random::<u128>());
        let mut map = self.0.lock().unwrap();
        map.retain(|_, v| v.expires_at > Instant::now());
        map.insert(id.clone(), s);
        id
    }

    pub fn get(&self, id: &str) -> Option<Session> {
        let map = self.0.lock().unwrap();
        map.get(id).filter(|s| s.expires_at > Instant::now()).cloned()
    }

    /// A session that is allowed to open game connections.
    pub fn get_owner(&self, id: &str) -> Result<Session, AppError> {
        let s = self
            .get(id)
            .ok_or_else(|| AppError::new(StatusCode::UNAUTHORIZED, "not signed in or session expired"))?;
        if !s.owns_java {
            return Err(AppError::new(
                StatusCode::FORBIDDEN,
                "this Microsoft account does not own Minecraft: Java Edition",
            ));
        }
        Ok(s)
    }
}

#[derive(Serialize)]
pub struct DeviceStart {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in: u64,
    pub interval: u64,
}

pub async fn device_start(http: &reqwest::Client, client_id: &str) -> Result<DeviceStart, AppError> {
    #[derive(Deserialize)]
    struct Resp {
        device_code: String,
        user_code: String,
        verification_uri: String,
        expires_in: u64,
        interval: u64,
    }
    let r = http
        .post(DEVICE_CODE_URL)
        .form(&[("client_id", client_id), ("scope", SCOPE)])
        .send()
        .await?;
    if !r.status().is_success() {
        let body = r.text().await.unwrap_or_default();
        return Err(AppError::upstream(format!("Microsoft device-code request failed: {body}")));
    }
    let r: Resp = r.json().await?;
    Ok(DeviceStart {
        device_code: r.device_code,
        user_code: r.user_code,
        verification_uri: r.verification_uri,
        expires_in: r.expires_in,
        interval: r.interval,
    })
}

pub enum Poll {
    Pending,
    SlowDown,
    Done(Session),
}

pub async fn device_poll(
    http: &reqwest::Client,
    client_id: &str,
    device_code: &str,
) -> Result<Poll, AppError> {
    let r = http
        .post(TOKEN_URL)
        .form(&[
            ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ("client_id", client_id),
            ("device_code", device_code),
        ])
        .send()
        .await?;
    let ok = r.status().is_success();
    let body: serde_json::Value = r.json().await?;
    if !ok {
        return match body["error"].as_str() {
            Some("authorization_pending") => Ok(Poll::Pending),
            Some("slow_down") => Ok(Poll::SlowDown),
            Some("authorization_declined") => Err(AppError::new(StatusCode::FORBIDDEN, "sign-in was declined")),
            Some("expired_token") | Some("bad_verification_code") => {
                Err(AppError::new(StatusCode::GONE, "the sign-in code expired, start again"))
            }
            _ => Err(AppError::upstream(format!("Microsoft token error: {body}"))),
        };
    }
    let ms_token = body["access_token"]
        .as_str()
        .ok_or_else(|| AppError::upstream("Microsoft response had no access_token"))?;
    Ok(Poll::Done(minecraft_session(http, ms_token).await?))
}

async fn minecraft_session(http: &reqwest::Client, ms_token: &str) -> Result<Session, AppError> {
    // 1. Xbox Live user token
    let xbl: serde_json::Value = http
        .post(XBL_URL)
        .header("x-xbl-contract-version", "1")
        .json(&json!({
            "Properties": {
                "AuthMethod": "RPS",
                "SiteName": "user.auth.xboxlive.com",
                "RpsTicket": format!("d={ms_token}"),
            },
            "RelyingParty": "http://auth.xboxlive.com",
            "TokenType": "JWT",
        }))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let xbl_token = xbl["Token"].as_str().ok_or_else(|| AppError::upstream("XBL: no Token"))?;

    // 2. XSTS token for the Minecraft relying party
    let r = http
        .post(XSTS_URL)
        .json(&json!({
            "Properties": { "SandboxId": "RETAIL", "UserTokens": [xbl_token] },
            "RelyingParty": "rp://api.minecraftservices.com/",
            "TokenType": "JWT",
        }))
        .send()
        .await?;
    if r.status() == StatusCode::UNAUTHORIZED {
        let body: serde_json::Value = r.json().await.unwrap_or_default();
        return Err(AppError::new(StatusCode::FORBIDDEN, xsts_message(body["XErr"].as_u64())));
    }
    let xsts: serde_json::Value = r.error_for_status()?.json().await?;
    let xsts_token = xsts["Token"].as_str().ok_or_else(|| AppError::upstream("XSTS: no Token"))?;
    let uhs = xsts["DisplayClaims"]["xui"][0]["uhs"]
        .as_str()
        .ok_or_else(|| AppError::upstream("XSTS: no uhs"))?;

    // 3. Minecraft services access token
    let r = http
        .post(MC_LOGIN_URL)
        .json(&json!({ "identityToken": format!("XBL3.0 x={uhs};{xsts_token}") }))
        .send()
        .await?;
    if !r.status().is_success() {
        let body = r.text().await.unwrap_or_default();
        return Err(AppError::upstream(format!(
            "Minecraft login rejected ({body}). The Azure app registration must be approved by Mojang \
             for the Minecraft API; see README."
        )));
    }
    let mc: serde_json::Value = r.json().await?;
    let mc_token = mc["access_token"]
        .as_str()
        .ok_or_else(|| AppError::upstream("Minecraft: no access_token"))?
        .to_owned();
    let ttl = mc["expires_in"].as_u64().unwrap_or(3600);

    // 4. Ownership: entitlements and profile
    let ent: serde_json::Value = http
        .get(MC_ENTITLEMENTS_URL)
        .bearer_auth(&mc_token)
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;
    let owns_java = ent["items"]
        .as_array()
        .map(|items| {
            items
                .iter()
                .any(|i| matches!(i["name"].as_str(), Some("game_minecraft") | Some("product_minecraft")))
        })
        .unwrap_or(false);

    let r = http.get(MC_PROFILE_URL).bearer_auth(&mc_token).send().await?;
    let (uuid, name) = if r.status() == StatusCode::NOT_FOUND {
        (String::new(), String::new())
    } else {
        let p: serde_json::Value = r.error_for_status()?.json().await?;
        (
            p["id"].as_str().unwrap_or_default().to_owned(),
            p["name"].as_str().unwrap_or_default().to_owned(),
        )
    };

    Ok(Session {
        // A profile is required to actually join servers.
        owns_java: owns_java && !uuid.is_empty(),
        name,
        uuid,
        mc_token,
        expires_at: Instant::now() + Duration::from_secs(ttl.saturating_sub(60)),
    })
}

fn xsts_message(code: Option<u64>) -> &'static str {
    match code {
        Some(2148916233) => "this Microsoft account has no Xbox profile; create one at xbox.com first",
        Some(2148916235) => "Xbox Live is not available in your country/region",
        Some(2148916236) | Some(2148916237) => "this account needs adult verification on Xbox",
        Some(2148916238) => "this is a child account; add it to a Microsoft family group first",
        _ => "Xbox Live refused the sign-in",
    }
}

/// Tells Mojang's session server that this profile is joining `server_hash`
/// (the Minecraft-style SHA-1 hex digest computed by the client during login).
pub async fn join_server(http: &reqwest::Client, s: &Session, server_hash: &str) -> Result<(), AppError> {
    let r = http
        .post(SESSION_JOIN_URL)
        .json(&json!({
            "accessToken": s.mc_token,
            "selectedProfile": s.uuid,
            "serverId": server_hash,
        }))
        .send()
        .await?;
    if r.status() == StatusCode::NO_CONTENT || r.status().is_success() {
        Ok(())
    } else {
        Err(AppError::upstream(format!("session server rejected join: {}", r.status())))
    }
}
