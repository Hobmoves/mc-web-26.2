# MC Web

A **clean-room** Minecraft: Java Edition client for the browser, written in Rust
(compiled to WebAssembly), targeting **Java 26.2 (protocol 776)**.

## Why not decompile and port the game?

Decompiling Mojang's jar and translating it to Rust produces a derivative of
Mojang's code. Hosting that publicly would violate the Minecraft EULA and
copyright, and a web build that runs without a purchase would be piracy. So this
project is written from the public protocol/format documentation, with no
Mojang code or assets in the repo. Textures, sounds and models must come from
the player's own purchased copy (planned: the user supplies their own client
jar locally in the browser; it is never uploaded or hosted).

## Layout

| crate | role |
|---|---|
| `crates/mc-proto` | Wire-protocol primitives (VarInt, framing, handshake, status). Pure `std`, native + wasm. |
| `crates/mc-web` | `wasm-bindgen` wrapper used by the page. |
| `crates/mc-proxy` | Axum server: Microsoft → Xbox → XSTS → Minecraft login, ownership check, Mojang session-join, WebSocket↔TCP bridge, static hosting of `web/`. |
| `web/` | The page. |

Browsers can't open raw TCP sockets, so game traffic goes browser → WebSocket →
`mc-proxy` → Java server. The Minecraft access token stays on the proxy; the
browser only holds an opaque session id.

## Run

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli        # must match the wasm-bindgen crate version
./build-web.sh
MS_CLIENT_ID=<your-azure-app-id> cargo run -p mc-proxy   # http://127.0.0.1:8080
cargo test
```

### Microsoft sign-in setup (required)

1. Register an app in Azure (Entra ID) → *Accounts in any org directory and personal Microsoft accounts*, enable **public client flows**.
2. **Mojang must approve your app ID** for the Minecraft services API
   (see the Minecraft Wiki "Microsoft authentication" page and Mojang's
   application form). Until approved, `login_with_xbox` returns an
   "Invalid app registration" error and sign-in will fail at the last step.
   Do not borrow another launcher's client id.
3. Set `MS_CLIENT_ID`.

Ownership is verified from `entitlements/mcstore` plus a Minecraft profile; only
verified owners can open bridge connections. `ALLOW_PRIVATE_TARGETS=1` lets the
bridge dial loopback/LAN (off by default to prevent SSRF).

## Status

Done: protocol primitives, device-code login, ownership check, session-join call,
SSRF-guarded bridge, server-status ping from the browser.

Not done (roadmap, in order):
1. Login state: encryption request → AES-128-CFB8 + RSA, compression, `join_server`.
2. Configuration state, registries, tags (needed before play).
3. Play state: chunk/section decoding, palettes, block-state registry.
4. WebGL2/WebGPU chunk mesher + renderer, camera, input.
5. Entities, inventory, chat, sounds, resource-pack loading from the user's own jar.
6. Protocol is moving each release: pin to 776 and regenerate packet tables with the data generator (`server.jar -DbundlerMainClass=net.minecraft.data.Main --reports`) for each update.
