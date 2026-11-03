//! boring-remote (v1.7 t04): Allow / Don't allow in the middle of the main window, not only in
//! the small connection window.
//!
//! The ask lives in the connection window's process (`--cm`), the main window is another process.
//! Three plain-text messages travel as `Data::UrlLink` over our own ipc:
//! - `ask` and `done`: connection window → main window, on `_boring_approval` (the main window
//!   listens; it is opened if it is not running);
//! - `answer`: main window → connection window, on `_cm` (the connection window's own listener,
//!   which hands it to its page; the page then runs its own Allow / Don't allow, so trust is
//!   granted exactly as a click there does).
//!
//! Formats match flutter/lib/desktop/kit/approval.dart.

use crate::ipc::{self, Data};
use hbb_common::{futures::StreamExt as _, log, tokio, ResultType};

pub const ASK: &str = "boring-approval-ask:";
pub const DONE: &str = "boring-approval-done:";
pub const ANSWER: &str = "boring-approval-answer:";
pub const POSTFIX: &str = "_boring_approval";
/// The page event both windows get.
pub const EVENT: &str = "boring_approval";

/// Sends one message to the other window. Blocking: call it off the UI thread.
pub fn send(msg: String) {
    if msg.starts_with(ANSWER) {
        if let Err(e) = post("_cm", msg) {
            log::warn!("approval answer did not reach the connection window: {e}");
        }
        return;
    }
    if !(msg.starts_with(ASK) || msg.starts_with(DONE)) {
        return;
    }
    if post(POSTFIX, msg.clone()).is_ok() || !msg.starts_with(ASK) {
        return;
    }
    // No main window running: open it, then ask again once it listens.
    log::info!("approval: opening the main window to ask there");
    if let Err(e) = crate::run_me(Vec::<&str>::new()) {
        log::warn!("approval: could not open the main window: {e}");
        return;
    }
    for _ in 0..60 {
        std::thread::sleep(std::time::Duration::from_millis(500));
        if post(POSTFIX, msg.clone()).is_ok() {
            return;
        }
    }
    log::warn!("approval: the main window never listened; the connection window still asks");
}

#[tokio::main(flavor = "current_thread")]
async fn post(postfix: &str, msg: String) -> ResultType<()> {
    ipc::connect(1_000, postfix).await?.send(&Data::UrlLink(msg)).await?;
    Ok(())
}

/// Hands a message to a page (the main window or the connection window) as a `boring_approval` event.
#[cfg(feature = "flutter")]
pub fn to_page(app_type: &str, msg: &str) {
    let event = serde_json::json!({ "name": EVENT, "msg": msg }).to_string();
    if crate::flutter::push_global_event(app_type, event).is_none() {
        log::warn!("approval: no {app_type} page to show it");
    }
}

/// The main window listens once, from its first event stream (flutter_ffi.rs).
#[cfg(feature = "flutter")]
pub fn listen_once() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        std::thread::spawn(listen);
    });
}

#[cfg(feature = "flutter")]
#[tokio::main(flavor = "current_thread")]
async fn listen() {
    let mut incoming = match ipc::new_listener(POSTFIX).await {
        Ok(i) => i,
        Err(e) => {
            log::error!("approval: main window cannot listen: {e}");
            return;
        }
    };
    while let Some(Ok(conn)) = incoming.next().await {
        let mut conn = ipc::Connection::new(conn);
        if let Ok(Some(Data::UrlLink(msg))) = conn.next_timeout(1000).await {
            if msg.starts_with(ASK) || msg.starts_with(DONE) {
                to_page(crate::flutter::APP_TYPE_MAIN, &msg);
            }
        }
    }
}
