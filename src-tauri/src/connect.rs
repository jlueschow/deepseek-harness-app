// P1: 连接模式 — 智能模式 / 显式连接。
//
// 已接入 lib.rs（connect_and_navigate / save_settings 使用本模块的类型与工具）。

use serde::{Deserialize, Serialize};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", content = "url", rename_all = "snake_case")]
pub enum ConnectTarget {
    /// 智能模式: 探测 127.0.0.1:3080 已有实例 → 复用; 否则自启 `dsh web --port 0`
    Smart,
    /// 显式连接: 直接导航到给定 URL（远程机器 / 容器 / 自行维护的实例）
    Explicit(String),
}

impl Default for ConnectTarget {
    fn default() -> Self {
        ConnectTarget::Smart
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppSettings {
    pub connect: ConnectTarget,
    pub autostart: bool,
    pub notifications_enabled: bool,
    /// 仅窗口未聚焦时弹通知（聚焦时不打扰）。
    #[serde(default = "default_true")]
    pub notify_only_unfocused: bool,
    /// 需要确认（用户问题 / 权限请求）。
    #[serde(default = "default_true")]
    pub notify_confirm: bool,
    /// 任务完成（回合结束）。
    #[serde(default = "default_false")]
    pub notify_turn_complete: bool,
    /// 出错报警（流错误 / agent 错误 / 服务退出）。
    #[serde(default = "default_true")]
    pub notify_errors: bool,
    /// 全局快捷键，默认 CmdOrCtrl+Shift+Space
    pub shortcut: String,
}

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
}

impl Default for AppSettings {
    fn default() -> Self {
        AppSettings {
            connect: ConnectTarget::Smart,
            autostart: false,
            notifications_enabled: true,
            notify_only_unfocused: true,
            notify_confirm: true,
            notify_turn_complete: false,
            notify_errors: true,
            shortcut: "CmdOrCtrl+Shift+Space".to_string(),
        }
    }
}

impl AppSettings {
    /// 设置文件位置: $DSH_APP_HOME/settings.json（默认 ~/.dsh-app/settings.json），
    /// 与官方 $DSH_HOME（~/.dsh）分离，桌面壳偏好不污染官方数据。
    pub fn path() -> PathBuf {
        if let Ok(home) = std::env::var("DSH_APP_HOME") {
            if !home.is_empty() {
                return PathBuf::from(home).join("settings.json");
            }
        }
        let base = std::env::var_os("USERPROFILE")
            .or_else(|| std::env::var_os("HOME"))
            .unwrap_or_default();
        PathBuf::from(base).join(".dsh-app").join("settings.json")
    }

    pub fn load() -> Self {
        let p = Self::path();
        match std::fs::read_to_string(&p) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_default(),
            Err(_) => Self::default(),
        }
    }

    pub fn save(&self) -> Result<(), String> {
        let p = Self::path();
        if let Some(dir) = p.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let raw = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        std::fs::write(&p, raw).map_err(|e| e.to_string())
    }
}

/// URL scheme 白名单: 只允许 http/https（loopback 或远程）。
pub fn sanitize_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
        Some(trimmed.to_string())
    } else {
        None
    }
}

/// 探测给定 URL 是否可达（TCP 连接）。
pub fn probe_url(url: &str) -> bool {
    let without_scheme = url
        .trim_start_matches("http://")
        .trim_start_matches("https://");
    // Only the authority (host:port) is a valid SocketAddr; drop everything
    // from the first '/' onward (path, query string). Explicit-connect URLs
    // routinely carry a "?token=..." auth token (the normal shape of every
    // dsh web ready line), so without this the parse below always fails and
    // every reachable explicit URL is reported as unreachable.
    let hostport = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme);
    match hostport.parse::<std::net::SocketAddr>() {
        Ok(addr) => TcpStream::connect_timeout(&addr, Duration::from_millis(1200)).is_ok(),
        Err(_) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_rejects_bad_schemes() {
        assert!(sanitize_url("file:///etc/passwd").is_none());
        assert!(sanitize_url("javascript:alert(1)").is_none());
        assert!(sanitize_url("").is_none());
        assert_eq!(sanitize_url("http://192.168.1.10:3080/"), Some("http://192.168.1.10:3080".to_string()));
    }

    #[test]
    fn settings_default_and_roundtrip() {
        let s = AppSettings::default();
        let raw = serde_json::to_string(&s).unwrap();
        let back: AppSettings = serde_json::from_str(&raw).unwrap();
        assert_eq!(back.connect, ConnectTarget::Smart);
    }

    #[test]
    fn probe_url_reaches_a_real_listener_despite_query_string() {
        // Regression test: every real "dsh web:" URL carries "?token=..."
        // (see lib.rs's own parse_port_from_url fix for the same class of
        // bug). probe_url used to try to parse the WHOLE remainder after
        // the scheme as a SocketAddr, so any path/query string made a
        // genuinely reachable server look unreachable.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let bare = format!("http://{addr}");
        let with_token = format!("http://{addr}/?token=abc123");
        let with_trailing_slash = format!("http://{addr}/");

        assert!(probe_url(&bare), "bare host:port must still work");
        assert!(probe_url(&with_token), "host:port with a query string must be reachable");
        assert!(probe_url(&with_trailing_slash), "host:port with a trailing slash must be reachable");

        drop(listener);
        assert!(!probe_url(&with_token), "closed port must be reported unreachable");
    }
}
