use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
use once_cell::sync::Lazy;
use rand::Rng;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde_json::{json, Value};
use sha2::{Digest, Sha256, Sha512};
use std::process;

// ---- Required configuration ----
const APPLICATION_TOKEN: &str = "application_token_here";
const APPLICATION_SECRET: &str = "application_secret_here";
const APPLICATION_VERSION: &str = "application_version_here";

const API_URL: &str = "https://eauth.us.to/api/1.3/";
 
// ---- Advanced configuration (response messages) ----
const INVALID_REQUEST_MESSAGE: &str = "Invalid request!";
const OUTDATED_VERSION_MESSAGE: &str = "Outdated version, please upgrade!";
const BUSY_SESSIONS_MESSAGE: &str = "Please try again later!";
const UNAVAILABLE_SESSION_MESSAGE: &str = "Invalid session. Please re-launch the app!";
const USED_SESSION_MESSAGE: &str = "Why did the computer go to therapy? Because it had a case of 'Request Repeatitis' and couldn't stop asking for the same thing over and over again!";
const OVERCROWDED_SESSION_MESSAGE: &str = "Session limit exceeded. Please re-launch the app!";
const EXPIRED_SESSION_MESSAGE: &str = "Your session has timed out. Please re-launch the app!";
const INVALID_USER_MESSAGE: &str = "Incorrect login credentials!";
const BANNED_USER_MESSAGE: &str = "Access denied!";
const INCORRECT_HWID_MESSAGE: &str = "Hardware ID mismatch. Please try again with the correct device!";
#[allow(dead_code)]
const EXPIRED_USER_MESSAGE: &str = "Your subscription has ended. Please renew to continue using our service!";
const USED_NAME_MESSAGE: &str = "Username already taken. Please choose a different username!";
const INVALID_KEY_MESSAGE: &str = "Invalid key. Please enter a valid key!";
const UPGRADE_YOUR_EAUTH_MESSAGE: &str = "Upgrade your Eauth plan to exceed the limits!";
#[allow(dead_code)]
const COOLDOWN_HWID_MESSAGE: &str = "You have not yet reached your reset cool down, please try again later.";
#[allow(dead_code)]
const INVALID_USER_HWID_MESSAGE: &str = "The user either has a null HWID or is unavailable.";
 
const PUBLIC_KEY_PEM: &str = "-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAn2rh1JxHmjlu2UhR80g1
issihSD2Xuf5Pevlu0ZfRqFkgfdSxCyDwguNo9oTSG+wArktK7QJ0Xao+dsgg1vB
c7/mF/S+cdiCl8Gg8RTDvHZObqnoPQy8KgaqzilT5KMLp/1r5meky1bRmhFn3F17
Zkt3VQvM6T+99AMA6l/nDc0U8Xc1UvX9WrnR4UoBYWtO19/UaP/Z0zsFiSlu9iXP
QotGlL14gQvyByXE2icMR198/dj+wLV9Kirb17KuJtxQo9IHbVAPX3YZ72NPkDR0
hlATbgwXoLsvy1Jp3LLSV/kUWkWgQgcHp2WXNycpgVJDmfmna+mq0nhDSdCRoBl9
slU1xvBZTya/IAt5SqfazM/b0xM/uleXISx+oHjRIRM8Se26OByUl6Rtjkg/uSxj
Jk5ljAR0WjmC4fHD7fLEVbKG8SdQxHN5fb565hh8LlwG1ER6SaxmpmK2N5JC+FLQ
ihCJVDllLU5AwppZbv4PKUMprjNxZO41cKCcNUBxTX442k8HcXDqoRM2icjb4X35
SGie3lIw+WvEOr5Hr0vhoQnAwree2BnqMVZIjH34L5vObeToeTnUwXKJ9o7fGRhI
9P00gyzsFHQgiMKOygioj9NdobtPIPahcStagR9PQLR117Fhyx2R9RSZESZB4pIY
FtlOd7spqVctsJWnfVo9ai0CAwEAAQ==
-----END PUBLIC KEY-----";
 
static PUBLIC_KEY: Lazy<RsaPublicKey> =
    Lazy::new(|| RsaPublicKey::from_public_key_pem(PUBLIC_KEY_PEM).expect("invalid embedded public key"));
 
fn compute_sha512_hex(input: &str) -> String {
    let mut hasher = Sha512::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize())
}
 
fn generate_eauth_header(message: &str, app_secret: &str) -> String {
    let auth_token = format!("{app_secret}{message}");
    compute_sha512_hex(&auth_token)
}
 
fn generate_random_string(length: usize) -> String {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::thread_rng();
    (0..length)
        .map(|_| {
            let idx = rng.gen_range(0..CHARS.len());
            CHARS[idx] as char
        })
        .collect()
}
 
/// Resolve a hardware id the same way the Python client does:
/// - Windows: string SID of the current logged-in user
/// - Linux: contents of /etc/machine-id
#[cfg(target_os = "windows")]
fn get_hwid() -> String {
    use windows::core::PWSTR;
    use windows::Win32::Foundation::LocalFree;
    use windows::Win32::Security::Authorization::ConvertSidToStringSidW;
    use windows::Win32::Security::{LookupAccountNameW, PSID, SID_NAME_USE};
 
    unsafe {
        let username = whoami_username();
        let mut wide_username: Vec<u16> = username.encode_utf16().chain(std::iter::once(0)).collect();
 
        let mut sid_buf: Vec<u8> = vec![0u8; 256];
        let mut sid_size: u32 = sid_buf.len() as u32;
        let mut domain_buf: Vec<u16> = vec![0u16; 256];
        let mut domain_size: u32 = domain_buf.len() as u32;
        let mut sid_use = SID_NAME_USE(0);
 
        let psid = PSID(sid_buf.as_mut_ptr() as *mut _);
 
        let ok = LookupAccountNameW(
            None,
            windows::core::PCWSTR(wide_username.as_mut_ptr()),
            psid,
            &mut sid_size,
            windows::core::PWSTR(domain_buf.as_mut_ptr()),
            &mut domain_size,
            &mut sid_use,
        );
 
        if ok.is_err() {
            eprintln!("Failed to look up account SID");
            process::exit(1);
        }
 
        let mut string_sid = PWSTR::null();
        if ConvertSidToStringSidW(psid, &mut string_sid).is_err() {
            eprintln!("Failed to convert SID to string");
            process::exit(1);
        }
 
        let result = string_sid.to_string().unwrap_or_default();
        let _ = LocalFree(windows::Win32::Foundation::HLOCAL(string_sid.0 as *mut _));
        result
    }
}
 
#[cfg(target_os = "windows")]
fn whoami_username() -> String {
    // Equivalent of Python's os.getlogin()
    std::env::var("USERNAME").unwrap_or_default()
}
 
#[cfg(target_os = "linux")]
fn get_hwid() -> String {
    std::fs::read_to_string("/etc/machine-id")
        .unwrap_or_default()
        .trim()
        .to_string()
}
 
#[cfg(not(any(target_os = "windows", target_os = "linux")))]
fn get_hwid() -> String {
    eprintln!("HWID resolution is only implemented for Windows and Linux");
    process::exit(1);
}
 
#[allow(dead_code)]
pub struct EauthClient {
    http: reqwest::blocking::Client,
    pub user_hwid: String,
 
    pub init: bool,
    pub login: bool,
    pub register: bool,
 
    pub session_id: String,
    pub error_message: String,
 
    pub rank: String,
    pub register_date: String,
    pub expire_date: String,
    pub hwid: String,
}
 
#[allow(dead_code)]
impl EauthClient {
    pub fn new() -> Self {
        Self {
            http: reqwest::blocking::Client::new(),
            user_hwid: get_hwid(),
            init: false,
            login: false,
            register: false,
            session_id: String::new(),
            error_message: String::new(),
            rank: String::new(),
            register_date: String::new(),
            expire_date: String::new(),
            hwid: String::new(),
        }
    }
 
    fn raise_error(&mut self, error: &str) {
        self.error_message = error.to_string();
    }
 
    /// Sends a signed request to Eauth and verifies the response signature,
    /// mirroring run_request() in the Python client.
    fn run_request(&self, request_data: &str) -> Value {
        let signature = generate_eauth_header(request_data, APPLICATION_SECRET);
 
        let response = self
            .http
            .post(API_URL)
            .header("Content-Type", "application/json")
            .header("User-Agent", &signature)
            .body(request_data.to_string())
            .send()
            .unwrap_or_else(|e| {
                eprintln!("Request failed: {e}");
                process::exit(1);
            });
 
        let signature_header = response
            .headers()
            .get("Signature")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
 
        let body_text = response.text().unwrap_or_default();
        let res: Value = serde_json::from_str(&body_text).unwrap_or_else(|e| {
            eprintln!("Failed to parse response JSON: {e}");
            process::exit(1);
        });
 
        let message = res["message"].as_str().unwrap_or_default();
 
        let skip_verification = matches!(
            message,
            "invalid_request" | "session_unavailable" | "session_already_used" | "invalid_email"
        );
 
        if !skip_verification {
            let sig_b64 = signature_header.unwrap_or_else(|| {
                eprintln!("Missing Signature header");
                process::exit(1);
            });
 
            let sig_bytes = B64.decode(sig_b64).unwrap_or_else(|_| {
                eprintln!("Invalid Signature header encoding");
                process::exit(1);
            });
 
            let expected = generate_eauth_header(&format!("{message}{body_text}"), APPLICATION_SECRET);
            let verifying_key = VerifyingKey::<Sha256>::new((*PUBLIC_KEY).clone());
            let sig = Signature::try_from(sig_bytes.as_slice()).unwrap_or_else(|_| {
                eprintln!("Malformed signature");
                process::exit(1);
            });
 
            if verifying_key.verify(expected.as_bytes(), &sig).is_err() {
                process::exit(1);
            }
 
            if res["pair"].as_str() != Some(signature.as_str()) {
                process::exit(1);
            }
        }
 
        res
    }
 
    /// Eauth init request
    pub fn init_request(&mut self) -> bool {
        if self.init {
            return self.init;
        }
 
        let data = json!({
            "type": "init",
            "token": APPLICATION_TOKEN,
            "hwid": self.user_hwid,
            "version": APPLICATION_VERSION,
            "pair": generate_random_string(18),
        });
 
        let res = self.run_request(&data.to_string());
        let message = res["message"].as_str().unwrap_or_default();
 
        match message {
            "init_success" => {
                self.init = true;
                self.session_id = res["session_id"].as_str().unwrap_or_default().to_string();
            }
            "invalid_request" => self.raise_error(INVALID_REQUEST_MESSAGE),
            "version_outdated" => {
                let download_link = res["download_link"].as_str().unwrap_or_default();
                if !download_link.is_empty() {
                    let _ = webbrowser_open(download_link);
                }
                self.raise_error(OUTDATED_VERSION_MESSAGE);
            }
            "maximum_sessions_reached" => self.raise_error(BUSY_SESSIONS_MESSAGE),
            "user_is_banned" => self.raise_error(BANNED_USER_MESSAGE),
            "init_paused" => {
                let paused = res["paused_message"].as_str().unwrap_or_default().to_string();
                self.raise_error(&paused);
            }
            _ => {}
        }
 
        self.init
    }
 
    /// Eauth login request
    pub fn login_request(&mut self, username: &str, password: &str) -> bool {
        if self.login {
            return self.login;
        }
 
        let data = json!({
            "type": "login",
            "session_id": self.session_id,
            "username": username,
            "password": password,
            "hwid": self.user_hwid,
            "pair": generate_random_string(18),
        });
 
        let res = self.run_request(&data.to_string());
        let message = res["message"].as_str().unwrap_or_default();
 
        match message {
            "login_success" => {
                self.login = true;
                self.rank = res["rank"].as_str().unwrap_or_default().to_string();
                self.register_date = res["register_date"].as_str().unwrap_or_default().to_string();
                self.expire_date = res["expire_date"].as_str().unwrap_or_default().to_string();
                self.hwid = res["hwid"].as_str().unwrap_or_default().to_string();
            }
            "invalid_request" => self.raise_error(INVALID_REQUEST_MESSAGE),
            "session_unavailable" => self.raise_error(UNAVAILABLE_SESSION_MESSAGE),
            "session_already_used" => self.raise_error(USED_SESSION_MESSAGE),
            "session_overcrowded" => self.raise_error(OVERCROWDED_SESSION_MESSAGE),
            "session_expired" => self.raise_error(EXPIRED_SESSION_MESSAGE),
            "account_unavailable" => self.raise_error(INVALID_USER_MESSAGE),
            "user_is_banned" => self.raise_error(BANNED_USER_MESSAGE),
            "hwid_incorrect" => self.raise_error(INCORRECT_HWID_MESSAGE),
            "subscription_expired" => self.raise_error(EXPIRED_SESSION_MESSAGE),
            _ => {}
        }
 
        self.login
    }
 
    /// Eauth register request
    pub fn register_request(&mut self, username: &str, password: &str, key: &str) -> bool {
        if self.register {
            return self.register;
        }
 
        let data = json!({
            "type": "register",
            "session_id": self.session_id,
            "username": username,
            "password": password,
            "key": key,
            "hwid": self.user_hwid,
            "pair": generate_random_string(18),
        });
 
        let res = self.run_request(&data.to_string());
        let message = res["message"].as_str().unwrap_or_default();
 
        match message {
            "register_success" => self.register = true,
            "invalid_request" => self.raise_error(INVALID_REQUEST_MESSAGE),
            "session_unavailable" => self.raise_error(UNAVAILABLE_SESSION_MESSAGE),
            "session_already_used" => self.raise_error(USED_SESSION_MESSAGE),
            "session_overcrowded" => self.raise_error(OVERCROWDED_SESSION_MESSAGE),
            "session_expired" => self.raise_error(EXPIRED_SESSION_MESSAGE),
            "account_unavailable" => self.raise_error(INVALID_USER_MESSAGE),
            "name_already_used" => self.raise_error(USED_NAME_MESSAGE),
            "key_unavailable" => self.raise_error(INVALID_KEY_MESSAGE),
            "user_is_banned" => self.raise_error(BANNED_USER_MESSAGE),
            "maximum_users_reached" => self.raise_error(UPGRADE_YOUR_EAUTH_MESSAGE),
            _ => {}
        }
 
        self.register
    }
 
    /// Eauth reset HWID request
    pub fn hardware_reset_request(&mut self, username: &str) -> bool {
        let data = json!({
            "type": "hardware_reset",
            "session_id": self.session_id,
            "username": username,
            "pair": generate_random_string(18),
        });
 
        let res = self.run_request(&data.to_string());
        let message = res["message"].as_str().unwrap_or_default();
 
        match message {
            "reset_success" => return true,
            "invalid_request" => self.raise_error(INVALID_REQUEST_MESSAGE),
            "session_unavailable" => self.raise_error(UNAVAILABLE_SESSION_MESSAGE),
            "session_expired" => self.raise_error(EXPIRED_SESSION_MESSAGE),
            "invalid_user" => self.raise_error(INVALID_USER_HWID_MESSAGE),
            "cooldown_not_reached" => {
                let eta = res["estimated_reset_time"].as_str().unwrap_or_default();
                self.raise_error(&format!("{COOLDOWN_HWID_MESSAGE} @ {eta}"));
            }
            _ => {}
        }
 
        false
    }
 
    /// Check the session
    pub fn auth_monitor(&self) -> bool {
        let data = json!({
            "type": "auth_monitor",
            "session_id": self.session_id,
            "pair": generate_random_string(18),
        });
 
        let res = self.run_request(&data.to_string());
        res["message"].as_str() == Some("up")
    }
 
    /// Check the user
    pub fn user_monitor(&self, username: &str) -> bool {
        let data = json!({
            "type": "auth_monitor",
            "session_id": self.session_id,
            "username": username,
            "pair": generate_random_string(18),
        });
 
        let res = self.run_request(&data.to_string());
        res["message"].as_str() == Some("up")
    }
}
 
fn webbrowser_open(url: &str) -> std::io::Result<std::process::Child> {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd").args(["/C", "start", "", url]).spawn()
    }
    #[cfg(target_os = "linux")]
    {
        std::process::Command::new("xdg-open").arg(url).spawn()
    }
    #[cfg(not(any(target_os = "windows", target_os = "linux")))]
    {
        std::process::Command::new("open").arg(url).spawn()
    }
}