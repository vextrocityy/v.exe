//! Email account watch (Gmail).
//!
//! A takeover of someone's online accounts shows in their mailbox: "new
//! device" sign-ins, password resets they did not ask for, "your email was
//! changed". And the first thing an intruder does inside a mailbox is hide
//! those messages: a filter that deletes them, or a forwarding address.
//!
//! With the user's consent (Google OAuth, **read-only** scope) the engine
//! checks every few minutes:
//!   * new security-related messages, by sender and subject only (bodies are
//!     never fetched; the request asks Gmail for three headers);
//!   * the mailbox's filters, forwarding and send-as addresses against a stored
//!     baseline.
//!
//! Everything stays on this PC: the engine talks to Google directly. The
//! refresh token lives in the data folder (SYSTEM and administrators only).
//! It cannot send, delete or change anything, and the user can revoke it at
//! myaccount.google.com > Security > Third-party access.
//!
//! OAuth is the "installed app" flow: the dashboard listens on a loopback port
//! and opens the browser; the engine builds the consent URL (PKCE, S256) and
//! exchanges the code. The user supplies their own OAuth client id and secret
//! (a free Google Cloud project), so no shared credential ships in the binary.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;
use std::time::Duration;

pub const SCOPE: &str = "https://www.googleapis.com/auth/gmail.readonly";
const AUTH_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
const API_BASE: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

/// Seconds between mailbox checks.
pub const CHECK_SECS: i64 = 300;
/// How many message ids to remember as already reported.
const SEEN_CAP: usize = 2000;
/// Alerts from this many different services within [`BURST_WINDOW_SECS`] are
/// treated as one event: someone is working through a list of stolen logins.
const BURST_SERVICES: usize = 3;
const BURST_WINDOW_SECS: i64 = 3600;
const BURST_QUIET_SECS: i64 = 6 * 3600;

// ---------------------------------------------------------------------------
// Small encoders (no extra dependencies)
// ---------------------------------------------------------------------------

/// Percent-encode for a URL query or form value.
pub fn enc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// Base64url without padding (RFC 7636 code challenge).
pub fn b64url(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = match chunk.len() {
            3 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8 | chunk[2] as u32,
            2 => (chunk[0] as u32) << 16 | (chunk[1] as u32) << 8,
            _ => (chunk[0] as u32) << 16,
        };
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(T[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(T[n as usize & 63] as char);
        }
    }
    out
}

fn random_token() -> Result<String> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("no random numbers: {e}"))?;
    Ok(crate::engine::hasher::to_hex(&b))
}

// ---------------------------------------------------------------------------
// OAuth
// ---------------------------------------------------------------------------

/// Google OAuth client ids for desktop apps look like `<digits>-<chars>.apps.googleusercontent.com`.
pub fn valid_client_id(id: &str) -> bool {
    id.len() < 200
        && id.ends_with(".apps.googleusercontent.com")
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._".contains(&b))
}

/// The redirect must come back to this PC (the dashboard's one-shot listener).
pub fn valid_redirect(uri: &str) -> bool {
    crate::util::is_loopback_url(uri) && uri.len() < 100 && !uri.contains(['?', '#', ' '])
}

/// A consent request in progress: created by `begin`, consumed by `finish`.
#[derive(Debug, Clone)]
pub struct Pending {
    pub state: String,
    pub verifier: String,
    pub redirect_uri: String,
    pub started: std::time::Instant,
}

/// Start a consent request: returns what to remember and the URL to open.
pub fn begin(client_id: &str, redirect_uri: &str) -> Result<(Pending, String)> {
    anyhow::ensure!(valid_client_id(client_id), "the OAuth client ID in Settings is not a Google desktop client ID");
    anyhow::ensure!(valid_redirect(redirect_uri), "the sign-in must return to this PC");
    let pending = Pending {
        state: random_token()?,
        verifier: random_token()?,
        redirect_uri: redirect_uri.to_string(),
        started: std::time::Instant::now(),
    };
    let challenge = b64url(&Sha256::digest(pending.verifier.as_bytes()));
    let url = format!(
        "{AUTH_URL}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}\
         &code_challenge={challenge}&code_challenge_method=S256&access_type=offline&prompt=consent",
        enc(client_id),
        enc(redirect_uri),
        enc(SCOPE),
        pending.state,
    );
    Ok((pending, url))
}

/// Where the Google endpoints are (tests point these at a local fake).
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub token: String,
    pub api: String,
}

impl Default for Endpoints {
    fn default() -> Self {
        Self {
            token: TOKEN_URL.into(),
            api: API_BASE.into(),
        }
    }
}

fn agent(url: &str) -> ureq::Agent {
    ureq::AgentBuilder::new()
        .tls_config(super::update::tls_config())
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .user_agent(concat!("Vigil/", env!("CARGO_PKG_VERSION")))
        // Honour HTTPS_PROXY on managed networks, but never proxy a local test server.
        .try_proxy_from_env(!crate::util::is_loopback_url(url))
        .build()
}

/// Google's error text, without ever echoing a token or secret.
fn oauth_error(body: &str) -> String {
    let v: Value = serde_json::from_str(body).unwrap_or(Value::Null);
    let code = v["error"].as_str().or_else(|| v["error"]["status"].as_str()).unwrap_or("error");
    let desc = v["error_description"].as_str().or_else(|| v["error"]["message"].as_str()).unwrap_or("");
    format!("{code}{}{desc}", if desc.is_empty() { "" } else { ": " })
}

fn token_request(ep: &Endpoints, form: &[(&str, &str)]) -> Result<Value> {
    match agent(&ep.token).post(&ep.token).send_form(form) {
        Ok(r) => Ok(serde_json::from_str(&r.into_string()?)?),
        Err(ureq::Error::Status(_, r)) => {
            let msg = oauth_error(&r.into_string().unwrap_or_default());
            if msg.starts_with("invalid_grant") {
                bail!("Google no longer accepts Vigil's access (it expired or was revoked). Connect Gmail again.");
            }
            bail!("Google refused the sign-in ({msg})")
        }
        Err(e) => bail!("could not reach Google: {e}"),
    }
}

/// Trade the consent code for a refresh token (kept) and an access token.
pub fn exchange_code(
    ep: &Endpoints,
    client_id: &str,
    client_secret: &str,
    code: &str,
    pending: &Pending,
) -> Result<(String, String, u64)> {
    let v = token_request(
        ep,
        &[
            ("grant_type", "authorization_code"),
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", &pending.redirect_uri),
            ("code_verifier", &pending.verifier),
        ],
    )?;
    let refresh = v["refresh_token"]
        .as_str()
        .context("Google did not grant long-term access; remove Vigil under Third-party access in your Google account and connect again")?;
    let granted = v["scope"].as_str().unwrap_or(SCOPE);
    anyhow::ensure!(
        granted.split(' ').any(|s| s == SCOPE),
        "read access to Gmail was not ticked on Google's consent page"
    );
    let access = v["access_token"].as_str().context("no access token in Google's answer")?;
    Ok((refresh.to_string(), access.to_string(), v["expires_in"].as_u64().unwrap_or(3000)))
}

/// A fresh access token (they last about an hour).
pub fn refresh_access(ep: &Endpoints, client_id: &str, client_secret: &str, refresh: &str) -> Result<(String, u64)> {
    let v = token_request(
        ep,
        &[
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ],
    )?;
    let access = v["access_token"].as_str().context("no access token in Google's answer")?;
    Ok((access.to_string(), v["expires_in"].as_u64().unwrap_or(3000)))
}

fn api_get(ep: &Endpoints, access: &str, path: &str) -> Result<Value> {
    match agent(&ep.api)
        .get(&format!("{}{path}", ep.api))
        .set("Authorization", &format!("Bearer {access}"))
        .call()
    {
        Ok(r) => Ok(serde_json::from_str(&r.into_string()?)?),
        Err(ureq::Error::Status(code, r)) => {
            bail!("Gmail answered {code} ({})", oauth_error(&r.into_string().unwrap_or_default()))
        }
        Err(e) => bail!("could not reach Gmail: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Mailbox settings: filters, forwarding, send-as
// ---------------------------------------------------------------------------

/// What an intruder changes to hide: compared against the stored baseline.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct MailboxConfig {
    /// One line per filter: `<id> | <what it matches> -> <what it does>`.
    pub filters: BTreeSet<String>,
    /// Addresses mail may be forwarded to (verified in Gmail settings).
    pub forwarding: BTreeSet<String>,
    /// Address all incoming mail is being forwarded to, if any.
    pub auto_forward: Option<String>,
    /// Addresses this mailbox can send as.
    pub send_as: BTreeSet<String>,
}

fn label_names(v: &Value) -> String {
    v.as_array()
        .map(|a| a.iter().filter_map(|x| x.as_str()).collect::<Vec<_>>().join(","))
        .unwrap_or_default()
}

/// A filter in plain words. Filters that make mail disappear are what matter.
pub fn describe_filter(f: &Value) -> String {
    let c = &f["criteria"];
    let mut what = Vec::new();
    for (key, label) in [("from", "from"), ("to", "to"), ("subject", "subject"), ("query", "matching"), ("negatedQuery", "not matching")] {
        if let Some(v) = c[key].as_str() {
            what.push(format!("{label} \"{v}\""));
        }
    }
    if c["hasAttachment"].as_bool() == Some(true) {
        what.push("with an attachment".into());
    }
    let a = &f["action"];
    let (add, remove) = (label_names(&a["addLabelIds"]), label_names(&a["removeLabelIds"]));
    let mut does = Vec::new();
    if add.contains("TRASH") {
        does.push("deletes it".to_string());
    }
    if remove.contains("INBOX") {
        does.push("skips the inbox".to_string());
    }
    if remove.contains("UNREAD") {
        does.push("marks it read".to_string());
    }
    if add.contains("SPAM") {
        does.push("sends it to spam".to_string());
    }
    if let Some(fwd) = a["forward"].as_str() {
        does.push(format!("forwards it to {fwd}"));
    }
    if does.is_empty() {
        does.push("labels it".into());
    }
    format!(
        "{} | mail {} -> {}",
        f["id"].as_str().unwrap_or("?"),
        if what.is_empty() { "of any kind".into() } else { what.join(", ") },
        does.join(", ")
    )
}

/// Does this filter hide or leak mail (as opposed to just labelling it)?
pub fn filter_is_dangerous(description: &str) -> bool {
    ["deletes it", "skips the inbox", "forwards it", "sends it to spam", "marks it read"]
        .iter()
        .any(|d| description.contains(d))
}

pub fn parse_config(filters: &Value, forwarding: &Value, auto: &Value, send_as: &Value) -> MailboxConfig {
    let emails = |v: &Value, list: &str, field: &str| -> BTreeSet<String> {
        v[list]
            .as_array()
            .map(|a| a.iter().filter_map(|x| x[field].as_str()).map(|s| s.to_ascii_lowercase()).collect())
            .unwrap_or_default()
    };
    MailboxConfig {
        filters: filters["filter"]
            .as_array()
            .map(|a| a.iter().map(describe_filter).collect())
            .unwrap_or_default(),
        forwarding: emails(forwarding, "forwardingAddresses", "forwardingEmail"),
        auto_forward: (auto["enabled"].as_bool() == Some(true))
            .then(|| auto["emailAddress"].as_str().unwrap_or("an unknown address").to_ascii_lowercase()),
        send_as: emails(send_as, "sendAs", "sendAsEmail"),
    }
}

pub fn fetch_config(ep: &Endpoints, access: &str) -> Result<MailboxConfig> {
    Ok(parse_config(
        &api_get(ep, access, "/settings/filters")?,
        &api_get(ep, access, "/settings/forwardingAddresses")?,
        &api_get(ep, access, "/settings/autoForwarding")?,
        &api_get(ep, access, "/settings/sendAs")?,
    ))
}

/// One change to the mailbox's settings, worded for the user.
#[derive(Debug, Clone, PartialEq)]
pub struct ConfigChange {
    pub title: String,
    pub detail: String,
    /// Needs a decision (hides or leaks mail), as opposed to worth knowing.
    pub serious: bool,
}

pub fn diff_config(old: &MailboxConfig, new: &MailboxConfig) -> Vec<ConfigChange> {
    const CHECK: &str = "If you did not do this, someone else is in your mailbox: remove it in Gmail settings, \
                         change your Google password and sign out other devices.";
    let mut out = Vec::new();
    let body = |f: &String| f.split_once(" | ").map(|(_, b)| b.to_string()).unwrap_or_else(|| f.clone());
    for f in new.filters.difference(&old.filters) {
        let serious = filter_is_dangerous(f);
        out.push(ConfigChange {
            title: if serious { "A Gmail filter that hides or forwards mail was added" } else { "A Gmail filter was added" }.into(),
            detail: format!("New filter: {}. {CHECK}", body(f)),
            serious,
        });
    }
    for a in new.forwarding.difference(&old.forwarding) {
        out.push(ConfigChange {
            title: "A forwarding address was added to Gmail".into(),
            detail: format!("Your mail can now be forwarded to {a}. {CHECK}"),
            serious: true,
        });
    }
    if new.auto_forward != old.auto_forward {
        if let Some(to) = &new.auto_forward {
            out.push(ConfigChange {
                title: "Gmail is forwarding all your mail".into(),
                detail: format!("Every incoming message is being copied to {to}. {CHECK}"),
                serious: true,
            });
        }
    }
    for a in new.send_as.difference(&old.send_as) {
        out.push(ConfigChange {
            title: "A send-as address was added to Gmail".into(),
            detail: format!("Mail can now be sent from your mailbox as {a}. {CHECK}"),
            serious: true,
        });
    }
    out
}

// ---------------------------------------------------------------------------
// Security emails
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertKind {
    /// A sign-in from somewhere new, or flagged as unusual.
    NewSignIn,
    /// A password reset was requested.
    PasswordReset,
    /// Password, email, phone or two-step settings were changed.
    AccountChanged,
    /// A one-time code: normal when you are signing in yourself.
    Code,
}

/// What kind of security email is this, judging by its subject? `None` for
/// everything else (newsletters that mention "security", receipts, ...).
pub fn classify(subject: &str) -> Option<AlertKind> {
    let s = subject.to_lowercase();
    let has = |words: &[&str]| words.iter().any(|w| s.contains(w));
    if has(&[
        "password changed", "password was changed", "password has been changed", "password updated",
        "email changed", "email address changed", "email was changed", "email address was changed",
        "email has been changed", "phone number was", "phone number changed", "recovery email", "recovery phone",
        "2-step verification turned off", "two-step verification turned off", "two-factor authentication disabled",
        "2fa disabled", "two-factor authentication has been disabled", "new email address added",
        "account details changed", "account details were changed", "login details changed",
    ]) {
        return Some(AlertKind::AccountChanged);
    }
    if has(&["reset your password", "password reset", "reset password", "forgot your password", "recover your account", "account recovery"]) {
        return Some(AlertKind::PasswordReset);
    }
    if has(&[
        "new device", "new sign-in", "new sign in", "new signin", "new login", "new log-in", "new log in",
        "sign-in attempt", "sign in attempt", "login attempt", "log-in attempt", "unusual sign", "unusual activity",
        "unusual login", "suspicious", "security alert", "someone has your password", "verify your new device",
        "unrecognized device", "unrecognised device", "unrecognized login", "new location", "access from a new",
        "was this you", "did you just sign in", "did you just log in",
    ]) {
        return Some(AlertKind::NewSignIn);
    }
    if has(&["verification code", "security code", "login code", "sign-in code", "one-time", "is your code", "confirmation code", "your code is"]) {
        return Some(AlertKind::Code);
    }
    None
}

/// The Gmail search that finds candidates; [`classify`] makes the decision.
/// `in:anywhere` includes Spam and Trash, where a hiding filter puts them.
pub fn search_query() -> String {
    let subjects = [
        "new device", "new sign-in", "new login", "sign-in attempt", "login attempt", "unusual", "suspicious",
        "security alert", "password", "verification code", "security code", "login code", "recovery",
        "2-step", "two-factor", "was this you", "email changed", "new location",
    ];
    let ors: Vec<String> = subjects.iter().map(|s| format!("subject:\"{s}\"")).collect();
    format!("in:anywhere newer_than:2d {{{}}}", ors.join(" "))
}

/// `"LinkedIn" <security-noreply@linkedin.com>` → (`LinkedIn`, `linkedin.com`).
pub fn sender(from: &str) -> (String, String) {
    let addr = match (from.rfind('<'), from.rfind('>')) {
        (Some(a), Some(b)) if a < b => &from[a + 1..b],
        _ => from,
    }
    .trim()
    .to_ascii_lowercase();
    let host = addr.rsplit_once('@').map(|(_, h)| h).unwrap_or("");
    // Registrable-ish domain: the last two labels (three for co.uk-style endings).
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    let keep = if labels.len() >= 3 && labels[labels.len() - 2].len() <= 3 && labels[labels.len() - 1].len() == 2 { 3 } else { 2 };
    let domain = labels[labels.len().saturating_sub(keep)..].join(".");
    let name = from.split('<').next().unwrap_or("").trim().trim_matches('"').trim();
    let name = if name.is_empty() || name.contains('@') { domain.clone() } else { name.to_string() };
    // Display names are attacker-controlled text: keep them short and plain.
    let name: String = name.chars().filter(|c| !c.is_control()).take(40).collect();
    (name, domain)
}

/// A security email, reduced to what is reported. No body is ever read.
#[derive(Debug, Clone, PartialEq)]
pub struct MailAlert {
    pub id: String,
    pub kind: AlertKind,
    pub service: String,
    pub domain: String,
    pub subject: String,
    /// Unix seconds, from Gmail's receive time.
    pub received: i64,
    /// Found in Trash or Spam: a hiding filter may have put it there.
    pub hidden: bool,
}

pub fn parse_message(m: &Value) -> Option<MailAlert> {
    let header = |name: &str| -> Option<&str> {
        m["payload"]["headers"]
            .as_array()?
            .iter()
            .find(|h| h["name"].as_str().is_some_and(|n| n.eq_ignore_ascii_case(name)))?["value"]
            .as_str()
    };
    let subject: String = header("Subject")?.chars().filter(|c| !c.is_control()).take(160).collect();
    let kind = classify(&subject)?;
    let (service, domain) = sender(header("From").unwrap_or(""));
    let labels = label_names(&m["labelIds"]);
    Some(MailAlert {
        id: m["id"].as_str()?.to_string(),
        kind,
        service,
        domain,
        subject,
        received: m["internalDate"].as_str().and_then(|s| s.parse::<i64>().ok()).unwrap_or(0) / 1000,
        hidden: labels.contains("TRASH") || labels.contains("SPAM"),
    })
}

/// Ids of candidate messages from the last two days (newest first).
pub fn list_candidates(ep: &Endpoints, access: &str) -> Result<Vec<String>> {
    let v = api_get(ep, access, &format!("/messages?maxResults=50&includeSpamTrash=true&q={}", enc(&search_query())))?;
    Ok(v["messages"]
        .as_array()
        .map(|a| a.iter().filter_map(|m| m["id"].as_str()).map(str::to_string).collect())
        .unwrap_or_default())
}

/// Sender, subject and date of one message (headers only, never the body).
pub fn fetch_headers(ep: &Endpoints, access: &str, id: &str) -> Result<Value> {
    anyhow::ensure!(id.bytes().all(|b| b.is_ascii_alphanumeric()), "odd message id");
    api_get(
        ep,
        access,
        &format!("/messages/{id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date"),
    )
}

pub fn fetch_address(ep: &Endpoints, access: &str) -> Result<String> {
    api_get(ep, access, "/profile")?["emailAddress"]
        .as_str()
        .map(str::to_string)
        .context("Gmail did not say which mailbox this is")
}

// ---------------------------------------------------------------------------
// Stored state
// ---------------------------------------------------------------------------

/// `gmail.json` in the data folder.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Stored {
    pub refresh_token: String,
    pub email: String,
    pub connected_at: i64,
    pub baseline: Option<MailboxConfig>,
    /// Message ids already reported (or present when the mailbox was connected).
    pub seen: Vec<String>,
    /// (unix time, sender domain) of recent alerts, for burst detection.
    pub recent: Vec<(i64, String)>,
    pub last_burst: i64,
}

impl Stored {
    pub fn load(path: &Path) -> Option<Self> {
        let s: Self = serde_json::from_slice(&std::fs::read(path).ok()?).ok()?;
        (!s.refresh_token.is_empty()).then_some(s)
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        let tmp = path.with_extension("tmp");
        std::fs::write(&tmp, serde_json::to_vec(self).unwrap_or_default())?;
        std::fs::rename(tmp, path)
    }

    pub fn remember(&mut self, id: &str) {
        self.seen.push(id.to_string());
        if self.seen.len() > SEEN_CAP {
            let cut = self.seen.len() - SEEN_CAP;
            self.seen.drain(..cut);
        }
    }

    /// Record an alert; true when alerts from several different services have
    /// now arrived close together (and that has not been reported recently).
    pub fn note_alert(&mut self, at: i64, domain: &str, now: i64) -> bool {
        self.recent.push((at, domain.to_string()));
        self.recent.retain(|(t, _)| now - *t <= 86_400); // a day, for the "today" count
        let services: BTreeSet<&str> = self
            .recent
            .iter()
            .filter(|(t, _)| now - *t <= BURST_WINDOW_SECS)
            .map(|(_, d)| d.as_str())
            .collect();
        if services.len() >= BURST_SERVICES && now - self.last_burst > BURST_QUIET_SECS {
            self.last_burst = now;
            return true;
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn encoders() {
        assert_eq!(enc("http://127.0.0.1:5000/cb a"), "http%3A%2F%2F127.0.0.1%3A5000%2Fcb%20a");
        // RFC 4648 test vectors, url alphabet, no padding
        assert_eq!(b64url(b""), "");
        assert_eq!(b64url(b"f"), "Zg");
        assert_eq!(b64url(b"fo"), "Zm8");
        assert_eq!(b64url(b"foobar"), "Zm9vYmFy");
        assert_eq!(b64url(&[0xfb, 0xff]), "-_8");
        // RFC 7636 appendix B
        let challenge = b64url(&Sha256::digest(b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }

    #[test]
    fn consent_url_is_read_only_pkce_and_returns_to_this_pc() {
        let id = "1234-abc.apps.googleusercontent.com";
        let (p, url) = begin(id, "http://127.0.0.1:53124").unwrap();
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("scope=https%3A%2F%2Fwww.googleapis.com%2Fauth%2Fgmail.readonly"));
        assert!(url.contains("code_challenge_method=S256") && url.contains(&format!("state={}", p.state)));
        assert!(url.contains("redirect_uri=http%3A%2F%2F127.0.0.1%3A53124"));
        assert!(!url.contains(&p.verifier), "the verifier must never be in the URL");
        assert!(begin(id, "https://evil.example/cb").is_err());
        assert!(begin(id, "http://127.0.0.1.evil.example/").is_err());
        assert!(begin("not-a-client-id", "http://127.0.0.1:1").is_err());
        assert!(begin("x.apps.googleusercontent.com&scope=all", "http://127.0.0.1:1").is_err());
    }

    #[test]
    fn classifies_security_emails_by_subject() {
        use AlertKind::*;
        for (subject, want) in [
            ("Conner, please verify your new device", Some(NewSignIn)),
            ("Security alert", Some(NewSignIn)),
            ("New sign-in to your account", Some(NewSignIn)),
            ("Unusual sign-in activity", Some(NewSignIn)),
            ("Reset your password", Some(PasswordReset)),
            ("Steam account recovery", Some(PasswordReset)),
            ("Your password was changed", Some(AccountChanged)),
            ("Your email address was changed", Some(AccountChanged)),
            ("2-Step Verification turned off", Some(AccountChanged)),
            ("Your verification code is 123456", Some(Code)),
            ("Your order has shipped", None),
            ("5 security tips for the holidays", None),
            ("Password managers compared: our review", None),
        ] {
            assert_eq!(classify(subject), want, "{subject}");
        }
    }

    #[test]
    fn reads_sender_and_headers_without_a_body() {
        assert_eq!(sender("LinkedIn <security-noreply@linkedin.com>"), ("LinkedIn".into(), "linkedin.com".into()));
        assert_eq!(sender("no-reply@accounts.google.com"), ("google.com".into(), "google.com".into()));
        assert_eq!(sender("\"Bank\" <x@mail.bank.co.uk>").1, "bank.co.uk");
        let m = json!({
            "id": "18c0ffee", "labelIds": ["TRASH", "UNREAD"], "internalDate": "1764000000000",
            "payload": {"headers": [
                {"name": "From", "value": "LinkedIn <security-noreply@linkedin.com>"},
                {"name": "subject", "value": "Conner, please verify your new device"}]}
        });
        let a = parse_message(&m).unwrap();
        assert_eq!((a.kind, a.service.as_str(), a.domain.as_str()), (AlertKind::NewSignIn, "LinkedIn", "linkedin.com"));
        assert_eq!(a.received, 1_764_000_000);
        assert!(a.hidden, "a security email in Trash is itself a warning sign");
        let boring = json!({"id": "1", "payload": {"headers": [{"name": "Subject", "value": "Lunch?"}]}});
        assert!(parse_message(&boring).is_none());
    }

    #[test]
    fn reports_mailbox_changes_that_hide_or_leak_mail() {
        let filters = json!({"filter": [
            {"id": "f1", "criteria": {"from": "newsletter@shop.example"}, "action": {"addLabelIds": ["Label_7"]}}]});
        let none = json!({});
        let before = parse_config(&filters, &none, &json!({"enabled": false}), &json!({"sendAs": [{"sendAsEmail": "Me@Gmail.com"}]}));
        assert_eq!(before.send_as.iter().next().unwrap(), "me@gmail.com");
        assert!(diff_config(&before, &before).is_empty());

        let filters2 = json!({"filter": [
            {"id": "f1", "criteria": {"from": "newsletter@shop.example"}, "action": {"addLabelIds": ["Label_7"]}},
            {"id": "f2", "criteria": {"query": "security OR password OR linkedin"},
             "action": {"addLabelIds": ["TRASH"], "removeLabelIds": ["INBOX", "UNREAD"]}}]});
        let after = parse_config(
            &filters2,
            &json!({"forwardingAddresses": [{"forwardingEmail": "drop@evil.example"}]}),
            &json!({"enabled": true, "emailAddress": "drop@evil.example"}),
            &json!({"sendAs": [{"sendAsEmail": "me@gmail.com"}]}),
        );
        let changes = diff_config(&before, &after);
        let titles: Vec<&str> = changes.iter().map(|c| c.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "A Gmail filter that hides or forwards mail was added",
                "A forwarding address was added to Gmail",
                "Gmail is forwarding all your mail"
            ]
        );
        assert!(changes[0].detail.contains("matching \"security OR password OR linkedin\" -> deletes it, skips the inbox"));
        assert!(changes.iter().all(|c| c.serious));
        // A plain labelling filter is worth knowing, not an alarm.
        let labelled = parse_config(
            &json!({"filter": [{"id": "f9", "criteria": {"from": "a@b.example"}, "action": {"addLabelIds": ["Label_1"]}}]}),
            &none, &none, &none,
        );
        assert!(!diff_config(&MailboxConfig::default(), &labelled)[0].serious);
    }

    #[test]
    fn several_services_alerting_at_once_is_one_burst() {
        let mut s = Stored::default();
        let now = 1_000_000;
        assert!(!s.note_alert(now, "linkedin.com", now));
        assert!(!s.note_alert(now, "linkedin.com", now)); // same service twice is not a burst
        assert!(!s.note_alert(now + 60, "steampowered.com", now + 60));
        assert!(s.note_alert(now + 120, "paypal.com", now + 120));
        assert!(!s.note_alert(now + 180, "discord.com", now + 180), "reported once, then quiet");
        // Old alerts age out.
        let later = now + 10 * 3600;
        assert!(!s.note_alert(later, "google.com", later));
    }

    #[test]
    fn talks_to_google_end_to_end() {
        let base = crate::engine::homenet::tests::fake_pihole(|line, body| {
            if line.starts_with("POST /token") {
                if body.contains("grant_type=authorization_code") {
                    assert!(body.contains("code=the-code") && body.contains("code_verifier="));
                    return (200, json!({"access_token": "at1", "refresh_token": "rt1", "expires_in": 3599,
                        "scope": SCOPE}).to_string());
                }
                if body.contains("refresh_token=revoked") {
                    return (400, json!({"error": "invalid_grant", "error_description": "Token has been expired or revoked."}).to_string());
                }
                return (200, json!({"access_token": "at2", "expires_in": 3599}).to_string());
            }
            let ok = |v: Value| (200, v.to_string());
            if line.contains("/profile") {
                ok(json!({"emailAddress": "conner@example.com"}))
            } else if line.contains("/settings/filters") {
                ok(json!({"filter": [{"id": "f2", "criteria": {"from": "linkedin.com"}, "action": {"addLabelIds": ["TRASH"]}}]}))
            } else if line.contains("/settings/") {
                ok(json!({}))
            } else if line.contains("/messages?") {
                assert!(line.contains("includeSpamTrash=true"));
                ok(json!({"messages": [{"id": "m1"}, {"id": "m2"}]}))
            } else if line.contains("/messages/m1") {
                assert!(line.contains("format=metadata"), "must never ask for the body");
                ok(json!({"id": "m1", "internalDate": "1764000000000", "labelIds": ["INBOX"], "payload": {"headers": [
                    {"name": "From", "value": "LinkedIn <security-noreply@linkedin.com>"},
                    {"name": "Subject", "value": "Conner, please verify your new device"}]}}))
            } else {
                ok(json!({"id": "m2", "payload": {"headers": [{"name": "Subject", "value": "Password managers compared"}]}}))
            }
        });
        let ep = Endpoints {
            token: format!("{base}/token"),
            api: base.clone(),
        };
        let (pending, _) = begin("1-a.apps.googleusercontent.com", "http://127.0.0.1:9").unwrap();
        let (refresh, access, _) = exchange_code(&ep, "1-a.apps.googleusercontent.com", "secret", "the-code", &pending).unwrap();
        assert_eq!((refresh.as_str(), access.as_str()), ("rt1", "at1"));
        assert_eq!(refresh_access(&ep, "id", "secret", "rt1").unwrap().0, "at2");
        let err = refresh_access(&ep, "id", "secret", "revoked").unwrap_err().to_string();
        assert!(err.contains("Connect Gmail again"), "{err}");

        assert_eq!(fetch_address(&ep, "at2").unwrap(), "conner@example.com");
        let cfg = fetch_config(&ep, "at2").unwrap();
        assert!(filter_is_dangerous(cfg.filters.iter().next().unwrap()));
        let ids = list_candidates(&ep, "at2").unwrap();
        let alerts: Vec<MailAlert> = ids
            .iter()
            .filter_map(|id| parse_message(&fetch_headers(&ep, "at2", id).unwrap()))
            .collect();
        assert_eq!(alerts.len(), 1);
        assert_eq!(alerts[0].service, "LinkedIn");
        assert!(fetch_headers(&ep, "at2", "../settings").is_err());
    }
}
