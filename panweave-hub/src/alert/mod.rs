//! **Experimental** critical-event notifications over Wi-Fi from the one
//! shared radio of an ESP32-C6: Zigbee → Wi-Fi → Zigbee.
//!
//! The hub queues selected sensor events durably ([`queue`]), waits
//! for the next periodic check ([`schedule`]), then the firmware hands
//! the radio to Wi-Fi for at most `budget` milliseconds, sends one
//! Telegram message ([`telegram`], [`message`]) and gives the radio back
//! to IEEE 802.15.4 ([`attempt`]). This module is the radio-independent
//! part — the firmware supplies the [`attempt::RadioSwitch`] and
//! [`attempt::Network`] implementations — and is fully testable on a
//! host.
//!
//! Off unless enabled ([`Config::enabled`], default `false`); nothing is
//! read from or written to flash for it while disabled. While Wi-Fi has
//! the radio the hub hears **nothing** on IEEE 802.15.4: frames sensors
//! send during an attempt can be lost (sleepy devices retry their polls;
//! the queue protects only events already received).
//!
//! Secrets (Wi-Fi password, bot token) are stored **in plain text** in
//! the hub's flash partition: the ESP32-C6 hub does not enable flash
//! encryption, so anyone who can read the flash (USB / JTAG,
//! `espflash read-flash`) can read them. They are never returned over
//! the protocol, never logged, never captured.

pub mod attempt;
pub mod message;
pub mod queue;
pub mod schedule;
pub mod telegram;
pub mod uplink;

use core::fmt;

use panweave_codec::{Reader, Writer};
use panweave_storage::{Key, Kind, Storage};

use crate::protocol::alerts::{
    AlertDestination, BUDGET_MS, DELAY_MS, HEARTBEAT_S, MAX_BOT_TOKEN, MAX_CHAT_ID,
    MAX_SERVER_HOST, MAX_SSID, MAX_WIFI_PASSWORD, WIFI_CHANNELS, kinds,
};
use crate::protocol::{AlertConfigUpdate, ErrorCode, Text};

/// Default interval between notification checks.
pub const DEFAULT_DELAY_MS: u32 = 60_000;
/// Default Zigbee downtime budget.
pub const DEFAULT_BUDGET_MS: u32 = 2_000;
/// Default notification server port.
pub const DEFAULT_SERVER_PORT: u16 = 443;
/// Default heartbeat interval towards a notification server, seconds.
pub const DEFAULT_HEARTBEAT_S: u32 = 900;

const FORMAT: u8 = 1;
/// Largest settings record (about 300 octets with every text full; the
/// flash store takes up to 512).
const CONFIG_RECORD: usize = 384;
/// Flags of the access-point pin at the end of the record.
const PIN_BSSID: u8 = 1;
const PIN_CHANNEL: u8 = 2;
const PIN_WPA3: u8 = 4;

/// The persisted settings.
#[derive(Clone, PartialEq, Eq)]
pub struct Config {
    /// The experimental mode is on.
    pub enabled: bool,
    /// Which events are queued (`protocol::alerts::kinds`).
    pub kinds: u8,
    /// Notification check interval (legacy field name, milliseconds).
    pub delay_ms: u32,
    /// Zigbee downtime budget of one attempt.
    pub budget_ms: u32,
    /// Wi-Fi SSID.
    pub ssid: Text<MAX_SSID>,
    /// Wi-Fi password (secret).
    pub password: Text<MAX_WIFI_PASSWORD>,
    /// Telegram bot token (secret).
    pub token: Text<MAX_BOT_TOKEN>,
    /// Telegram chat identifier.
    pub chat_id: Text<MAX_CHAT_ID>,
    /// Join only this access point (BSSID).
    pub bssid: Option<[u8; 6]>,
    /// Look for the access point on this channel only.
    pub channel: Option<u8>,
    /// Join only WPA3-Personal (SAE) access points.
    pub wpa3_only: bool,
    /// Where notifications go.
    pub destination: AlertDestination,
    /// Notification server host name.
    pub server_host: Text<MAX_SERVER_HOST>,
    /// Notification server port.
    pub server_port: u16,
    /// Heartbeat interval towards the server, seconds (0: none).
    pub heartbeat_s: u32,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            enabled: false,
            kinds: kinds::DEFAULT,
            delay_ms: DEFAULT_DELAY_MS,
            budget_ms: DEFAULT_BUDGET_MS,
            ssid: Text::new(),
            password: Text::new(),
            token: Text::new(),
            chat_id: Text::new(),
            bssid: None,
            channel: None,
            wpa3_only: false,
            destination: AlertDestination::Telegram,
            server_host: Text::new(),
            server_port: DEFAULT_SERVER_PORT,
            heartbeat_s: DEFAULT_HEARTBEAT_S,
        }
    }
}

impl fmt::Debug for Config {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Config")
            .field("enabled", &self.enabled)
            .field("kinds", &self.kinds)
            .field("delay_ms", &self.delay_ms)
            .field("budget_ms", &self.budget_ms)
            .field("ssid", &self.ssid)
            .field("password", &"[REDACTED]")
            .field("token", &"[REDACTED]")
            .field("chat_id", &self.chat_id)
            .field("bssid", &self.bssid)
            .field("channel", &self.channel)
            .field("wpa3_only", &self.wpa3_only)
            .field("destination", &self.destination)
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("heartbeat_s", &self.heartbeat_s)
            .finish()
    }
}

fn wipe<const N: usize>(t: &mut Text<N>) {
    t.iter_mut().for_each(|b| *b = 0);
    core::hint::black_box(&*t);
    t.clear();
}

impl Drop for Config {
    fn drop(&mut self) {
        wipe(&mut self.password);
        wipe(&mut self.token);
    }
}

const fn config_key() -> Key {
    Key::with_id(Kind::Application, queue::CONFIG_ID)
}

fn read_text<const N: usize>(r: &mut Reader<'_>) -> Option<Text<N>> {
    let n = usize::from(r.u8().ok()?);
    Text::from_slice(r.bytes(n).ok()?).ok()
}

fn write_text<const N: usize>(w: &mut Writer<'_>, t: &Text<N>) -> Option<()> {
    w.u8(u8::try_from(t.len()).ok()?).ok()?;
    w.bytes(t).ok()
}

impl Config {
    /// The Wi-Fi settings and those of the destination are all present.
    pub fn is_complete(&self) -> bool {
        !self.ssid.is_empty()
            && !self.token.is_empty()
            && match self.destination {
                AlertDestination::Telegram => !self.chat_id.is_empty(),
                AlertDestination::Server => !self.server_host.is_empty(),
            }
    }

    /// The host and port notifications are sent to.
    pub fn endpoint(&self) -> (&str, u16) {
        match self.destination {
            AlertDestination::Telegram => (telegram::HOST, telegram::PORT),
            AlertDestination::Server => (
                core::str::from_utf8(&self.server_host).unwrap_or(""),
                self.server_port,
            ),
        }
    }

    /// The heartbeat interval in milliseconds, when one applies (a server
    /// destination with a non-zero interval).
    pub fn heartbeat_ms(&self) -> Option<u64> {
        (self.destination == AlertDestination::Server && self.heartbeat_s > 0)
            .then(|| u64::from(self.heartbeat_s) * 1000)
    }

    /// Loads the settings (defaults when absent or unreadable).
    pub fn load<S: Storage>(storage: &mut S) -> Self {
        let mut buf = [0u8; CONFIG_RECORD];
        let mut c = Config::default();
        if let Ok(Some(n)) = storage.load(config_key(), &mut buf) {
            let mut r = Reader::new(buf.get(..n).unwrap_or(&[]));
            let parsed = (|| {
                if r.u8().ok()? != FORMAT {
                    return None;
                }
                // Built field by field: `Config` wipes its secrets on drop,
                // so it cannot be the base of a struct update.
                let mut c = Config::default();
                c.enabled = r.u8().ok()? != 0;
                c.kinds = r.u8().ok()?;
                c.delay_ms = r.u32_le().ok()?;
                c.budget_ms = r.u32_le().ok()?;
                c.ssid = read_text(&mut r)?;
                c.password = read_text(&mut r)?;
                c.token = read_text(&mut r)?;
                c.chat_id = read_text(&mut r)?;
                // The access-point pin, appended to format 1 later: a
                // record written before it simply ends here.
                if !r.is_empty() {
                    let flags = r.u8().ok()?;
                    if flags & PIN_BSSID != 0 {
                        c.bssid = Some(r.bytes(6).ok()?.try_into().ok()?);
                    }
                    if flags & PIN_CHANNEL != 0 {
                        c.channel = Some(r.u8().ok()?);
                    }
                    c.wpa3_only = flags & PIN_WPA3 != 0;
                }
                // The server settings, appended after the pin later still.
                if !r.is_empty() {
                    c.destination = AlertDestination::from_code(r.u8().ok()?)?;
                    c.server_host = read_text(&mut r)?;
                    c.server_port = r.u16_le().ok()?;
                    c.heartbeat_s = r.u32_le().ok()?;
                }
                Some(c)
            })();
            if let Some(p) = parsed {
                c = p;
            }
        }
        buf.fill(0);
        core::hint::black_box(&buf);
        c
    }

    /// Persists the settings.
    ///
    /// # Errors
    ///
    /// `StorageFailure`.
    pub fn store<S: Storage>(&self, storage: &mut S) -> Result<(), ErrorCode> {
        let mut buf = [0u8; CONFIG_RECORD];
        let mut w = Writer::new(&mut buf);
        let ok = (|| {
            w.u8(FORMAT).ok()?;
            w.u8(u8::from(self.enabled)).ok()?;
            w.u8(self.kinds).ok()?;
            w.u32_le(self.delay_ms).ok()?;
            w.u32_le(self.budget_ms).ok()?;
            write_text(&mut w, &self.ssid)?;
            write_text(&mut w, &self.password)?;
            write_text(&mut w, &self.token)?;
            write_text(&mut w, &self.chat_id)?;
            let flags = if self.bssid.is_some() { PIN_BSSID } else { 0 }
                | if self.channel.is_some() {
                    PIN_CHANNEL
                } else {
                    0
                }
                | if self.wpa3_only { PIN_WPA3 } else { 0 };
            w.u8(flags).ok()?;
            if let Some(m) = self.bssid {
                w.bytes(&m).ok()?;
            }
            if let Some(c) = self.channel {
                w.u8(c).ok()?;
            }
            w.u8(self.destination.code()).ok()?;
            write_text(&mut w, &self.server_host)?;
            w.u16_le(self.server_port).ok()?;
            w.u32_le(self.heartbeat_s).ok()?;
            Some(())
        })();
        let n = w.position();
        let r = match ok {
            Some(()) => storage
                .store(config_key(), buf.get(..n).unwrap_or(&[]))
                .map_err(|_| ErrorCode::StorageFailure),
            None => Err(ErrorCode::StorageFailure),
        };
        buf.fill(0);
        core::hint::black_box(&buf);
        r
    }

    /// Applies a change (validated as a whole: nothing changes on error).
    ///
    /// # Errors
    ///
    /// `InvalidArgument` for out-of-range values or settings that cannot
    /// be sent as they are.
    pub fn apply(&mut self, u: &AlertConfigUpdate) -> Result<(), ErrorCode> {
        if u.delay_ms.is_some_and(|d| !DELAY_MS.contains(&d))
            || u.budget_ms.is_some_and(|b| !BUDGET_MS.contains(&b))
            || u.kinds.is_some_and(|k| k & !kinds::ALL != 0)
            || u.token
                .as_ref()
                .is_some_and(|t| !t.is_empty() && !telegram_safe(t, b":_-"))
            || u.chat_id
                .as_ref()
                .is_some_and(|c| !c.is_empty() && !telegram_safe(c, b"-_@"))
            || u.password
                .as_ref()
                .is_some_and(|p| !p.is_empty() && p.len() < 8)
            || u.channel
                .flatten()
                .is_some_and(|c| !WIFI_CHANNELS.contains(&c))
            // A BSSID is a unicast address, never all zeros.
            || u.bssid
                .flatten()
                .is_some_and(|m| m[0] & 1 != 0 || m == [0; 6])
            || u.server_host
                .as_ref()
                .is_some_and(|h| !h.is_empty() && !valid_host(h))
            || u.server_port == Some(0)
            || u.heartbeat_s
                .is_some_and(|h| h != 0 && !HEARTBEAT_S.contains(&h))
        {
            return Err(ErrorCode::InvalidArgument);
        }
        if u.clear_secrets {
            wipe(&mut self.password);
            wipe(&mut self.token);
        }
        if let Some(e) = u.enabled {
            self.enabled = e;
        }
        if let Some(k) = u.kinds {
            self.kinds = k;
        }
        if let Some(d) = u.delay_ms {
            self.delay_ms = d;
        }
        if let Some(b) = u.budget_ms {
            self.budget_ms = b;
        }
        if let Some(s) = &u.ssid {
            self.ssid.clone_from(s);
        }
        if let Some(p) = &u.password {
            wipe(&mut self.password);
            self.password.clone_from(p);
        }
        if let Some(t) = &u.token {
            wipe(&mut self.token);
            self.token.clone_from(t);
        }
        if let Some(c) = &u.chat_id {
            self.chat_id.clone_from(c);
        }
        if let Some(m) = u.bssid {
            self.bssid = m;
        }
        if let Some(c) = u.channel {
            self.channel = c;
        }
        if let Some(w) = u.wpa3_only {
            self.wpa3_only = w;
        }
        if let Some(d) = u.destination {
            self.destination = d;
        }
        if let Some(h) = &u.server_host {
            self.server_host.clone_from(h);
        }
        if let Some(p) = u.server_port {
            self.server_port = p;
        }
        if let Some(h) = u.heartbeat_s {
            self.heartbeat_s = h;
        }
        Ok(())
    }
}

/// A DNS host name: labels of letters, digits and hyphens separated by
/// dots, no label empty or starting or ending with a hyphen.
fn valid_host(h: &[u8]) -> bool {
    h.split(|b| *b == b'.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || *b == b'-')
            && label.first() != Some(&b'-')
            && label.last() != Some(&b'-')
    })
}

fn telegram_safe(v: &[u8], extra: &[u8]) -> bool {
    v.iter()
        .all(|b| b.is_ascii_alphanumeric() || extra.contains(b))
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_storage::MemoryStorage;

    fn text<const N: usize>(s: &str) -> Text<N> {
        Text::from_slice(s.as_bytes()).unwrap()
    }

    #[test]
    fn the_mode_is_off_by_default_with_the_specified_timings() {
        let c = Config::default();
        assert!(!c.enabled);
        assert_eq!((c.delay_ms, c.budget_ms), (60_000, 2_000));
        assert!(!c.is_complete());
        assert_ne!(c.kinds & kinds::CONTACT, 0);
    }

    #[test]
    fn the_access_point_pin_persists_and_an_older_record_still_loads() {
        let mut s = MemoryStorage::<4, 512>::new();
        let mut c = Config::default();
        c.apply(&AlertConfigUpdate {
            ssid: Some(text("hidden")),
            password: Some(text("correct horse")),
            bssid: Some(Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55])),
            channel: Some(Some(11)),
            wpa3_only: Some(true),
            ..AlertConfigUpdate::default()
        })
        .unwrap();
        c.store(&mut s).unwrap();
        let l = Config::load(&mut s);
        assert_eq!(l, c);
        assert_eq!(
            (l.bssid, l.channel, l.wpa3_only),
            (Some([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]), Some(11), true)
        );

        // A record written before the pin existed ends after the chat
        // identifier: it loads with its settings and no pin.
        let mut plain = Config::default();
        plain
            .apply(&AlertConfigUpdate {
                ssid: Some(text("home")),
                password: Some(text("correct horse")),
                ..AlertConfigUpdate::default()
            })
            .unwrap();
        plain.store(&mut s).unwrap();
        let mut buf = [0u8; CONFIG_RECORD];
        let n = s.load(config_key(), &mut buf).unwrap().unwrap();
        // The server tail of a default record: destination, empty host,
        // port, heartbeat.
        let server_tail = 1 + 1 + 2 + 4;
        // Written before the server settings existed: ends after the pin.
        s.store(config_key(), &buf[..n - server_tail]).unwrap();
        assert_eq!(Config::load(&mut s), plain);
        let n = n - server_tail;
        assert_eq!(buf[n - 1], 0, "no pin flags");
        s.store(config_key(), &buf[..n - 1]).unwrap();
        assert_eq!(Config::load(&mut s), plain);

        // Removing the pin.
        c.apply(&AlertConfigUpdate {
            bssid: Some(None),
            channel: Some(None),
            wpa3_only: Some(false),
            ..AlertConfigUpdate::default()
        })
        .unwrap();
        assert_eq!((c.bssid, c.channel, c.wpa3_only), (None, None, false));
    }

    #[test]
    fn server_settings_persist_and_decide_completeness_and_endpoint() {
        let mut s = MemoryStorage::<4, 512>::new();
        let mut c = Config::default();
        assert_eq!(c.endpoint(), (telegram::HOST, telegram::PORT));
        assert_eq!(c.heartbeat_ms(), None, "no heartbeat towards Telegram");
        c.apply(&AlertConfigUpdate {
            ssid: Some(text("home")),
            token: Some(text("hub-token_0123")),
            destination: Some(AlertDestination::Server),
            server_host: Some(text("hub.example.com")),
            server_port: Some(8443),
            heartbeat_s: Some(600),
            ..AlertConfigUpdate::default()
        })
        .unwrap();
        assert!(c.is_complete(), "a server needs no chat identifier");
        assert_eq!(c.endpoint(), ("hub.example.com", 8443));
        assert_eq!(c.heartbeat_ms(), Some(600_000));
        c.store(&mut s).unwrap();
        assert_eq!(Config::load(&mut s), c);

        c.apply(&AlertConfigUpdate {
            heartbeat_s: Some(0),
            server_host: Some(Text::new()),
            ..AlertConfigUpdate::default()
        })
        .unwrap();
        assert_eq!(c.heartbeat_ms(), None);
        assert!(!c.is_complete(), "a server destination needs a host");
    }

    #[test]
    fn invalid_server_settings_are_refused() {
        let mut c = Config::default();
        for u in [
            AlertConfigUpdate {
                server_host: Some(text("bad host")),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                server_host: Some(text("-x.example.com")),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                server_host: Some(text("a..b")),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                server_port: Some(0),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                heartbeat_s: Some(10),
                ..AlertConfigUpdate::default()
            },
        ] {
            assert_eq!(c.apply(&u), Err(ErrorCode::InvalidArgument), "{u:?}");
        }
        assert_eq!(c, Config::default(), "nothing changed");
    }

    #[test]
    fn a_pin_that_cannot_be_an_access_point_is_refused() {
        let mut c = Config::default();
        for u in [
            AlertConfigUpdate {
                channel: Some(Some(0)),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                channel: Some(Some(14)),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                bssid: Some(Some([0x01, 0, 0x5e, 0, 0, 1])),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                bssid: Some(Some([0; 6])),
                ..AlertConfigUpdate::default()
            },
        ] {
            assert_eq!(c.apply(&u), Err(ErrorCode::InvalidArgument), "{u:?}");
        }
        assert_eq!(c, Config::default(), "nothing changed");
    }

    #[test]
    fn settings_persist_and_secrets_never_appear_in_debug_output() {
        let mut s = MemoryStorage::<4, 512>::new();
        let mut c = Config::default();
        c.apply(&AlertConfigUpdate {
            enabled: Some(true),
            delay_ms: Some(60_000),
            budget_ms: Some(2_500),
            ssid: Some(text("home")),
            password: Some(text("correct horse")),
            token: Some(text("123:AAbb-cc_dd")),
            chat_id: Some(text("-1001234")),
            ..AlertConfigUpdate::default()
        })
        .unwrap();
        c.store(&mut s).unwrap();
        let l = Config::load(&mut s);
        assert_eq!(l, c);
        assert!(l.is_complete());
        let dbg = format!("{l:?}");
        assert!(!dbg.contains("horse") && !dbg.contains("AAbb"));
        // An empty store reads as defaults.
        assert_eq!(
            Config::load(&mut MemoryStorage::<4, 512>::new()),
            Config::default()
        );
    }

    #[test]
    fn invalid_changes_are_refused_as_a_whole() {
        let mut c = Config::default();
        for bad in [
            AlertConfigUpdate {
                delay_ms: Some(10),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                budget_ms: Some(100),
                enabled: Some(true),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                token: Some(text("1:a\r\nb")),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                chat_id: Some(text("x\"y")),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                password: Some(text("short")),
                ..AlertConfigUpdate::default()
            },
            AlertConfigUpdate {
                kinds: Some(0x80),
                ..AlertConfigUpdate::default()
            },
        ] {
            assert_eq!(c.apply(&bad), Err(ErrorCode::InvalidArgument));
            assert_eq!(c, Config::default());
        }
        // Clearing secrets.
        c.apply(&AlertConfigUpdate {
            token: Some(text("1:a")),
            ..AlertConfigUpdate::default()
        })
        .unwrap();
        c.apply(&AlertConfigUpdate {
            clear_secrets: true,
            ..AlertConfigUpdate::default()
        })
        .unwrap();
        assert!(c.token.is_empty());
    }
}
