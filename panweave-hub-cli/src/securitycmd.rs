//! `security …`: the Trust Center's authorization policy, devices without
//! application access, and key-exchange exemptions.

use panweave_hub::model::Ieee;
use panweave_hub::protocol::{ErrorCode, Request, Response, SecurityStatus};

use crate::diagcmd::unsupported;
use crate::json::{Obj, array};
use crate::{Hub, error_text, ieee, number};

const OLD_FIRMWARE: &str =
    "the hub firmware does not support security status (needs firmware 0.2.1 or later)";

pub(crate) fn status_json(s: &SecurityStatus) -> String {
    let exemptions: Vec<String> = s
        .exemptions
        .iter()
        .map(|e| {
            Obj::new()
                .str("ieee", &Ieee(e.ieee).to_string())
                .opt("remaining_s", e.remaining_s.map(Into::into))
                .bool("permanent", e.remaining_s.is_none())
                .finish()
        })
        .collect();
    let unauthorized: Vec<String> = s
        .unauthorized
        .iter()
        .map(|(i, a)| {
            Obj::new()
                .str("ieee", &Ieee(*i).to_string())
                .str("authorization", a.name())
                .finish()
        })
        .collect();
    Obj::new()
        .bool("require_key_exchange", s.require_key_exchange)
        .int("node_join_timeout_s", s.node_join_timeout_s.into())
        .int("pending_key_exchanges", s.pending_key_exchanges.into())
        .int("key_exchange_timeouts", s.key_exchange_timeouts.into())
        .int(
            "unauthorized_frames_dropped",
            s.unauthorized_frames_dropped.into(),
        )
        .raw(
            "denied",
            &Obj::new()
                .int("unresolved", s.denied.unresolved.into())
                .int("inconsistent", s.denied.inconsistent.into())
                .int("unknown", s.denied.unknown.into())
                .int("pending", s.denied.pending.into())
                .int("incomplete", s.denied.incomplete.into())
                .finish(),
        )
        .int("exemptions_used", s.exemptions_used.into())
        .int("exemptions_expired", s.exemptions_expired.into())
        .int("link_keys", s.link_keys.into())
        .int("link_key_capacity", s.link_key_capacity.into())
        .raw("exemptions", &array(&exemptions))
        .raw("unauthorized", &array(&unauthorized))
        .finish()
}

fn status(hub: &mut Hub, as_json: bool) -> Result<(), String> {
    let s = match hub.call(Request::GetSecurityStatus)? {
        Response::SecurityStatus(s) => s,
        r if unsupported(&r) => return Err(OLD_FIRMWARE.into()),
        Response::Error(e) => return Err(error_text(e)),
        r => return Err(format!("unexpected response: {r:?}")),
    };
    if as_json {
        println!("{}", status_json(&s));
        return Ok(());
    }
    println!(
        "key exchange      {}",
        if s.require_key_exchange {
            format!(
                "required: a joiner has {} s to verify a unique link key",
                s.node_join_timeout_s
            )
        } else {
            "not required (devices are authorized when they receive the network key)".into()
        }
    );
    println!(
        "pending           {} device(s); {} removed for not completing it",
        s.pending_key_exchanges, s.key_exchange_timeouts
    );
    println!(
        "dropped frames    {} application frame(s) from unauthorized devices",
        s.unauthorized_frames_dropped
    );
    let d = &s.denied;
    println!(
        "  by reason       unresolved {}, inconsistent {}, unknown {}, pending {}, incomplete {}",
        d.unresolved, d.inconsistent, d.unknown, d.pending, d.incomplete
    );
    println!(
        "grants            {} used by a join, {} expired unused",
        s.exemptions_used, s.exemptions_expired
    );
    println!("link keys         {}/{}", s.link_keys, s.link_key_capacity);
    if s.exemptions.is_empty() {
        println!("exemptions        none");
    }
    for e in &s.exemptions {
        match e.remaining_s {
            Some(r) => println!(
                "exemption         {} (joining window, {r} s left)",
                Ieee(e.ieee)
            ),
            None => println!(
                "exemption         {} (joined, kept until revoked)",
                Ieee(e.ieee)
            ),
        }
    }
    for (i, a) in &s.unauthorized {
        println!("unauthorized      {} {}", Ieee(*i), a.name());
    }
    Ok(())
}

fn set(hub: &mut Hub, target: u64, seconds: u16) -> Result<(), String> {
    match hub.call(Request::SetKeyExchangeExemption {
        ieee: target,
        seconds,
    })? {
        Response::Done => Ok(()),
        Response::Error(ErrorCode::Busy) => {
            Err("no room for another exemption (at most 8): revoke one first".into())
        }
        r if unsupported(&r) => Err(OLD_FIRMWARE.into()),
        Response::Error(e) => Err(error_text(e)),
        r => Err(format!("unexpected response: {r:?}")),
    }
}

/// `security [exempt <ieee> [--seconds N] | revoke <ieee>]`.
pub(crate) fn run(hub: &mut Hub, args: &[&str], as_json: bool) -> Result<(), String> {
    match args {
        [] | ["status", ..] => status(hub, as_json),
        ["exempt", id, rest @ ..] => {
            let seconds: u16 = rest
                .iter()
                .position(|a| *a == "--seconds")
                .and_then(|i| rest.get(i + 1))
                .map_or(Ok(120), |v| number(v))?;
            if seconds == 0 {
                return Err(
                    "--seconds must be at least 1 (use `security revoke` to revoke)".into(),
                );
            }
            let target = ieee(id)?;
            set(hub, target, seconds)?;
            eprintln!(
                "warning: {} may stay on the network without a unique Trust Center link key; anyone who captured its join can derive the network key",
                Ieee(target)
            );
            println!(
                "{} exempted from the key exchange: it must join within {seconds} s (open the network too)",
                Ieee(target)
            );
            Ok(())
        }
        ["revoke", id, ..] => {
            let target = ieee(id)?;
            set(hub, target, 0)?;
            println!("exemption of {} revoked", Ieee(target));
            Ok(())
        }
        _ => Err(crate::USAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use panweave_hub::protocol::{DeviceAuthorization, ExemptionInfo};

    #[test]
    fn the_status_serializes() {
        let mut s = SecurityStatus {
            require_key_exchange: true,
            node_join_timeout_s: 15,
            link_keys: 3,
            link_key_capacity: 32,
            ..SecurityStatus::default()
        };
        s.exemptions
            .push(ExemptionInfo {
                ieee: 1,
                remaining_s: None,
            })
            .unwrap_or_else(|_| unreachable!());
        s.unauthorized
            .push((2, DeviceAuthorization::KeyExchangeIncomplete))
            .unwrap_or_else(|_| unreachable!());
        let j = status_json(&s);
        assert!(j.starts_with(r#"{"require_key_exchange":true,"node_join_timeout_s":15"#));
        assert!(j.contains(r#""permanent":true"#), "{j}");
        assert!(
            j.contains(r#""authorization":"key-exchange-incomplete""#),
            "{j}"
        );
    }
}
