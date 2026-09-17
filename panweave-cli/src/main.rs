//! Host-side command-line tool: runs canned simulator scenarios with
//! optional PCAP capture and frame traces.
//!
//! ```text
//! panweave-cli sim [--scenario basic|mesh] [--pcap FILE] [--trace] [--seconds N]
//! panweave-cli summarize <hex frame>
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]
// A host tool may abort on programming errors in its fixed scenarios.
#![allow(clippy::expect_used)]

use std::fs::File;
use std::io::{self, Write};
use std::process::ExitCode;

use panweave_runtime::{JoinMode, StackConfig, StackEvent};
use panweave_sim::Simulator;
use panweave_types::time::Duration;
use panweave_types::{
    ClusterId, DeviceId, Endpoint, ExtendedAddress, LogicalDeviceType, ProfileId,
};
use panweave_zcl::clusters::{identify, on_off};
use panweave_zcl::layer::EndpointInstance;
use panweave_zdo::descriptor::SimpleDescriptor;

fn usage() -> ExitCode {
    eprintln!(
        "usage:\n  panweave-cli sim [--scenario basic|mesh] [--pcap FILE] [--trace] [--seconds N]\n  panweave-cli summarize <hex frame>"
    );
    ExitCode::from(2)
}

fn lamp(cfg: StackConfig, sim: &mut Simulator, name: &str, seed: u64) -> usize {
    let mut stack = panweave_sim::SimStack::new(
        cfg,
        panweave_mac::service::MacServiceConfig::default(),
        panweave_testkit::TestRng::seed(seed),
        panweave_storage::MemoryStorage::new(),
    );
    let desc = SimpleDescriptor::new(
        Endpoint(1),
        ProfileId::HOME_AUTOMATION,
        DeviceId(0x0100),
        1,
        &[ClusterId(0), identify::ID, on_off::ID],
        &[],
    )
    .expect("descriptor");
    let mut ep = EndpointInstance::new(Endpoint(1), ProfileId::HOME_AUTOMATION);
    let _ = ep.add_instance(identify::server().expect("identify"));
    let _ = ep.add_instance(on_off::server().expect("on/off"));
    let _ = stack.add_endpoint(desc, ep);
    sim.add_stack(name, stack, Box::new(panweave_sim::OnOffApp::default()))
}

fn run_sim(
    scenario: &str,
    pcap: Option<String>,
    trace: bool,
    seconds: u64,
) -> io::Result<ExitCode> {
    let mut sim = Simulator::new();
    sim.trace_enabled = trace;
    if let Some(path) = pcap {
        sim.capture(Box::new(File::create(path)?))?;
    }
    let mut ccfg = StackConfig::new(LogicalDeviceType::Coordinator, ExtendedAddress(0x1));
    ccfg.trust_center_policy.allow_joins = true;
    let c = lamp(ccfg, &mut sim, "coordinator", 1);
    sim.stack(c)
        .form_network()
        .map_err(|e| io::Error::other(format!("{e:?}")))?;
    sim.run_until(Duration::from_secs(30), |s| {
        s.events(c)
            .iter()
            .any(|e| matches!(e, StackEvent::NetworkFormed { .. }))
    });
    let _ = sim.stack(c).permit_join_network(180);
    let mut joiners = Vec::new();
    match scenario {
        "basic" => {
            let d = lamp(
                StackConfig::new(LogicalDeviceType::EndDevice, ExtendedAddress(0x2)),
                &mut sim,
                "end-device",
                2,
            );
            joiners.push(d);
        }
        "mesh" => {
            let r = lamp(
                StackConfig::new(LogicalDeviceType::Router, ExtendedAddress(0x3)),
                &mut sim,
                "router",
                3,
            );
            let mut scfg = StackConfig::new(LogicalDeviceType::EndDevice, ExtendedAddress(0x4));
            scfg.sleepy = true;
            let s = lamp(scfg, &mut sim, "sleepy", 4);
            sim.block(c, s);
            joiners.push(r);
            joiners.push(s);
        }
        _ => return Ok(usage()),
    }
    for &j in &joiners {
        let _ = sim.stack(j).join(JoinMode::Association);
        let ok = sim.run_until(Duration::from_secs(120), |s| {
            s.events(j)
                .iter()
                .any(|e| matches!(e, StackEvent::Joined { .. }))
        });
        println!(
            "{}: {}",
            sim.node(j).name,
            if ok { "joined" } else { "join failed" }
        );
        let _ = sim.stack(c).permit_join_network(180);
    }
    sim.run_for(Duration::from_secs(seconds));
    for i in 0..sim.len() {
        println!(
            "{}: short={} events={} frames on air so far={}",
            sim.node(i).name,
            sim.node(i).stack.short_address(),
            sim.events(i).len(),
            sim.frames
        );
    }
    if trace {
        let stdout = io::stdout();
        sim.dump_trace(&mut stdout.lock())?;
    }
    sim.finish_capture()?;
    Ok(ExitCode::SUCCESS)
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("sim") => {
            let mut scenario = "basic".to_string();
            let mut pcap = None;
            let mut trace = false;
            let mut seconds = 60u64;
            let mut i = 1;
            while i < args.len() {
                match args[i].as_str() {
                    "--scenario" if i + 1 < args.len() => {
                        scenario.clone_from(&args[i + 1]);
                        i += 2;
                    }
                    "--pcap" if i + 1 < args.len() => {
                        pcap = Some(args[i + 1].clone());
                        i += 2;
                    }
                    "--seconds" if i + 1 < args.len() => {
                        seconds = args[i + 1].parse().unwrap_or(60);
                        i += 2;
                    }
                    "--trace" => {
                        trace = true;
                        i += 1;
                    }
                    _ => return usage(),
                }
            }
            match run_sim(&scenario, pcap, trace, seconds) {
                Ok(code) => code,
                Err(e) => {
                    eprintln!("error: {e}");
                    ExitCode::FAILURE
                }
            }
        }
        Some("summarize") => {
            let hex: String = args[1..].concat().replace([' ', ':'], "");
            let bytes: Result<Vec<u8>, _> = (0..hex.len() / 2)
                .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16))
                .collect();
            match bytes {
                Ok(b) => {
                    let _ = writeln!(io::stdout(), "{}", panweave_pcap::summarize(&b));
                    ExitCode::SUCCESS
                }
                Err(_) => usage(),
            }
        }
        _ => usage(),
    }
}
