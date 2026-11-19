//! The platform process: boot in phases, run, stop in order.
//!
//! ```text
//!  PHASE 0  foundation   config, log, error, kernel (signals hooked, urgent line)
//!  PHASE 1  core boot    the core's seams: authenticator, authorizer, customs, cache
//!  PHASE 2  core load    services register, profiles compile (invalid: refuse to start)
//!  PHASE 3  post-load    services built with their context; the theme compiled, its
//!                        watcher started; the web site built
//!  PHASE 4  open         the gateway binds and opens the door: last
//!
//!  stop: 1-2 gateway (door closes, drain)  3-6 core  7 kernel (last)
//! ```
//!
//! A stop is a signal (SIGTERM, SIGINT, Ctrl-C) or, behind an application
//! server (`PORT` set, on Unix), the server letting go: standard input
//! closing when it is a pipe or a socket (how Passenger stops a process, and
//! what the start shim's pipe does when the shim exits), or the parent
//! process going away.

use std::process::ExitCode;

use gateway_io::Gateway;
use wasp_core::CoreSubsystem;
use wasp_core::suite::System;
use wasp_core::suite::log;

fn main() -> ExitCode {
    // PHASE 0: the foundation and the kernel. Nothing is open yet.
    let mut boot = match System::builder("wasp").boot() {
        Ok(boot) => boot,
        Err(error) => return error.report(),
    };

    // `wasp import <folder>`: content into the store, then exit.
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.first().map(String::as_str) == Some("import") {
        let Some(from) = args.get(1) else {
            eprintln!("usage: wasp import <folder with posts/ and pages/>");
            return ExitCode::from(64);
        };
        let data = boot.foundation().paths().data().to_path_buf();
        return match wasp::import(
            &boot.foundation().config(),
            &data,
            std::path::Path::new(from),
        ) {
            Ok(report) => {
                for slug in &report.saved {
                    println!("saved    {slug}");
                }
                for (file, why) in &report.refused {
                    println!("refused  {file}: {why}");
                }
                println!(
                    "{} saved, {} refused",
                    report.saved.len(),
                    report.refused.len()
                );
                if report.refused.is_empty() {
                    ExitCode::SUCCESS
                } else {
                    ExitCode::from(65)
                }
            }
            Err(reason) => {
                eprintln!("import refused: {reason}");
                ExitCode::from(78)
            }
        };
    }

    // PHASES 1 to 3: the core, its services and profiles, the site.
    let data = boot.foundation().paths().data().to_path_buf();
    let wiring = match wasp::wire_in(&boot.foundation().config(), &data) {
        Ok(wiring) => wiring,
        Err(reason) => {
            log::error!(
                boot.foundation().log(),
                "refused to load",
                reason = reason.as_str()
            );
            return ExitCode::from(78);
        }
    };
    for notice in &wiring.notices {
        log::warn!(
            boot.foundation().log(),
            "boot notice",
            notice = notice.as_str()
        );
    }
    if let Err(error) = boot.start(CoreSubsystem::new(wiring.core.clone())) {
        return error.report();
    }
    if let Err(error) = boot.start(wiring.theme) {
        return error.report();
    }

    watch_providers(boot.foundation(), wiring.core.clone());

    // PHASE 4: the door opens last.
    if let Err(error) = boot.start(
        Gateway::new(wiring.core)
            .web("web", wiring.site)
            .stages(wiring.stages),
    ) {
        return error.report();
    }

    #[cfg(unix)]
    if std::env::var_os("PORT").is_some() {
        stop_with_front_end(boot.foundation());
    }

    let system = match boot.ready() {
        Ok(system) => system,
        Err(error) => return error.report(),
    };
    // Parked until a stop signal; then the shutdown order runs in reverse of
    // the start order: gateway, core, members, kernel.
    system.run()
}

/// Logs a warning when a provider (the content store, the database) stops
/// serving, and a line when it serves again: what `/ready` answering 503
/// means. A database that went read-only (a full disk) serves again only
/// after a restart.
fn watch_providers(
    foundation: &wasp_core::suite::Foundation,
    core: std::sync::Arc<wasp_core::Core>,
) {
    let f = foundation.clone();
    let _ = std::thread::Builder::new()
        .name("wasp-providers".into())
        .spawn(move || {
            let mut down: Vec<String> = Vec::new();
            loop {
                std::thread::sleep(std::time::Duration::from_secs(5));
                for p in core.providers() {
                    let name = p.name().to_owned();
                    let was_down = down.contains(&name);
                    match (p.healthy(), was_down) {
                        (false, false) => {
                            log::warn!(f.log(), "store not serving", provider = name.as_str());
                            down.push(name);
                        }
                        (true, true) => {
                            log::info!(f.log(), "store serving again", provider = name.as_str());
                            down.retain(|n| *n != name);
                        }
                        _ => {}
                    }
                }
            }
        });
}

/// Behind an application server: asks for the same clean stop a SIGTERM
/// would when standard input closes (only when it is a pipe or a socket: a
/// terminal or `/dev/null` is not a front end) or when the parent process
/// is gone (the process was handed to another parent).
#[cfg(unix)]
fn stop_with_front_end(foundation: &wasp_core::suite::Foundation) {
    use std::io::Read;
    use std::os::unix::fs::FileTypeExt;

    let piped = std::fs::metadata("/dev/stdin").is_ok_and(|m| {
        let t = m.file_type();
        t.is_fifo() || t.is_socket()
    });
    if piped {
        let f = foundation.clone();
        let _ = std::thread::Builder::new()
            .name("wasp-stdin".into())
            .spawn(move || {
                let mut sink = [0u8; 256];
                let mut stdin = std::io::stdin().lock();
                loop {
                    match stdin.read(&mut sink) {
                        Ok(0) => break,
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                        Err(_) => break,
                        Ok(_) => {}
                    }
                }
                f.kernel()
                    .request_supervisor_stop("standard input closed (the front end let go)");
            });
    }
    let parent = std::os::unix::process::parent_id();
    if parent > 1 {
        let f = foundation.clone();
        let _ = std::thread::Builder::new()
            .name("wasp-parent".into())
            .spawn(move || {
                while std::os::unix::process::parent_id() == parent {
                    std::thread::sleep(std::time::Duration::from_millis(500));
                }
                f.kernel()
                    .request_supervisor_stop("the parent process is gone");
            });
    }
}
