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

    // PHASE 4: the door opens last.
    if let Err(error) = boot.start(
        Gateway::new(wiring.core)
            .web("web", wiring.site)
            .stages(wiring.stages),
    ) {
        return error.report();
    }

    let system = match boot.ready() {
        Ok(system) => system,
        Err(error) => return error.report(),
    };
    // Parked until a stop signal; then the shutdown order runs in reverse of
    // the start order: gateway, core, members, kernel.
    system.run()
}
