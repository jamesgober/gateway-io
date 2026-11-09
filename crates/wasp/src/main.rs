//! The platform process: boot in phases, run, stop in order.
//!
//! ```text
//!  PHASE 0  foundation   config, log, error, kernel (signals hooked, urgent line)
//!  PHASE 1  core boot    the core's seams: authenticator, authorizer, customs, cache
//!  PHASE 2  core load    services register, profiles compile (invalid: refuse to start)
//!  PHASE 3  post-load    services built with their context (no providers yet)
//!  PHASE 4  open         the gateway binds and opens the door: last
//!
//!  stop: 1-2 gateway (door closes, drain)  3-6 core  7 kernel (last)
//! ```

use std::process::ExitCode;
use std::sync::Arc;

use gateway_io::Gateway;
use wasp_core::stub::Hello;
use wasp_core::suite::System;
use wasp_core::suite::log;
use wasp_core::{Core, CoreSubsystem};

fn main() -> ExitCode {
    // PHASE 0: the foundation and the kernel. Nothing is open yet.
    let mut boot = match System::builder("wasp").boot() {
        Ok(boot) => boot,
        Err(error) => return error.report(),
    };

    // PHASES 1 to 3: the core, its services and profiles.
    let slow = boot
        .foundation()
        .config()
        .get_or("hello.slow_route", false)
        .unwrap_or(false);
    let core = match Core::builder()
        .service("hello", move |ctx| {
            if slow {
                Hello::with_slow_route(ctx)
            } else {
                Hello::new(ctx)
            }
        })
        .profile("site", "hello", |_| {})
        .load()
    {
        Ok(core) => Arc::new(core),
        Err(error) => {
            log::error!(
                boot.foundation().log(),
                "core refused to load",
                reason = error.0.as_str()
            );
            return ExitCode::from(78);
        }
    };
    if let Err(error) = boot.start(CoreSubsystem::new(core.clone())) {
        return error.report();
    }

    // PHASE 4: the door opens last.
    if let Err(error) = boot.start(Gateway::new(core)) {
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
