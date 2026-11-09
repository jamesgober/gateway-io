//! The platform process's wiring: which services the core declares, which
//! profile uses which, and the web site attached to the gateway. `main` boots
//! it; the tests open the same wiring on a loopback port.

pub mod site;

use std::sync::Arc;

use gateway_io::WaspGate;
use wasp_core::Core;
use wasp_core::stub::Hello;
use wasp_core::suite::config::Config;
use web_net::App;

/// The core and the site, ready for the gateway.
pub struct Wiring {
    /// The loaded core (phases 1 to 3).
    pub core: Arc<Core>,
    /// The web site, attached to the core's external service `web`.
    pub site: App<WaspGate>,
}

impl std::fmt::Debug for Wiring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Wiring").field("core", &self.core).finish()
    }
}

/// Phases 1 to 3 from configuration.
///
/// Two services are declared: `web` (external: the web site on web-net) and
/// `hello` (a passport service, the step-2 stub, with its slow route when
/// `hello.slow_route` is on, for drain tests). `[site] service` picks the one
/// the `site` profile uses; the default is `web`.
pub fn wire(config: &Config) -> Result<Wiring, String> {
    let slow: bool = config
        .get_or("hello.slow_route", false)
        .map_err(|e| e.to_string())?;
    let service: String = config
        .get_or("site.service", "web".to_owned())
        .map_err(|e| e.to_string())?;
    if service != "web" && service != "hello" {
        return Err(format!(
            "site.service must be `web` or `hello`, not `{service}`"
        ));
    }
    let core = Core::builder()
        .external("web")
        .service("hello", move |ctx| {
            if slow {
                Hello::with_slow_route(ctx)
            } else {
                Hello::new(ctx)
            }
        })
        .profile("site", &service, |_| {})
        .load()
        .map_err(|e| e.0)?;
    let core = Arc::new(core);
    let settings = site::SiteSettings::from_config(config)?;
    let site = site::build(core.access().clone(), site::Content::sample(), &settings)
        .map_err(|e| format!("site: {e}"))?;
    Ok(Wiring { core, site })
}
