//! Host profiles: one process, several sites, chosen by the request's
//! `Host`.
//!
//! ```toml
//! [host]
//! default = "main"            # a host no profile names gets this one (else 421)
//!
//! [host.main]
//! hosts = ["example.com", "www.example.com"]
//!
//! [host.blog]
//! hosts = ["blog.example.com", "*.blog.example.com"]
//! name = "The Blog"           # default: site.name
//! theme = "themes/blog"       # default: site.theme
//! content = "blog"            # the content site; default: the profile's name
//! realm = "blog"              # accounts and sessions of its own ("shared": the default)
//! admin = "you@example.com"   # its realm's boot account (password: WASP_ADMIN_PASSWORD)
//!
//! [host.blog.errors.404]      # falls back to [errors.*]
//! message = "No such post."
//!
//! [host.blog.log_rule.misses] # falls back to [log_rule.*]
//! codes = ["404"]
//! ```
//!
//! An exact name wins over a wildcard; among wildcards the longest wins. A
//! wildcard `*.example.com` matches one more label (`a.example.com`), never
//! `example.com` itself or `a.b.example.com`. A host is in at most one
//! profile. Without `[host.*]` the site is one profile from `[site]`.

use std::path::PathBuf;

use gateway_io::{Answered, Caller, WebService};
use serve_net::{Envelope, Finished, HttpHead, HttpReply, HttpRequest, Outcome, WorkClass};
use wasp_core::suite::config::Config;

/// One profile.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProfile {
    /// Its name (`[host.<name>]`).
    pub name: String,
    /// Exact host names, lower case.
    pub exact: Vec<String>,
    /// Wildcards, as the suffix after `*` (`.example.com`).
    pub wildcards: Vec<String>,
    /// The site's name, when it differs from `site.name`.
    pub site_name: Option<String>,
    /// The theme folder, when it differs from `site.theme`.
    pub theme: Option<PathBuf>,
    /// The content site.
    pub content: String,
    /// The accounts realm: `shared` (nex-db's default, with `auth.admin`),
    /// or a realm of its own, whose accounts and sessions no other realm
    /// sees.
    pub realm: String,
    /// The boot account of a realm of its own.
    pub admin: Option<String>,
}

/// Every profile, and the default one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostProfiles {
    /// The profiles, in name order.
    pub profiles: Vec<HostProfile>,
    /// The profile a host no profile names gets.
    pub default: Option<usize>,
}

const PROFILE_KEYS: &[&str] = &[
    "admin", "content", "errors", "hosts", "log_rule", "name", "realm", "theme",
];

/// `host` as profiles compare it: lower case, without a port or a trailing
/// dot.
#[must_use]
pub fn normalize(host: &str) -> String {
    let h = host.trim();
    let h = if let Some(rest) = h.strip_prefix('[') {
        // An IPv6 literal: `[::1]:8080`.
        rest.split(']').next().unwrap_or("")
    } else {
        h.rsplit_once(':').map_or(h, |(name, port)| {
            if port.bytes().all(|b| b.is_ascii_digit()) {
                name
            } else {
                h
            }
        })
    };
    h.trim_end_matches('.').to_ascii_lowercase()
}

fn name_ok(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

impl HostProfiles {
    /// The profiles `[host.*]` sets, or `None` when there are none.
    pub fn from_config(config: &Config) -> Result<Option<HostProfiles>, String> {
        let e = |e: wasp_core::suite::Error| e.to_string();
        let names: Vec<&str> = config
            .keys("host")
            .into_iter()
            .filter(|k| *k != "default")
            .collect();
        if names.is_empty() {
            if config.contains("host.default") {
                return Err(
                    "host.default names a profile, but there is no [host.<name>]".to_owned(),
                );
            }
            return Ok(None);
        }
        let mut profiles = Vec::new();
        let mut seen: Vec<(String, String)> = Vec::new();
        for name in names {
            let at = format!("host.{name}");
            if !name_ok(name) || name.contains('.') {
                return Err(format!(
                    "[{at}]: a profile name is lower case letters, digits and `-`"
                ));
            }
            if let Some(k) = config
                .keys(&at)
                .into_iter()
                .find(|k| !PROFILE_KEYS.contains(k))
            {
                return Err(format!(
                    "unknown key `{at}.{k}`: the keys of a host profile are {}",
                    PROFILE_KEYS.join(", ")
                ));
            }
            let hosts: Vec<String> = config
                .get(&format!("{at}.hosts"))
                .map_err(e)?
                .ok_or_else(|| format!("{at}.hosts is missing"))?;
            if hosts.is_empty() {
                return Err(format!("{at}.hosts is empty"));
            }
            let mut exact = Vec::new();
            let mut wildcards = Vec::new();
            for h in &hosts {
                let n = h.trim().to_ascii_lowercase();
                if let Some(rest) = n.strip_prefix("*.") {
                    if !name_ok(rest) || !rest.contains('.') {
                        return Err(format!(
                            "{at}.hosts: `{h}`: a wildcard is `*.` and a name of two labels or more (`*.example.com`)"
                        ));
                    }
                    wildcards.push(format!(".{rest}"));
                } else if name_ok(&n) {
                    exact.push(n.clone());
                } else {
                    return Err(format!("{at}.hosts: `{h}` is not a host name"));
                }
                if let Some((_, other)) = seen.iter().find(|(x, _)| *x == n) {
                    return Err(format!(
                        "{at}.hosts: `{h}` is in [host.{other}] too; a host is in one profile"
                    ));
                }
                seen.push((n, name.to_owned()));
            }
            let realm: String = config
                .get_or(&format!("{at}.realm"), "shared".to_owned())
                .map_err(e)?;
            let realm_ok = realm == "shared"
                || (realm.len() <= 32
                    && realm.starts_with(|c: char| c.is_ascii_lowercase())
                    && realm
                        .bytes()
                        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'));
            if !realm_ok || realm == "users" {
                return Err(format!(
                    "{at}.realm is `{realm}`: `shared`, or a name of lower case letters, digits and `_` (not `users`)"
                ));
            }
            let admin: Option<String> = config.get(&format!("{at}.admin")).map_err(e)?;
            if admin.is_some() && realm == "shared" {
                return Err(format!(
                    "{at}.admin is for a realm of its own; the shared realm's boot account is auth.admin"
                ));
            }
            let content: String = config
                .get_or(&format!("{at}.content"), name.to_owned())
                .map_err(e)?;
            if !name_ok(&content) || content.contains('.') {
                return Err(format!(
                    "{at}.content: a content site is lower case letters, digits and `-`"
                ));
            }
            profiles.push(HostProfile {
                name: name.to_owned(),
                exact,
                wildcards,
                site_name: config.get(&format!("{at}.name")).map_err(e)?,
                theme: config.get(&format!("{at}.theme")).map_err(e)?,
                content,
                realm,
                admin,
            });
        }
        let default = match config.get::<String>("host.default").map_err(e)? {
            None => None,
            Some(d) => Some(
                profiles
                    .iter()
                    .position(|p| p.name == d)
                    .ok_or_else(|| format!("host.default is `{d}`: no [host.{d}]"))?,
            ),
        };
        Ok(Some(HostProfiles { profiles, default }))
    }

    /// The profile that serves `host` (as a request names it): an exact
    /// name, else the longest wildcard, else the default.
    #[must_use]
    pub fn pick(&self, host: &str) -> Option<usize> {
        let h = normalize(host);
        if let Some(i) = self.profiles.iter().position(|p| p.exact.contains(&h)) {
            return Some(i);
        }
        let mut best: Option<(usize, usize)> = None;
        for (i, p) in self.profiles.iter().enumerate() {
            for w in &p.wildcards {
                // One more label: `a.example.com` for `.example.com`.
                if let Some(label) = h.strip_suffix(w.as_str())
                    && !label.is_empty()
                    && !label.contains('.')
                    && best.is_none_or(|(_, len)| w.len() > len)
                {
                    best = Some((i, w.len()));
                }
            }
        }
        best.map(|(i, _)| i).or(self.default)
    }
}

/// The core's authenticator with host profiles that have realms of their
/// own: each request is authenticated by its profile's realm, so a session
/// of one realm is no one on another profile. A host no profile names is a
/// guest (the router answers it 421, or the default profile, whose realm
/// then decides).
pub struct HostAuth {
    profiles: HostProfiles,
    realms: Vec<std::sync::Arc<dyn wasp_core::Authenticator>>,
}

impl HostAuth {
    /// One authenticator per profile, in the profiles' order.
    #[must_use]
    pub fn new(
        profiles: HostProfiles,
        realms: Vec<std::sync::Arc<dyn wasp_core::Authenticator>>,
    ) -> HostAuth {
        HostAuth { profiles, realms }
    }
}

impl wasp_core::Authenticator for HostAuth {
    fn authenticate(
        &self,
        request: wasp_core::RequestView<'_>,
        profile: &wasp_core::Profile,
        out: &mut wasp_core::AuthOut,
    ) -> wasp_core::Authentication {
        let host = request
            .head()
            .header("host")
            .and_then(|h| std::str::from_utf8(h).ok())
            .unwrap_or("");
        match self.profiles.pick(host).and_then(|i| self.realms.get(i)) {
            Some(realm) => realm.authenticate(request, profile, out),
            None => wasp_core::Authentication::Identified(wasp_core::Identity::guest()),
        }
    }
}

/// The site's web service with host profiles: hands each request to the
/// site its `Host` names; a host no profile names gets the default
/// profile, else 421, never another profile's site.
pub struct HostRouter {
    profiles: HostProfiles,
    sites: Vec<Box<dyn WebService>>,
}

impl HostRouter {
    /// One site per profile, in the profiles' order.
    #[must_use]
    pub fn new(profiles: HostProfiles, sites: Vec<Box<dyn WebService>>) -> HostRouter {
        HostRouter { profiles, sites }
    }

    fn site_for(&self, host: Option<&str>) -> Option<&dyn WebService> {
        let i = self.profiles.pick(host.unwrap_or(""))?;
        self.sites.get(i).map(AsRef::as_ref)
    }
}

impl WebService for HostRouter {
    fn respond(
        &self,
        req: &HttpRequest<'_>,
        env: &Envelope,
        caller: &Caller<'_>,
        reply: &mut HttpReply,
    ) -> Answered {
        let host = req.head().header_str("host");
        match self.site_for(host) {
            Some(site) => site.respond(req, env, caller, reply),
            None => {
                reply.text(421, "This server does not serve that host.\n");
                Answered::from(Outcome::Done)
            }
        }
    }

    fn classify(&self, head: &HttpHead<'_>) -> WorkClass {
        self.site_for(head.header_str("host"))
            .map_or(WorkClass::Quick, |s| s.classify(head))
    }

    fn done(&self, env: &Envelope, finished: &Finished) {
        // The request's head is gone by now: every site forgets what it kept
        // for it (each keeps only its own requests).
        for site in &self.sites {
            site.done(env, finished);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profiles(text: &str) -> Result<Option<HostProfiles>, String> {
        HostProfiles::from_config(&Config::from_text(text).expect("toml"))
    }

    #[test]
    fn hosts_are_matched_exactly_then_by_the_longest_wildcard() {
        let p = profiles(
            "[host.main]\nhosts = [\"example.com\", \"www.example.com\", \"*.example.com\"]\n\
             [host.blog]\nhosts = [\"*.blog.example.com\", \"blog.example.com\"]\n",
        )
        .expect("ok")
        .expect("profiles");
        let name = |h: &str| p.pick(h).map(|i| p.profiles[i].name.as_str());
        assert_eq!(name("Example.COM:8443"), Some("main"));
        assert_eq!(name("shop.example.com"), Some("main"));
        assert_eq!(
            name("blog.example.com"),
            Some("blog"),
            "exact beats a wildcard"
        );
        assert_eq!(
            name("ann.blog.example.com"),
            Some("blog"),
            "the longest wildcard"
        );
        assert_eq!(name("a.b.c.example.com"), None, "one label only");
        assert_eq!(name("example.org"), None, "no default: 421");
        assert_eq!(name("example.com."), Some("main"));
    }

    #[test]
    fn profiles_are_checked() {
        for (text, says) in [
            (
                "[host.a]\nhosts = [\"x.com\"]\n[host.b]\nhosts = [\"X.com\"]\n",
                "in [host.a] too",
            ),
            ("[host.a]\nhosts = [\"*.com\"]\n", "two labels"),
            ("[host.a]\nhosts = [\"bad host\"]\n", "not a host name"),
            ("[host.a]\nhost = [\"x.com\"]\n", "unknown key"),
            (
                "[host.a]\nhosts = [\"x.com\"]\nrealm = \"Own\"\n",
                "lower case",
            ),
            (
                "[host.a]\nhosts = [\"x.com\"]\nrealm = \"users\"\n",
                "not `users`",
            ),
            (
                "[host.a]\nhosts = [\"x.com\"]\nadmin = \"a@x.com\"\n",
                "realm of its own",
            ),
            ("[host]\ndefault = \"a\"\n", "no [host.<name>]"),
            (
                "[host]\ndefault = \"b\"\n[host.a]\nhosts = [\"x.com\"]\n",
                "no [host.b]",
            ),
        ] {
            let e = profiles(text).expect_err(text);
            assert!(e.contains(says), "{text}: {e}");
        }
        assert!(profiles("[site]\nname = \"x\"\n").expect("ok").is_none());
        let d = profiles("[host]\ndefault = \"a\"\n[host.a]\nhosts = [\"x.com\"]\n")
            .expect("ok")
            .expect("profiles");
        assert_eq!(d.pick("anything.org"), Some(0), "the default");
    }
}
