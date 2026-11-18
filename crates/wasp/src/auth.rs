//! The gates of the process (build-path step 7): one gatekeeper for the
//! core's authentication and the site's authorization, sign-in, sign-out,
//! and CSRF.
//!
//! Accounts and sessions are in memory (gatekeeper-io's own stores): a
//! restart signs everyone out and forgets accounts made at run time. The
//! master secret every gate key is derived from is a file read through
//! key-vault, made on the first run:
//!
//! | Key | Default | Meaning |
//! |---|---|---|
//! | `auth.secret` | `<data folder>/gate.key` | the 32-byte master secret (made on first run, owner-only on Unix) |
//! | `auth.origin` | `https://<first site host>` | the site's origin, for the CSRF origin check (none on a development site: the token decides) |
//! | `auth.admin` | none | an account made at boot, its password from `WASP_ADMIN_PASSWORD` |
//!
//! The password is never read from configuration or written to the log.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use gateway_io::gatekeeper::gatekeeper_io::{
    GateKeys, Gatekeeper, PasswordPolicy, Schema, Standing, keys_from_vault,
};
use key_vault::{FetchContext, FileFetch, KeyFetch, KeyVaultBuilder, RawKey};
use wasp_core::suite::config::Config;

pub use crate::ADMIN_PASSWORD_ENV;

/// The permission the account page needs.
pub const ACCOUNT_READ: &str = "account.read";

/// What `[auth]` says.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AuthSettings {
    /// The master secret's file; `None` for a secret made for this run only.
    pub secret: Option<PathBuf>,
    /// The site's origin, for the CSRF origin check.
    pub origin: Option<String>,
    /// An account made at boot.
    pub admin: Option<String>,
}

impl AuthSettings {
    /// Reads `[auth]`. `data_dir` holds the secret unless `auth.secret`
    /// names a file; without either, the secret lasts for this run only.
    pub fn from_config(
        config: &Config,
        data_dir: Option<&Path>,
        hosts: &[String],
    ) -> Result<AuthSettings, String> {
        let e = |e: wasp_core::suite::Error| e.to_string();
        let secret: Option<PathBuf> = config.get("auth.secret").map_err(e)?;
        let origin: Option<String> = config.get("auth.origin").map_err(e)?;
        Ok(AuthSettings {
            secret: secret.or_else(|| data_dir.map(|d| d.join("gate.key"))),
            origin: origin.or_else(|| hosts.first().map(|h| format!("https://{h}"))),
            admin: config.get("auth.admin").map_err(e)?,
        })
    }
}

/// The schema: what can be granted, and to whom.
pub fn schema() -> Result<Schema, String> {
    Schema::builder("wasp")
        .permissions(&[ACCOUNT_READ])
        .role("member", &[ACCOUNT_READ])
        .build()
        .map_err(|e| format!("auth schema: {e}"))
}

/// The gatekeeper for `settings`, with `admin_password` for the boot account
/// (required when `auth.admin` is set).
pub fn gatekeeper(
    settings: &AuthSettings,
    admin_password: Option<&str>,
) -> Result<Arc<Gatekeeper>, String> {
    let keys = keys(settings.secret.as_deref())?;
    let mut builder = Gatekeeper::builder(schema()?, keys)
        .map_err(|e| format!("gatekeeper: {e}"))?
        .password_policy(PasswordPolicy::new());
    if let Some(origin) = &settings.origin {
        builder = builder.origin(origin);
    }
    let gk = builder.build().map_err(|e| format!("gatekeeper: {e}"))?;
    if let Some(admin) = &settings.admin {
        let password = admin_password.ok_or_else(|| {
            format!("auth.admin is set: put its password in {ADMIN_PASSWORD_ENV}")
        })?;
        gk.create_account(admin, password, Standing::Active, &["member"])
            .map_err(|e| format!("auth.admin {admin}: {e}"))?;
    }
    Ok(Arc::new(gk))
}

/// The gate keys, derived inside key-vault from the master secret.
fn keys(secret: Option<&Path>) -> Result<GateKeys, String> {
    let raw = match secret {
        Some(path) => {
            if !path.exists() {
                create_secret(path)?;
            }
            FileFetch::new(path)
                .fetch(&FetchContext::new("gate/master"))
                .map_err(|e| format!("auth.secret {}: {e}", path.display()))?
        }
        None => RawKey::new(fresh()?.to_vec()),
    };
    let vault = KeyVaultBuilder::new().build();
    let handle = vault
        .register("gate/master", raw)
        .map_err(|e| format!("key vault: {e}"))?;
    keys_from_vault(&vault, handle).map_err(|e| format!("gate keys: {e}"))
}

fn fresh() -> Result<crypt_io::Zeroizing<[u8; 32]>, String> {
    crypt_io::generate_key().map_err(|e| format!("random master secret: {e}"))
}

/// Writes a new 32-byte secret to `path`, owner-only on Unix. Never replaces
/// an existing file.
fn create_secret(path: &Path) -> Result<(), String> {
    let fail = |e: std::io::Error| format!("auth.secret {}: {e}", path.display());
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    let secret = fresh()?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(fail)?;
    file.write_all(&secret[..]).map_err(fail)?;
    file.sync_all().map_err(fail)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_master_secret_is_made_once_and_kept() {
        let dir =
            TempDir(std::env::temp_dir().join(format!("wasp-gate-key-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        let path = dir.0.join("keys").join("gate.key");
        keys(Some(&path)).expect("made");
        let first = std::fs::read(&path).expect("written");
        assert_eq!(first.len(), 32);
        keys(Some(&path)).expect("read");
        assert_eq!(std::fs::read(&path).expect("kept"), first, "never replaced");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
    }

    #[test]
    fn a_boot_account_needs_its_password() {
        let settings = AuthSettings {
            admin: Some("admin@example.com".into()),
            ..AuthSettings::default()
        };
        let err = gatekeeper(&settings, None).expect_err("refused");
        assert!(err.contains(ADMIN_PASSWORD_ENV), "{err}");
        assert!(
            gatekeeper(&settings, Some("short")).is_err(),
            "policy applies"
        );
        assert!(gatekeeper(&settings, Some("a long enough password")).is_ok());
    }

    #[test]
    fn the_origin_defaults_to_the_first_host() {
        let config = Config::from_text("").expect("config");
        let s = AuthSettings::from_config(&config, None, &["blog.example".into()]).expect("auth");
        assert_eq!(s.origin.as_deref(), Some("https://blog.example"));
        assert_eq!(s.secret, None);
        let s = AuthSettings::from_config(&config, Some(Path::new("/data")), &[]).expect("auth");
        assert_eq!(s.origin, None);
        assert_eq!(s.secret, Some(Path::new("/data").join("gate.key")));
    }
}
