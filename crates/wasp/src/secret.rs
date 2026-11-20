//! The site's master secret: 32 random bytes in a file, made on the first
//! run (owner-only on Unix) and read on every later one. Keys that must
//! outlive a restart (the gates', the CSRF tokens') come from it, each
//! derived for its own purpose, so a form opened before a restart still
//! posts after it.
//!
//! | Key | Default | Meaning |
//! |---|---|---|
//! | `auth.secret` | `gate.key` beside `nex.path` with nex-db, else `<data folder>/gate.key` | the master secret's file |
//!
//! Rotating it on purpose: stop the site, move the file away, start again.
//! Every open form (and, with the gatekeeper, every session) is then
//! refused once.

use std::io::Write;
use std::path::Path;

use crypt_io::Zeroizing;

/// A master secret's length.
pub const LEN: usize = 32;

/// 32 fresh random bytes.
pub fn fresh() -> Result<Zeroizing<[u8; LEN]>, String> {
    crypt_io::generate_key().map_err(|e| format!("random master secret: {e}"))
}

/// Writes a new secret to `path`, owner-only on Unix. Never replaces an
/// existing file, and never shows a half-written one where it can help it:
/// the secret is written to a file of its own first and linked into place,
/// so of two processes starting at once one makes it and the other reads
/// that one. On a file system without hard links (some network and FAT
/// mounts) the secret is written in place, created only if it is not there;
/// a reader that finds it still short waits a moment for it.
pub fn create(path: &Path) -> Result<(), String> {
    static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let fail = |e: std::io::Error| format!("auth.secret {}: {e}", path.display());
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        std::fs::create_dir_all(dir).map_err(fail)?;
    }
    let n = NEXT.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_owned();
    name.push(format!(".{}-{n}.new", std::process::id()));
    let draft = path.with_file_name(name);
    let secret = fresh()?;
    let linked = write_new(&draft, &secret[..]).and_then(|()| std::fs::hard_link(&draft, path));
    let _ = std::fs::remove_file(&draft);
    match linked {
        Ok(()) => Ok(()),
        // Another process made it first: its secret is the one.
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
        // No hard links here: created in place, only if it is not there.
        Err(_) => match write_new(path, &secret[..]) {
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            other => other.map_err(fail),
        },
    }
}

/// Writes `bytes` to a new file at `path` (owner-only on Unix), synced.
fn write_new(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

/// How long a reader waits for a secret another process is still writing
/// in place.
#[cfg(feature = "store-nex")]
const SHORT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// The secret in `path`, made first when there is none. Refused when the
/// file is not exactly [`LEN`] bytes, or (on Unix) when others may read it.
#[cfg(feature = "store-nex")]
pub fn read_or_create(path: &Path) -> Result<Zeroizing<[u8; LEN]>, String> {
    use std::io::Read;

    let fail = |e: std::io::Error| format!("auth.secret {}: {e}", path.display());
    if !path.exists() {
        create(path)?;
    }
    let until = std::time::Instant::now() + SHORT_WAIT;
    let bytes = loop {
        let mut file = std::fs::File::open(path).map_err(fail)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = file.metadata().map_err(fail)?.permissions().mode();
            if mode & 0o077 != 0 {
                return Err(format!(
                    "auth.secret {} can be read by other users: make it owner-only (chmod 600)",
                    path.display()
                ));
            }
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(LEN + 1));
        (&mut file)
            .take(LEN as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(fail)?;
        // Still being written in place by another process: wait for it.
        if bytes.len() < LEN && std::time::Instant::now() < until {
            std::thread::sleep(std::time::Duration::from_millis(20));
            continue;
        }
        break bytes;
    };
    if bytes.len() != LEN {
        return Err(format!(
            "auth.secret {} is not a {LEN}-byte secret: move it away to have a new one made",
            path.display()
        ));
    }
    let mut secret = Zeroizing::new([0u8; LEN]);
    secret.copy_from_slice(&bytes);
    Ok(secret)
}

/// The key for `purpose`, derived from `master` (HKDF-SHA256).
#[cfg(feature = "store-nex")]
pub fn derive(master: &[u8; LEN], purpose: &str) -> Result<Zeroizing<[u8; LEN]>, String> {
    let mut key = Zeroizing::new([0u8; LEN]);
    crypt_io::kdf::hkdf_sha256_into(master, None, purpose.as_bytes(), &mut key[..])
        .map_err(|e| format!("deriving the {purpose} key: {e}"))?;
    Ok(key)
}

#[cfg(all(test, feature = "store-nex"))]
mod tests {
    use super::*;

    struct TempDir(std::path::PathBuf);
    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn the_secret_is_made_once_and_read_after() {
        let dir = TempDir(std::env::temp_dir().join(format!("wasp-secret-{}", std::process::id())));
        let _ = std::fs::remove_dir_all(&dir.0);
        let path = dir.0.join("gate.key");
        let first = read_or_create(&path).expect("made");
        let again = read_or_create(&path).expect("read");
        assert_eq!(*first, *again, "the same secret after a restart");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        let a = derive(&first, "wasp csrf v1").expect("csrf");
        let b = derive(&first, "something else").expect("other");
        assert_ne!(*a, *b, "one key per purpose");
        assert_ne!(*a, *first, "never the secret itself");

        // Processes starting at once on a new data folder: one secret, never
        // a half-written file.
        let race = dir.0.join("race").join("gate.key");
        let made: Vec<[u8; LEN]> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| s.spawn(|| *read_or_create(&race).expect("made or read")))
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("thread"))
                .collect()
        });
        assert!(made.iter().all(|m| *m == made[0]), "one secret for all");
        let left: Vec<_> = std::fs::read_dir(dir.0.join("race"))
            .expect("dir")
            .flatten()
            .map(|e| e.file_name())
            .collect();
        assert_eq!(left.len(), 1, "no draft left behind: {left:?}");

        std::fs::write(&path, b"short").expect("write");
        let err = read_or_create(&path).expect_err("not 32 bytes");
        assert!(err.contains("32-byte"), "{err}");
    }
}
