//! What a web service says about the request it is serving, for the
//! gateway's log: the application's error code, a message, and the
//! request's reference (the one an error page shows).
//!
//! ```text
//!  call starts:   the path is set for this worker thread
//!  the service:   note(code, message, reference)        (same thread)
//!  call returns:  the note is taken and kept with the request's ticket
//! ```
//!
//! Everything here is per thread and lives only for one call: a service
//! that hands work to another thread notes nothing from there.

use std::cell::RefCell;

/// The longest message kept, in bytes; a longer one is cut at a character
/// boundary.
pub const MAX_MESSAGE: usize = 512;

/// What the service noted about one request.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Note {
    /// The application's error code (`content.unavailable`), or empty.
    pub code: &'static str,
    /// A message for the log, or empty.
    pub message: Box<str>,
    /// The request's reference, as the visitor sees it, or empty.
    pub reference: Box<str>,
}

thread_local! {
    static PATH: RefCell<String> = const { RefCell::new(String::new()) };
    static NOTE: RefCell<Option<Note>> = const { RefCell::new(None) };
}

/// Notes the application's error code, a message, and the request's
/// reference for the request this thread is serving. A later note replaces
/// an earlier one; an empty `message` keeps the earlier message.
pub fn note(code: &'static str, message: &str, reference: &str) {
    NOTE.with(|n| {
        let mut n = n.borrow_mut();
        let keep = n.take().map(|old| old.message).unwrap_or_default();
        let message = if message.is_empty() {
            keep
        } else {
            cut(message, MAX_MESSAGE).into()
        };
        *n = Some(Note {
            code,
            message,
            reference: reference.into(),
        });
    });
}

/// Whether the request this thread is serving has a path that is `prefix`
/// or under it (`/admin` matches `/admin` and `/admin/edit`, not
/// `/administrator`). `false` outside a call.
#[must_use]
pub fn path_under(prefix: &str) -> bool {
    PATH.with(|p| {
        let p = p.borrow();
        p.strip_prefix(prefix)
            .is_some_and(|rest| rest.is_empty() || rest.starts_with('/'))
    })
}

/// The call starts: `path` is this thread's request.
pub(crate) fn begin(path: &str) {
    PATH.with(|p| {
        let mut p = p.borrow_mut();
        p.clear();
        p.push_str(path);
    });
    NOTE.with(|n| *n.borrow_mut() = None);
}

/// The call returned: what the service noted, if anything.
pub(crate) fn end() -> Option<Note> {
    PATH.with(|p| p.borrow_mut().clear());
    NOTE.with(|n| n.borrow_mut().take())
}

/// `text` cut to at most `max` bytes at a character boundary.
pub(crate) fn cut(text: &str, max: usize) -> &str {
    if text.len() <= max {
        return text;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    &text[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_note_lives_for_one_call_on_its_thread() {
        begin("/admin/edit/x");
        assert!(path_under("/admin"));
        assert!(!path_under("/adm"));
        note(
            "content.unavailable",
            "the store is down",
            "0123456789abcdef",
        );
        note("site.failed", "", "0123456789abcdef");
        let n = end().expect("noted");
        assert_eq!(n.code, "site.failed");
        assert_eq!(
            &*n.message, "the store is down",
            "an empty message keeps the last"
        );
        assert!(end().is_none(), "taken once");
        assert!(!path_under("/admin"), "no path outside a call");
        assert_eq!(cut("héllo", 2), "h");
    }
}
