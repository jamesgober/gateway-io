//! The first service: answers every request with a hello page. It follows the
//! real service contract (route, then authorize, then content), so the web
//! service replaces it without any change around it.

use crate::gates::Rule;
use crate::passport::{Exit, Passport};
use crate::service::{Service, ServiceCtx};
use crate::stage::Identified;

/// The rule every route of the hello service uses: anyone.
pub const HELLO_RULE: Rule = Rule::public(1);

/// The longest `/slow` waits.
pub const SLOW_MAX_MS: u64 = 30_000;

/// Answers `GET` and `HEAD` with a hello page naming the path, `POST` with the
/// size of the body it received, anything else with 405.
///
/// With the slow route on (for drain tests only), `GET /slow?ms=N` waits `N`
/// milliseconds (at most [`SLOW_MAX_MS`]) before answering.
#[derive(Debug)]
pub struct Hello {
    ctx: ServiceCtx,
    slow: bool,
}

impl Hello {
    /// Built in boot phase 3 with its context.
    #[must_use]
    pub fn new(ctx: ServiceCtx) -> Hello {
        Hello { ctx, slow: false }
    }

    /// The same service with the slow route on.
    #[must_use]
    pub fn with_slow_route(ctx: ServiceCtx) -> Hello {
        Hello { ctx, slow: true }
    }
}

impl Service for Hello {
    fn name(&self) -> &str {
        "hello"
    }

    fn handle(&self, p: Passport<Identified>) -> Exit {
        // The router step: method check, then the route's rule.
        let post = match p.head().method() {
            "GET" | "HEAD" => false,
            "POST" => true,
            _ => return p.refuse(405),
        };
        let mut p = match self.ctx.access().authorize(p, &HELLO_RULE) {
            Ok(cleared) => cleared,
            Err(refused) => return refused,
        };
        if self.slow && p.head().path() == "/slow" {
            let ms = p
                .head()
                .query()
                .and_then(|q| q.strip_prefix("ms="))
                .and_then(|n| n.parse::<u64>().ok())
                .unwrap_or(1000)
                .min(SLOW_MAX_MS);
            std::thread::sleep(std::time::Duration::from_millis(ms));
        }
        let mut page = String::with_capacity(256);
        page.push_str("<!doctype html><meta charset=utf-8><title>hello</title><h1>Hello from WASP</h1><p>path: <code>");
        escape_into(&mut page, p.head().path());
        page.push_str("</code></p>");
        if post {
            page.push_str("<p>body: ");
            page.push_str(&p.body().len().to_string());
            page.push_str(" bytes</p>");
        }
        p.reply().html(200, &page);
        p.answer()
    }
}

/// HTML-escapes `text` into `out`.
fn escape_into(out: &mut String, text: &str) {
    for c in text.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
}
