//! The content manifest: entries prepared when they are saved, served from
//! memory, read by the templates through the `View` trait.
//!
//! The heavy work happens when content is saved ([`Manifest::save`]): the
//! body is turned into safe HTML once (every character escaped, paragraphs
//! split), the URL and the listing are computed. A request only borrows what
//! is already there: an entry is an `Arc<Entry>`, the post listing one shared
//! `Arc<Vec<Arc<Entry>>>`, so rendering a page copies no content.

use std::collections::BTreeMap;
use std::sync::Arc;

/// What kind of entry: it picks the default template.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A standalone page (`/about`).
    Page,
    /// A dated post, listed on the home page (`/posts/:slug`).
    Post,
}

impl Kind {
    fn as_str(self) -> &'static str {
        match self {
            Kind::Page => "page",
            Kind::Post => "post",
        }
    }
}

/// One entry as the templates see it (`page.entry`, each of `page.posts`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    /// `page` or `post`.
    pub kind: String,
    /// The slug.
    pub slug: String,
    /// The title (plain text; the template escapes it).
    pub title: String,
    /// The site-relative URL.
    pub url: String,
    /// A one-line summary (plain text).
    pub summary: String,
    /// The body as safe HTML, prepared when the entry was saved.
    pub body: String,
    /// The date (`2026-11-09`), for posts.
    pub date: String,
}

luminess::view!(Entry as "entry" {
    kind: text,
    slug: text,
    title: text,
    url: text,
    summary: text,
    body: html,
    date: text,
});

/// What an editor saves.
#[derive(Clone, Debug)]
pub struct Draft<'a> {
    /// Page or post.
    pub kind: Kind,
    /// The slug: lowercase letters, digits, and `-` only.
    pub slug: &'a str,
    /// The title.
    pub title: &'a str,
    /// A one-line summary.
    pub summary: &'a str,
    /// The body, plain text; blank lines separate paragraphs.
    pub body: &'a str,
    /// The date, for posts.
    pub date: &'a str,
}

/// Why a draft was refused (the editor sees it; nothing is saved).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Invalid(pub String);

impl std::fmt::Display for Invalid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for Invalid {}

/// The content, in memory until a content store exists (build-path step 8).
#[derive(Clone, Debug, Default)]
pub struct Manifest {
    base: String,
    entries: BTreeMap<String, Arc<Entry>>,
    posts: Arc<Vec<Arc<Entry>>>,
}

/// Escapes text for HTML, once, at save time.
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

impl Manifest {
    /// An empty manifest.
    #[must_use]
    pub fn new() -> Manifest {
        Manifest::default()
    }

    /// An empty manifest for a site installed under `base` (`/blog`): entry
    /// URLs are prepared with it.
    #[must_use]
    pub fn with_base(base: &str) -> Manifest {
        Manifest {
            base: base.trim_end_matches('/').to_owned(),
            ..Manifest::default()
        }
    }

    /// Validates and prepares a draft, then stores it (replacing an entry with
    /// the same slug) and rebuilds the post listing, newest first.
    pub fn save(&mut self, draft: &Draft<'_>) -> Result<(), Invalid> {
        let slug_ok = !draft.slug.is_empty()
            && draft
                .slug
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-');
        if !slug_ok {
            return Err(Invalid(format!(
                "slug `{}`: lowercase letters, digits, and `-` only",
                draft.slug
            )));
        }
        if draft.title.trim().is_empty() {
            return Err(Invalid(format!("`{}` has no title", draft.slug)));
        }
        if draft.kind == Kind::Post && draft.date.len() != 10 {
            return Err(Invalid(format!(
                "post `{}` needs a date (YYYY-MM-DD)",
                draft.slug
            )));
        }
        let mut body = String::with_capacity(draft.body.len() + 32);
        for para in draft
            .body
            .split("\n\n")
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            body.push_str("<p>");
            escape_into(&mut body, para);
            body.push_str("</p>");
        }
        let url = match draft.kind {
            Kind::Page => format!("{}/{}", self.base, draft.slug),
            Kind::Post => format!("{}/posts/{}", self.base, draft.slug),
        };
        let entry = Arc::new(Entry {
            kind: draft.kind.as_str().to_owned(),
            slug: draft.slug.to_owned(),
            title: draft.title.to_owned(),
            url,
            summary: draft.summary.to_owned(),
            body,
            date: draft.date.to_owned(),
        });
        self.entries.insert(draft.slug.to_owned(), entry);
        let mut posts: Vec<Arc<Entry>> = self
            .entries
            .values()
            .filter(|e| e.kind == "post")
            .cloned()
            .collect();
        posts.sort_by(|a, b| b.date.cmp(&a.date).then_with(|| a.slug.cmp(&b.slug)));
        self.posts = Arc::new(posts);
        Ok(())
    }

    /// The entry with this slug and kind.
    #[must_use]
    pub fn get(&self, kind: Kind, slug: &str) -> Option<Arc<Entry>> {
        self.entries
            .get(slug)
            .filter(|e| e.kind == kind.as_str())
            .cloned()
    }

    /// The posts, newest first (shared, not copied).
    #[must_use]
    pub fn posts(&self) -> Arc<Vec<Arc<Entry>>> {
        self.posts.clone()
    }

    /// The sample content.
    #[must_use]
    pub fn sample() -> Manifest {
        Manifest::sample_at("")
    }

    /// The sample content for a site under `base`.
    #[must_use]
    pub fn sample_at(base: &str) -> Manifest {
        let mut m = Manifest::with_base(base);
        let drafts = [
            Draft {
                kind: Kind::Post,
                slug: "hello-world",
                title: "Hello, world",
                summary: "The first page through the gateway, the core, and the web service.",
                body: "This page came in through the gateway, was identified by the core, routed by the web service, and rendered by the theme.\n\nEvery value on it was read through a view, never through JSON.",
                date: "2026-11-08",
            },
            Draft {
                kind: Kind::Post,
                slug: "the-passport",
                title: "The passport",
                summary: "One per request, from the pool to the reply and back.",
                body: "Every request carries one from the pool to the reply, and back, wiped.",
                date: "2026-11-09",
            },
            Draft {
                kind: Kind::Post,
                slug: "escaping",
                title: "Tom & Jerry <script>alert(1)</script>",
                summary: "A title with markup in it, written as text.",
                body: "<b>Not bold.</b> & not a tag either.",
                date: "2026-11-10",
            },
            Draft {
                kind: Kind::Page,
                slug: "about",
                title: "About",
                summary: "What this site is.",
                body: "A site in memory, themed from a folder, on the platform's walking skeleton.",
                date: "",
            },
        ];
        for d in &drafts {
            // The sample is fixed and valid.
            let _ = m.save(d);
        }
        m
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_prepares_escaped_paragraphs_and_lists_posts_newest_first() {
        let m = Manifest::sample();
        let e = m.get(Kind::Post, "escaping").expect("entry");
        assert_eq!(
            e.body,
            "<p>&lt;b&gt;Not bold.&lt;/b&gt; &amp; not a tag either.</p>"
        );
        assert_eq!(e.url, "/posts/escaping");
        let slugs: Vec<_> = m.posts().iter().map(|p| p.slug.clone()).collect();
        assert_eq!(slugs, ["escaping", "the-passport", "hello-world"]);
        assert!(m.get(Kind::Post, "about").is_none(), "a page is not a post");
    }

    #[test]
    fn invalid_drafts_are_refused() {
        let mut m = Manifest::new();
        let bad = Draft {
            kind: Kind::Post,
            slug: "Bad Slug",
            title: "x",
            summary: "",
            body: "",
            date: "2026-11-10",
        };
        assert!(m.save(&bad).is_err());
        assert!(
            m.save(&Draft {
                slug: "ok",
                date: "",
                ..bad.clone()
            })
            .is_err(),
            "a post needs a date"
        );
        assert!(
            m.save(&Draft {
                slug: "ok",
                title: " ",
                ..bad
            })
            .is_err()
        );
    }
}
