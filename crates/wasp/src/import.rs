//! Content import: posts and pages from files into the content store,
//! through the same validation and preparation as any save.
//!
//! ```text
//!  <folder>/posts/<slug>.md     a post   (title and date required)
//!  <folder>/pages/<slug>.md     a page   (title required)
//! ```
//!
//! Each file starts with a short header of `key: value` lines, ends the
//! header with a blank line, and the rest is the body: plain text, blank
//! lines between paragraphs (it is escaped, never trusted as HTML).
//!
//! ```text
//! title: Hello from a file
//! date: 2026-11-18
//! summary: One line for the listing.
//! description: The line search results show under the title.
//!
//! The first paragraph.
//!
//! The second.
//! ```
//!
//! The search and sharing fields are header keys too: `seo_title`,
//! `description`, `og_title`, `og_description`, `canonical`, `robots`,
//! `og_image`, `twitter_card`.
//!
//! A file whose slug, header, or fields do not pass is reported and skipped;
//! the rest are saved. An entry with a slug already in the store is
//! replaced.

use std::path::Path;

use crate::content::{Draft, Kind, Manifest, Meta};

/// The largest file read.
pub const MAX_FILE_BYTES: u64 = 1 << 20;

/// The most files read in one import.
pub const MAX_FILES: usize = 10_000;

/// What an import did.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Report {
    /// The slugs saved, in the order they were read.
    pub saved: Vec<String>,
    /// The files skipped, with why.
    pub refused: Vec<(String, String)>,
}

/// One file, parsed.
struct Parsed {
    title: String,
    date: String,
    summary: String,
    body: String,
    meta: Meta,
}

fn parse(text: &str) -> Result<Parsed, String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut parsed = Parsed {
        title: String::new(),
        date: String::new(),
        summary: String::new(),
        body: String::new(),
        meta: Meta::default(),
    };
    let mut lines = text.lines();
    for line in lines.by_ref() {
        if line.trim().is_empty() {
            break;
        }
        let Some((key, value)) = line.split_once(':') else {
            return Err(format!("header line `{line}` is not `key: value`"));
        };
        let value = value.trim().to_owned();
        match key.trim() {
            "title" => parsed.title = value,
            "date" => parsed.date = value,
            "summary" => parsed.summary = value,
            other => match parsed.meta.get_mut(other) {
                Some(field) => *field = value,
                None => {
                    return Err(format!(
                        "unknown header `{other}` (title, date, summary, {})",
                        Meta::FIELDS.join(", ")
                    ));
                }
            },
        }
    }
    parsed.body = lines.collect::<Vec<_>>().join("\n");
    Ok(parsed)
}

/// Reads `<from>/posts` and `<from>/pages` into `manifest` (and so its
/// store). A missing folder of the two is skipped; `from` itself must exist.
pub fn import_into(manifest: &mut Manifest, from: &Path) -> Result<Report, String> {
    if !from.is_dir() {
        return Err(format!("{} is not a folder", from.display()));
    }
    let mut report = Report::default();
    let mut seen = 0;
    for (folder, kind) in [("posts", Kind::Post), ("pages", Kind::Page)] {
        let dir = from.join(folder);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        let mut files: Vec<_> = entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "md"))
            .collect();
        files.sort();
        for path in files {
            seen += 1;
            if seen > MAX_FILES {
                return Err(format!("more than {MAX_FILES} files"));
            }
            let shown = format!(
                "{folder}/{}",
                path.file_name().unwrap_or_default().to_string_lossy()
            );
            let Some(slug) = path.file_stem().and_then(|s| s.to_str()).map(str::to_owned) else {
                report
                    .refused
                    .push((shown, "the file name is not UTF-8".into()));
                continue;
            };
            let meta = match std::fs::symlink_metadata(&path) {
                Ok(m) if m.file_type().is_symlink() => {
                    report
                        .refused
                        .push((shown, "symbolic links are not read".into()));
                    continue;
                }
                Ok(m) => m,
                Err(e) => {
                    report.refused.push((shown, e.to_string()));
                    continue;
                }
            };
            if meta.len() > MAX_FILE_BYTES {
                report
                    .refused
                    .push((shown, format!("over {MAX_FILE_BYTES} bytes")));
                continue;
            }
            let parsed = match std::fs::read_to_string(&path)
                .map_err(|e| e.to_string())
                .and_then(|t| parse(&t))
            {
                Ok(p) => p,
                Err(e) => {
                    report.refused.push((shown, e));
                    continue;
                }
            };
            let draft = Draft {
                kind,
                slug: &slug,
                title: &parsed.title,
                summary: &parsed.summary,
                body: &parsed.body,
                date: &parsed.date,
                meta: parsed.meta.clone(),
            };
            match manifest.save(&draft) {
                Ok(()) => report.saved.push(slug),
                Err(e) => report.refused.push((shown, e.to_string())),
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_header_then_a_body() {
        let p = parse("title: Hi\ndate: 2026-11-18\n\nOne.\n\nTwo.").expect("parsed");
        assert_eq!((p.title.as_str(), p.date.as_str()), ("Hi", "2026-11-18"));
        assert_eq!(p.body, "One.\n\nTwo.");
        assert!(
            parse("tilte: typo\n\nx").is_err(),
            "unknown keys are refused"
        );
        assert!(parse("no colon here\n\nx").is_err());
        assert_eq!(parse("\u{feff}title: Bom\n\nx").expect("bom").title, "Bom");
    }
}
