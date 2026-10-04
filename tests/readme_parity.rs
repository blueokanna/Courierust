//! The English and Chinese documentation must stay in step.
//!
//! Two rules, from strictest to loosest:
//!
//! 1. **`README.md` vs `README_CN.md` — byte for byte.** Every fenced block a
//!    reader would copy (`rust`, `bash`, `toml`, `nginx`, `yaml`) must have
//!    the same info string and the same body, in the same order. The
//!    `mermaid` layout diagram may have translated labels, so only its
//!    structure (node ids, edges, classes) is compared, with string literals
//!    and `%%` comments removed. The English README is additionally compiled
//!    as doctests from `courierust::ReadmeDoctests` (`#[cfg(doctest)]` in
//!    `src/lib.rs`), so a block that stops compiling fails `cargo test --doc`.
//! 2. **`src/<module>/README.md` vs `README_CN.md` — code, not comments.**
//!    The Chinese files translate the comments inside their snippets, so the
//!    comparison drops `//` and `/* … */` comments (string literals are
//!    respected, so `"http://…"` survives) and requires the remaining code to
//!    be identical, block for block and line for line.
//!
//! Together: if it is in the README and it is code, it compiles, and both
//! languages carry the same code.

const EN: &str = include_str!("../README.md");
const CN: &str = include_str!("../README_CN.md");

/// Languages whose blocks a reader is expected to copy verbatim.
const COPIED_LANGUAGES: [&str; 5] = ["rust", "bash", "toml", "nginx", "yaml"];

/// The fenced blocks a reader copies, in file order: `(info, body)`.
fn copied_blocks(src: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    let mut lines = src.lines();
    while let Some(line) = lines.next() {
        let Some(info) = line.trim().strip_prefix("```") else {
            continue;
        };
        let info = info.trim();
        if !COPIED_LANGUAGES
            .iter()
            .any(|lang| info == *lang || info.starts_with(&format!("{lang},")))
        {
            continue;
        }
        let mut body = String::new();
        for body_line in lines.by_ref() {
            if body_line.trim() == "```" {
                break;
            }
            body.push_str(body_line);
            body.push('\n');
        }
        out.push((info.to_string(), body));
    }
    out
}

/// The structure of the first `mermaid` block: non-empty lines with `%%`
/// comments dropped and `"…"` label text removed. Node ids, edges and
/// class assignments must match; the labels themselves are translated.
fn mermaid_structure(src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut inside = false;
    for line in src.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("```mermaid") {
            inside = true;
            continue;
        }
        if inside && trimmed == "```" {
            break;
        }
        if !inside || trimmed.is_empty() || trimmed.starts_with("%%") {
            continue;
        }
        out.push(strip_quoted(line).trim_end().to_string());
    }
    out
}

fn strip_quoted(line: &str) -> String {
    let mut out = String::new();
    let mut in_quotes = false;
    for ch in line.chars() {
        match ch {
            '"' => in_quotes = !in_quotes,
            _ if !in_quotes => out.push(ch),
            _ => {}
        }
    }
    out
}

#[test]
fn readmes_share_the_same_code_blocks() {
    let en = copied_blocks(EN);
    let cn = copied_blocks(CN);
    assert!(
        !en.is_empty(),
        "no copyable code blocks found in README.md — the extractor is wrong"
    );
    assert_eq!(
        en.len(),
        cn.len(),
        "README.md has {} copyable blocks but README_CN.md has {}",
        en.len(),
        cn.len()
    );
    for (index, ((en_info, en_body), (cn_info, cn_body))) in en.iter().zip(cn.iter()).enumerate() {
        assert_eq!(
            en_info, cn_info,
            "block #{index}: fence language differs between the READMEs"
        );
        assert_eq!(
            en_body, cn_body,
            "block #{index} ({en_info}): code differs between README.md and README_CN.md"
        );
    }
}

#[test]
fn readmes_share_the_same_layout_graph() {
    let en = mermaid_structure(EN);
    let cn = mermaid_structure(CN);
    assert!(
        !en.is_empty(),
        "no mermaid block found in README.md — the extractor is wrong"
    );
    assert_eq!(
        en, cn,
        "the layout diagrams differ in structure (only labels may be translated)"
    );
}

// ---------------------------------------------------------------------
// Module READMEs: same code, comments may be translated
// ---------------------------------------------------------------------

/// A snippet with `//` and `/* … */` comments removed and trailing
/// whitespace trimmed: the code a reader copies. String literals are
/// respected, so a URL like `"http://127.0.0.1:8080/"` survives.
fn code_only(snippet: &str) -> String {
    let mut lines: Vec<String> = Vec::new();
    let mut in_block = false;
    for line in snippet.lines() {
        let mut out = String::new();
        let mut chars = line.chars().peekable();
        let mut in_string = false;
        while let Some(ch) = chars.next() {
            if in_block {
                if ch == '*' && chars.peek() == Some(&'/') {
                    chars.next();
                    in_block = false;
                }
                continue;
            }
            if in_string {
                out.push(ch);
                if ch == '\\' {
                    if let Some(escaped) = chars.next() {
                        out.push(escaped);
                    }
                } else if ch == '"' {
                    in_string = false;
                }
                continue;
            }
            match ch {
                '"' => {
                    in_string = true;
                    out.push(ch);
                }
                '/' if chars.peek() == Some(&'/') => break,
                '/' if chars.peek() == Some(&'*') => {
                    chars.next();
                    in_block = true;
                }
                _ => out.push(ch),
            }
        }
        lines.push(out.trim_end().to_string());
    }
    // A run of comment-only lines becomes a run of empty lines; its length
    // depends on how verbose each translation is, so collapse the runs.
    let mut collapsed: Vec<String> = Vec::new();
    for line in lines {
        if line.is_empty() && collapsed.last().is_some_and(|last| last.is_empty()) {
            continue;
        }
        collapsed.push(line);
    }
    while collapsed.last().is_some_and(|last| last.is_empty()) {
        collapsed.pop();
    }
    collapsed.join("\n")
}

fn rust_blocks(src: &str) -> Vec<(String, String)> {
    copied_blocks(src)
        .into_iter()
        .filter(|(info, _)| info.starts_with("rust"))
        .collect()
}

#[test]
fn module_readmes_share_the_same_code() {
    let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut checked = 0usize;
    for entry in std::fs::read_dir(src).expect("src/ is readable") {
        let dir = entry.expect("readable dir entry").path();
        let en_path = dir.join("README.md");
        let cn_path = dir.join("README_CN.md");
        if !(en_path.is_file() && cn_path.is_file()) {
            continue;
        }
        let name = dir
            .file_name()
            .expect("module dir has a name")
            .to_string_lossy()
            .into_owned();
        let en = rust_blocks(&std::fs::read_to_string(en_path).expect("README.md is UTF-8"));
        let cn = rust_blocks(&std::fs::read_to_string(cn_path).expect("README_CN.md is UTF-8"));
        assert_eq!(
            en.len(),
            cn.len(),
            "{name}: README.md has {} rust blocks, README_CN.md has {}",
            en.len(),
            cn.len()
        );
        for (index, ((en_info, a), (cn_info, b))) in en.iter().zip(cn.iter()).enumerate() {
            assert_eq!(
                en_info, cn_info,
                "{name}: rust block #{index} has a different fence (rust vs rust,no_run)"
            );
            assert_eq!(
                code_only(a),
                code_only(b),
                "{name}: rust block #{index} differs in code \
                 (comments may be translated, code may not)"
            );
        }
        checked += 1;
    }
    assert!(
        checked >= 10,
        "expected the module READMEs to be found, only saw {checked} pairs"
    );
}

// ---------------------------------------------------------------------
// Links must survive crates.io / docs.rs
// ---------------------------------------------------------------------

/// Markdown link destinations and HTML `src="…"` attributes on one line.
fn link_targets(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    for after in line.split("](").skip(1) {
        let end = after
            .find(|c: char| c == ')' || c.is_whitespace())
            .unwrap_or(after.len());
        out.push(after[..end].to_string());
    }
    let mut rest = line;
    while let Some(pos) = rest.find("src=") {
        rest = &rest[pos + 4..];
        let mut chars = rest.chars();
        let Some(quote) = chars.next() else { break };
        if quote != '"' && quote != '\'' {
            continue;
        }
        if let Some(end) = rest[1..].find(quote) {
            out.push(rest[1..1 + end].to_string());
            rest = &rest[1 + end..];
        }
    }
    out
}

/// crates.io and docs.rs render the README without serving the repository's
/// relative targets, so every link and the logo image must be absolute.
#[test]
fn readmes_link_out_with_absolute_urls() {
    for (name, src) in [("README.md", EN), ("README_CN.md", CN)] {
        let mut seen = 0usize;
        for (index, line) in src.lines().enumerate() {
            for target in link_targets(line) {
                seen += 1;
                assert!(
                    target.starts_with("http://")
                        || target.starts_with("https://")
                        || target.starts_with('#')
                        || target.starts_with("mailto:"),
                    "{name}:{}: `{target}` is a relative link and will 404 on crates.io/docs.rs",
                    index + 1
                );
            }
        }
        assert!(seen > 0, "{name}: no links found — the extractor is wrong");
    }
}

// ---------------------------------------------------------------------
// Wiki pages: same code, comments may be translated
// ---------------------------------------------------------------------

/// `wiki/en/<English name>` ↔ `wiki/zh/<translated name>`, in the order the
/// sidebar lists them. The English pages are compiled as doctests from
/// `courierust::wiki_doctests` (`#[cfg(doctest)]` in `src/lib.rs`), so a
/// snippet that stops compiling fails `cargo test --doc`; this test keeps the
/// Chinese page from drifting away from the compiled one.
const WIKI_PAGES: [(&str, &str); 9] = [
    ("Benchmarks.md", "基准测试.md"),
    ("Examples.md", "示例.md"),
    ("Fingerprints.md", "浏览器指纹.md"),
    ("Getting-Started.md", "快速上手.md"),
    ("gRPC.md", "gRPC-使用指南.md"),
    ("HTTP-Client.md", "HTTP-客户端.md"),
    ("HTTP-Server.md", "HTTP-服务器.md"),
    ("WebSockets.md", "WebSocket-使用指南.md"),
    ("no_std.md", "no_std-使用.md"),
];

#[test]
fn wiki_pages_share_the_same_code() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("wiki");
    let read = |path: &std::path::Path| {
        std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
    };
    let mut total = 0usize;
    for (en_name, zh_name) in WIKI_PAGES {
        let en_path = root.join("en").join(en_name);
        let zh_path = root.join("zh").join(zh_name);
        let en = rust_blocks(&read(&en_path));
        let zh = rust_blocks(&read(&zh_path));
        assert_eq!(
            en.len(),
            zh.len(),
            "{en_name}/{zh_name}: {} rust blocks vs {} — \
             add the missing snippet or the translated fence",
            en.len(),
            zh.len()
        );
        total += en.len();
        for (index, ((en_info, a), (zh_info, b))) in en.iter().zip(zh.iter()).enumerate() {
            assert_eq!(
                en_info, zh_info,
                "{en_name}: rust block #{index} has a different fence \
                 (rust vs rust,no_run)"
            );
            assert_eq!(
                code_only(a),
                code_only(b),
                "{en_name}: rust block #{index} differs in code \
                 (comments may be translated, code must not)"
            );
        }
    }
    assert!(
        total >= 20,
        "expected the wiki rust snippets to be found, only saw {total}"
    );
}
