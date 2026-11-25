//! Importer entry point and commented TOML serializer.
//!
//! [`airswitch::convert`] maps an AirSwitch / ZeroOmega / SwitchyOmega `.bak` backup onto
//! profiles and rules; [`render_toml`] writes them as a `rusty-conduit-switch` config with
//! header and per-item comments; [`run_import`] is the `import-airswitch` subcommand
//! (stdout by default, `-o <path>` refusing to overwrite unless `--force`).

pub mod airswitch;

use std::fmt::Write as _;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::Path;

pub use airswitch::{
    convert, slugify, ImportError, ImportOptions, Imported, ImportedProfile, ImportedRule,
};

use crate::config::{OneOrMany, PortSpec, ProfileConfig, RuleConfig};

/// Exit code for a failed import.
const EXIT_FAILED: u8 = 1;

/// Quote `s` as a TOML basic string.
pub fn toml_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\u{7f}' => {
                let _ = write!(out, "\\u{:04X}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// A TOML key: bare when it only uses `A-Za-z0-9_-`, quoted otherwise.
pub fn toml_key(k: &str) -> String {
    if !k.is_empty()
        && k.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        k.to_string()
    } else {
        toml_string(k)
    }
}

fn string_list(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| toml_string(s)).collect();
    format!("[{}]", inner.join(", "))
}

fn one_or_many(v: &OneOrMany<String>) -> String {
    match v {
        OneOrMany::One(s) => toml_string(s),
        OneOrMany::Many(items) => string_list(items),
    }
}

/// Comment text on one line (newlines in imported names would otherwise end the comment).
fn comment(text: &str) -> String {
    format!("# {}\n", text.replace(['\n', '\r'], " "))
}

fn render_profile(out: &mut String, p: &ImportedProfile) {
    for c in &p.comments {
        out.push_str(&comment(c));
    }
    let _ = writeln!(out, "[profiles.{}]", toml_key(&p.key));
    let c: &ProfileConfig = &p.config;
    let _ = writeln!(out, "type = {}", toml_string(c.kind.as_str()));
    if let Some(h) = &c.host {
        let _ = writeln!(out, "host = {}", toml_string(h));
    }
    if let Some(port) = c.port {
        let _ = writeln!(out, "port = {port}");
    }
    if let Some(u) = &c.username {
        let _ = writeln!(out, "username = {}", toml_string(u));
    }
    if let Some(pw) = &c.password {
        let _ = writeln!(out, "password = {}", toml_string(pw));
    }
    for (key, v) in [
        ("http_proxy", &c.http_proxy),
        ("https_proxy", &c.https_proxy),
        ("fallback_proxy", &c.fallback_proxy),
    ] {
        if let Some(v) = v {
            let _ = writeln!(out, "{key} = {}", toml_string(v));
        }
    }
    if !c.bypass.is_empty() {
        let _ = writeln!(out, "bypass = {}", string_list(&c.bypass));
    }
    out.push('\n');
}

/// The `key = value` lines of one rule (without the table header).
fn rule_lines(r: &RuleConfig) -> Vec<String> {
    let mut lines = Vec::new();
    if let Some(n) = &r.name {
        lines.push(format!("name = {}", toml_string(n)));
    }
    if let Some(i) = r.inbound {
        lines.push(format!("inbound = {}", toml_string(&i.to_string())));
    }
    for (key, v) in [
        ("host", &r.host),
        ("host_wildcard", &r.host_wildcard),
        ("host_regex", &r.host_regex),
        ("cidr", &r.cidr),
        ("ip", &r.ip),
    ] {
        if let Some(v) = v {
            lines.push(format!("{key} = {}", one_or_many(v)));
        }
    }
    if let Some(p) = &r.port {
        let spec = |s: &PortSpec| match s {
            PortSpec::Port(n) => n.to_string(),
            PortSpec::Range(r) => toml_string(r),
        };
        let v = match p {
            OneOrMany::One(s) => spec(s),
            OneOrMany::Many(v) => {
                format!("[{}]", v.iter().map(spec).collect::<Vec<_>>().join(", "))
            }
        };
        lines.push(format!("port = {v}"));
    }
    if let Some(l) = &r.host_levels {
        let mut parts = Vec::new();
        if let Some(min) = l.min {
            parts.push(format!("min = {min}"));
        }
        if let Some(max) = l.max {
            parts.push(format!("max = {max}"));
        }
        lines.push(format!("host_levels = {{ {} }}", parts.join(", ")));
    }
    for (key, v) in [
        ("bypass", &r.bypass),
        ("weekday", &r.weekday),
        ("time", &r.time),
        ("url_wildcard", &r.url_wildcard),
        ("url_regex", &r.url_regex),
        ("keyword", &r.keyword),
    ] {
        if let Some(v) = v {
            lines.push(format!("{key} = {}", one_or_many(v)));
        }
    }
    if r.match_all {
        lines.push("match_all = true".into());
    }
    if r.disabled {
        lines.push("disabled = true".into());
    }
    if let Some(d) = r.resolve_dns {
        lines.push(format!("resolve_dns = {d}"));
    }
    lines.push(format!("target = {}", one_or_many(&r.target)));
    lines
}

fn render_rule(out: &mut String, r: &ImportedRule) {
    for c in &r.comments {
        out.push_str(&comment(c));
    }
    match &r.skipped {
        None => {
            out.push_str("[[routing.rules]]\n");
            for l in rule_lines(&r.rule) {
                out.push_str(&l);
                out.push('\n');
            }
        }
        Some(reason) => {
            out.push_str(&comment(&format!("SKIPPED: {reason}")));
            out.push_str("# [[routing.rules]]\n");
            let name = r.rule.name.as_deref().unwrap_or("");
            out.push_str(&comment(&format!("name = {}", toml_string(name))));
            out.push_str(&comment(&format!(
                "target = {}",
                one_or_many(&r.rule.target)
            )));
        }
    }
    out.push('\n');
}

/// Render an import as a commented TOML configuration. `source_name` is shown in the
/// header (pass a file name, not a full path).
pub fn render_toml(imp: &Imported, source_name: &str) -> String {
    let mut out = String::new();
    out.push_str(&comment(&format!(
        "Generated by rusty-conduit-switch import-airswitch from {source_name:?}"
    )));
    match &imp.switch_profile {
        Some(s) => out.push_str(&comment(&format!("Routing imported from profile {s:?}"))),
        None => out.push_str("# No SwitchProfile was imported; [routing] has no rules.\n"),
    }
    out.push_str(
        "# Review this file, then check it with:\n\
         #   rusty-conduit-switch validate --config <this file>\n\
         # Server settings (bind, ports, MITM, logging) use their defaults; see docs/USER-GUIDE.md.\n\
         # Built-in profiles \"direct\" and \"block\" always exist and are not declared here.\n",
    );
    if !imp.warnings.is_empty() {
        out.push_str("#\n# Import warnings:\n");
        for w in &imp.warnings {
            out.push_str(&comment(&format!("  - {w}")));
        }
    }
    out.push('\n');

    for p in &imp.profiles {
        render_profile(&mut out, p);
    }

    if let Some(s) = &imp.switch_profile {
        out.push_str(&comment(&format!(
            "Imported from AirSwitch SwitchProfile {s:?} (rules are evaluated top to bottom)"
        )));
    }
    out.push_str("[routing]\n");
    let default = if imp.default.len() == 1 {
        OneOrMany::One(imp.default[0].clone())
    } else {
        OneOrMany::Many(imp.default.clone())
    };
    let _ = writeln!(out, "default = {}", one_or_many(&default));
    out.push('\n');
    for r in &imp.rules {
        render_rule(&mut out, r);
    }
    while out.ends_with("\n\n") {
        out.pop();
    }
    out
}

/// `import-airswitch <BAK_PATH> [-o OUT] [--profile NAME] [--force]`. TOML goes to `out`
/// (or `output`); warnings and errors go to `err`. Returns the process exit code.
pub fn run_import(
    bak_path: &Path,
    output: Option<&Path>,
    profile: Option<&str>,
    force: bool,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    let fail = |err: &mut dyn Write, msg: String| {
        let _ = writeln!(err, "import-airswitch: {msg}");
        EXIT_FAILED
    };
    let text = match std::fs::read(bak_path) {
        Ok(bytes) => String::from_utf8_lossy(&bytes).into_owned(),
        Err(e) => return fail(err, format!("cannot read {}: {e}", bak_path.display())),
    };
    let opts = ImportOptions {
        profile: profile.map(str::to_string),
    };
    let imp = match convert(&text, &opts) {
        Ok(i) => i,
        Err(e) => return fail(err, e.to_string()),
    };
    let source_name = bak_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| bak_path.display().to_string());
    let toml = render_toml(&imp, &source_name);

    for w in &imp.warnings {
        let _ = writeln!(err, "warning: {w}");
    }
    match output {
        None => {
            if let Err(e) = out.write_all(toml.as_bytes()).and_then(|_| out.flush()) {
                return fail(err, format!("cannot write output: {e}"));
            }
        }
        Some(path) => {
            let mut o = OpenOptions::new();
            o.write(true);
            if force {
                o.create(true).truncate(true);
            } else {
                o.create_new(true);
            }
            let written = o
                .open(path)
                .and_then(|mut f| f.write_all(toml.as_bytes()).and_then(|_| f.flush()));
            match written {
                Ok(()) => {
                    let _ = writeln!(err, "import-airswitch: wrote {} ({imp})", path.display());
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    return fail(
                        err,
                        format!(
                            "refusing to overwrite existing file {} (pass --force to replace it)",
                            path.display()
                        ),
                    )
                }
                Err(e) => return fail(err, format!("cannot write {}: {e}", path.display())),
            }
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, FileConfig};

    const BAK: &str = r#"{
      "-startupProfileName": "auto switch",
      "schemaVersion": 2,
      "+Work Proxy": {"name": "Work Proxy", "profileType": "FixedProfile",
        "fallbackProxy": {"scheme": "http", "host": "10.0.0.2", "port": 3128},
        "auth": {"fallbackProxy": {"username": "alice", "password": "pa\"ss"}},
        "bypassList": [{"conditionType": "BypassCondition", "pattern": "<local>"},
                       {"conditionType": "BypassCondition", "pattern": "[::1]"}]},
      "+auto switch": {"name": "auto switch", "profileType": "SwitchProfile",
        "defaultProfileName": "direct",
        "rules": [
          {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.corp.example"},
           "profileName": "Work Proxy", "note": "corp \"hosts\""},
          {"condition": {"conditionType": "HostLevelsCondition", "minValue": 0, "maxValue": 0},
           "profileName": "Work Proxy"},
          {"condition": {"conditionType": "HostRegexCondition", "pattern": "(?<=a)b"},
           "profileName": "Work Proxy"}
        ]}
    }"#;

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("rcs-import-unit-{}-{name}", std::process::id()))
    }

    #[test]
    fn toml_string_escapes() {
        assert_eq!(toml_string("a\"b\\c\n"), r#""a\"b\\c\n""#);
        assert_eq!(toml_string("\u{1}"), r#""\u0001""#);
        assert_eq!(toml_key("work_proxy"), "work_proxy");
        assert_eq!(toml_key("a b"), "\"a b\"");
    }

    #[test]
    fn rendered_toml_parses_and_validates() {
        let imp = convert(BAK, &ImportOptions::default()).unwrap();
        let text = render_toml(&imp, "Options.bak");
        assert!(text.contains("# Imported from AirSwitch profile \"Work Proxy\""));
        assert!(text.contains("# SKIPPED:"), "{text}");
        let file = FileConfig::from_toml_str(&text, Path::new("x.toml")).unwrap();
        let cfg = Config {
            profiles: file.profiles,
            routing: file.routing,
            ..Config::default()
        };
        cfg.validate().unwrap();
        crate::router::Router::from_input(&cfg.routing_input()).unwrap();
        assert_eq!(cfg.routing.rules.len(), 2);
        assert_eq!(
            cfg.profiles["work_proxy"].password.as_deref(),
            Some("pa\"ss")
        );
        assert_eq!(cfg.routing.rules[0].name.as_deref(), Some("corp \"hosts\""));
    }

    #[test]
    fn rendering_is_deterministic() {
        let a = render_toml(&convert(BAK, &ImportOptions::default()).unwrap(), "x");
        let b = render_toml(&convert(BAK, &ImportOptions::default()).unwrap(), "x");
        assert_eq!(a, b);
    }

    #[test]
    fn run_import_refuses_overwrite_without_force() {
        let bak = tmp("in.bak");
        let out_path = tmp("out.toml");
        std::fs::write(&bak, BAK).unwrap();
        std::fs::write(&out_path, "keep").unwrap();
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run_import(&bak, Some(&out_path), None, false, &mut out, &mut err),
            EXIT_FAILED
        );
        assert!(String::from_utf8_lossy(&err).contains("--force"));
        assert_eq!(std::fs::read_to_string(&out_path).unwrap(), "keep");

        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run_import(&bak, Some(&out_path), None, true, &mut out, &mut err),
            0
        );
        assert!(std::fs::read_to_string(&out_path)
            .unwrap()
            .contains("[profiles.work_proxy]"));
        let err = String::from_utf8_lossy(&err);
        assert!(err.contains("warning:") && err.contains("wrote"), "{err}");
        assert!(!err.contains("pa\"ss"));
        std::fs::remove_file(bak).ok();
        std::fs::remove_file(out_path).ok();
    }

    #[test]
    fn run_import_reports_errors() {
        let (mut out, mut err) = (Vec::new(), Vec::new());
        assert_eq!(
            run_import(
                Path::new("/nonexistent/x.bak"),
                None,
                None,
                false,
                &mut out,
                &mut err
            ),
            EXIT_FAILED
        );
        assert!(String::from_utf8_lossy(&err).contains("cannot read"));
    }
}
