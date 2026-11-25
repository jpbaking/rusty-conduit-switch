//! Integration tests for `import-airswitch`: realistic AirSwitch / ZeroOmega /
//! SwitchyOmega `.bak` fixtures are converted to TOML, and the generated file is checked
//! by parsing it back through `validate` and `test-route` (library entry points and the
//! built binary), including `-o` overwrite protection.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

use rusty_conduit_switch::config::{CliInput, Config, FileConfig, Inbound, ProfileType};
use rusty_conduit_switch::{cmd_import_airswitch, cmd_test_route, cmd_validate, EXIT_FATAL};

// ---------------------------------------------------------------------------
// Fixtures & helpers
// ---------------------------------------------------------------------------

/// A realistic AirSwitch export: IP/CIDR conditions, a FixedProfile with `bypassList` and
/// auth, a per-scheme FixedProfile, a nested SwitchProfile, a VirtualProfile, a PacProfile,
/// and a rule pointing at the built-in SystemProfile.
const FULL_BAK: &str = r##"{
  "schemaVersion": 2,
  "-startupProfileName": "auto switch",
  "-enableQuickSwitch": false,
  "-refreshOnProfileChange": true,
  "-showInspectMenu": true,
  "+Corp Proxy": {
    "name": "Corp Proxy",
    "profileType": "FixedProfile",
    "color": "#99ccee",
    "revision": "18c1f0a2b3c",
    "fallbackProxy": {"scheme": "http", "host": "10.0.0.2", "port": 3128},
    "auth": {"fallbackProxy": {"username": "alice", "password": "hunter2"}},
    "bypassList": [
      {"conditionType": "BypassCondition", "pattern": "127.0.0.1"},
      {"conditionType": "BypassCondition", "pattern": "[::1]"},
      {"conditionType": "BypassCondition", "pattern": "localhost"},
      {"conditionType": "BypassCondition", "pattern": "*.local"}
    ]
  },
  "+Bastion": {
    "name": "Bastion",
    "profileType": "FixedProfile",
    "color": "#ca0",
    "fallbackProxy": {"scheme": "socks5", "host": "127.0.0.1", "port": 1081},
    "bypassList": []
  },
  "+Split": {
    "name": "Split",
    "profileType": "FixedProfile",
    "proxyForHttp": {"scheme": "http", "host": "web.proxy.example", "port": 8080},
    "proxyForHttps": {"scheme": "https", "host": "tls.proxy.example", "port": 8443},
    "fallbackProxy": {"scheme": "socks5", "host": "socks.proxy.example", "port": 1080},
    "auth": {"all": {"username": "bob", "password": "pw"}},
    "bypassList": []
  },
  "+Legacy PAC": {
    "name": "Legacy PAC",
    "profileType": "PacProfile",
    "pacUrl": "",
    "pacScript": "function FindProxyForURL(url, host) { return \"DIRECT\"; }"
  },
  "+Dev Switch": {
    "name": "Dev Switch",
    "profileType": "SwitchProfile",
    "defaultProfileName": "Corp Proxy",
    "rules": [
      {"condition": {"conditionType": "HostRegexCondition", "pattern": "^db\\."},
       "profileName": "Bastion"}
    ]
  },
  "+Via Bastion": {
    "name": "Via Bastion",
    "profileType": "VirtualProfile",
    "defaultProfileName": "Bastion"
  },
  "+auto switch": {
    "name": "auto switch",
    "profileType": "SwitchProfile",
    "color": "#99dd99",
    "defaultProfileName": "direct",
    "rules": [
      {"condition": {"conditionType": "IpCondition", "ip": "10.0.0.0", "prefixLength": 8},
       "profileName": "Corp Proxy"},
      {"condition": {"conditionType": "IpCondition", "ip": "fd00::", "prefixLength": 8},
       "profileName": "Corp Proxy"},
      {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.internal.example"},
       "profileName": "Dev Switch", "note": "internal"},
      {"condition": {"conditionType": "HostWildcardCondition", "pattern": "ssh.example.com"},
       "profileName": "Via Bastion"},
      {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.split.example"},
       "profileName": "Split"},
      {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.legacy.example"},
       "profileName": "Legacy PAC"},
      {"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.sys.example"},
       "profileName": "system"},
      {"condition": {"conditionType": "FalseCondition"}, "profileName": "Corp Proxy"},
      {"condition": {"conditionType": "HostWildcardCondition", "pattern": "localhost|*.local"},
       "profileName": "Corp Proxy"},
      {"condition": {"conditionType": "UrlWildcardCondition", "pattern": "http://downloads.example.com/private/*"},
       "profileName": "Corp Proxy"}
    ]
  }
}"##;

static COUNTER: AtomicUsize = AtomicUsize::new(0);

/// A unique temporary path, removed on drop.
struct TempPath(PathBuf);

impl TempPath {
    fn new(name: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        Self(std::env::temp_dir().join(format!("rcs-airswitch-{}-{n}-{name}", std::process::id())))
    }

    fn with(name: &str, content: &str) -> Self {
        let p = Self::new(name);
        std::fs::write(&p.0, content).unwrap();
        p
    }

    fn path(&self) -> &Path {
        &self.0
    }

    fn str(&self) -> &str {
        self.0.to_str().unwrap()
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

struct Import {
    code: u8,
    toml: String,
    stderr: String,
}

fn import(bak: &str, profile: Option<&str>) -> Import {
    let input = TempPath::with("in.bak", bak);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cmd_import_airswitch(input.path(), None, profile, false, &mut out, &mut err);
    Import {
        code,
        toml: String::from_utf8(out).unwrap(),
        stderr: String::from_utf8(err).unwrap(),
    }
}

fn cli(args: &[&str]) -> CliInput {
    let mut full = vec!["rusty-conduit-switch"];
    full.extend_from_slice(args);
    CliInput::try_parse_from(full).unwrap()
}

fn validate(toml: &str) -> (u8, String, String) {
    let f = TempPath::with("out.toml", toml);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cmd_validate(cli(&["validate", "--config", f.str()]), &mut out, &mut err);
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}

/// `test-route` output for `target` against the generated config.
fn route(toml: &str, inbound: Inbound, target: &str) -> String {
    let f = TempPath::with("route.toml", toml);
    let inbound_arg = inbound.to_string();
    let c = cli(&[
        "test-route",
        "--config",
        f.str(),
        "--inbound",
        &inbound_arg,
        target,
    ]);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let code = cmd_test_route(c, inbound, target, &mut out, &mut err);
    let err = String::from_utf8(err).unwrap();
    assert_eq!(code, 0, "{err}");
    String::from_utf8(out).unwrap()
}

fn parse(toml: &str) -> Config {
    let file = FileConfig::from_toml_str(toml, Path::new("imported.toml")).unwrap();
    Config::merge(CliInput::default(), Some(file)).unwrap()
}

// ---------------------------------------------------------------------------
// Full fixture
// ---------------------------------------------------------------------------

#[test]
fn full_backup_imports_to_valid_toml() {
    let imp = import(FULL_BAK, None);
    assert_eq!(imp.code, 0, "{}", imp.stderr);
    let (code, out, err) = validate(&imp.toml);
    assert_eq!(code, 0, "generated TOML must validate: {err}\n{}", imp.toml);
    assert!(out.contains("config OK"), "{out}");

    let cfg = parse(&imp.toml);
    let corp = &cfg.profiles["corp_proxy"];
    assert_eq!(corp.kind, ProfileType::Http);
    assert_eq!(corp.host.as_deref(), Some("10.0.0.2"));
    assert_eq!(corp.port, Some(3128));
    assert_eq!(corp.username.as_deref(), Some("alice"));
    assert_eq!(corp.password.as_deref(), Some("hunter2"));
    assert_eq!(corp.bypass, ["127.0.0.1", "[::1]", "localhost", "*.local"]);
    assert_eq!(cfg.profiles["bastion"].kind, ProfileType::Socks5);
    assert_eq!(cfg.profiles["split"].kind, ProfileType::Composite);
    assert_eq!(cfg.profiles["split_https"].kind, ProfileType::Https);
    assert_eq!(
        cfg.profiles["split_fallback"].username.as_deref(),
        Some("bob")
    );
    // PAC and the nested/virtual switch profiles are not emitted as profiles.
    assert_eq!(cfg.profiles.len(), 6, "{:?}", cfg.profiles.keys());
}

#[test]
fn generated_toml_has_clean_comments() {
    let imp = import(FULL_BAK, None);
    let t = &imp.toml;
    assert!(
        t.starts_with("# Generated by rusty-conduit-switch import-airswitch from \"rcs-airswitch-")
    );
    assert!(t.contains("# Routing imported from profile \"auto switch\""));
    let header = t
        .find("# Imported from AirSwitch profile \"Corp Proxy\"\n")
        .unwrap();
    let table = t.find("[profiles.corp_proxy]\n").unwrap();
    assert!(header < table);
    assert!(t[header..table].contains("# Password imported in plaintext"));
    assert!(t.contains("# Imported from AirSwitch profile \"Bastion\"\n[profiles.bastion]\n"));
    assert!(t.contains("# Imported from AirSwitch SwitchProfile \"auto switch\""));
    assert!(t.contains("# Import warnings:"));
    assert!(
        t.contains("# SKIPPED:"),
        "the PAC rule is kept commented out"
    );
    assert!(t.contains("# URL rule: only matches plain HTTP"));
    // The input path is never embedded, only the file name.
    assert!(!t.contains(std::env::temp_dir().to_str().unwrap().trim_end_matches('/')));
}

#[test]
fn warnings_cover_browser_only_constructs() {
    let imp = import(FULL_BAK, None);
    let e = &imp.stderr;
    assert!(
        e.contains("warning: SystemProfile has no server-side equivalent; mapped to \"direct\""),
        "{e}"
    );
    assert!(
        e.contains("JavaScript PAC scripts are not executed; skipped — convert rules manually"),
        "{e}"
    );
    assert!(e.contains("URL rule(s)"), "{e}");
    assert!(e.contains("password imported in plaintext"), "{e}");
    assert!(
        !e.contains("hunter2"),
        "credentials must not be printed: {e}"
    );
}

#[test]
fn imported_routing_matches_airswitch_decisions() {
    let t = import(FULL_BAK, None).toml;
    let http = |target: &str| route(&t, Inbound::Http, target);

    let out = http("10.1.2.3:443");
    assert!(
        out.contains("rule=\"auto switch #1\" profile=corp_proxy"),
        "{out}"
    );
    assert!(out.contains("upstream=http://10.0.0.2:3128"), "{out}");
    assert!(http("[fd00::1]:22").contains("profile=corp_proxy"));

    // Nested SwitchProfile: outer host wildcard AND inner host regex.
    let out = http("db.internal.example:5432");
    assert!(
        out.contains("rule=\"internal > Dev Switch #1\" profile=bastion"),
        "{out}"
    );
    let out = http("web.internal.example:443");
    assert!(
        out.contains("rule=\"internal > default\" profile=corp_proxy"),
        "{out}"
    );

    // VirtualProfile resolves to its target.
    assert!(http("ssh.example.com:22").contains("profile=bastion"));

    // Per-scheme FixedProfile → composite.
    assert!(http("http://www.split.example/").contains("profile=split->split_http"));
    assert!(http("https://www.split.example/").contains("profile=split->split_https"));
    assert!(
        route(&t, Inbound::Socks, "www.split.example:25").contains("profile=split->split_fallback")
    );

    // PAC rule skipped → table default; SystemProfile → direct.
    assert!(http("www.legacy.example:80").contains("rule=<default> profile=direct"));
    assert!(http("www.sys.example:80").contains("profile=direct"));

    // FixedProfile bypassList sends local targets direct.
    let out = http("localhost:8080");
    assert!(out.contains("profile=corp_proxy(bypass->direct)"), "{out}");
    let out = http("printer.local:631");
    assert!(out.contains("profile=corp_proxy(bypass->direct)"), "{out}");

    // URL rule: plain HTTP only.
    assert!(http("http://downloads.example.com/private/a.zip").contains("profile=corp_proxy"));
    assert!(http("example.org:443").contains("rule=<default> profile=direct"));
}

#[test]
fn false_condition_is_preserved_as_disabled_rule() {
    let t = import(FULL_BAK, None).toml;
    let cfg = parse(&t);
    let disabled: Vec<_> = cfg.routing.rules.iter().filter(|r| r.disabled).collect();
    assert_eq!(disabled.len(), 1);
    assert_eq!(disabled[0].name.as_deref(), Some("auto switch #8"));
}

// ---------------------------------------------------------------------------
// Profile selection, cycles, rule lists
// ---------------------------------------------------------------------------

const TWO_SWITCHES: &str = r#"{
  "+Proxy": {"name": "Proxy", "profileType": "FixedProfile",
    "fallbackProxy": {"scheme": "socks4", "host": "10.0.0.5", "port": 1080}},
  "+Home": {"name": "Home", "profileType": "SwitchProfile", "defaultProfileName": "direct",
    "rules": [{"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.home"},
               "profileName": "Proxy"}]},
  "+Office": {"name": "Office", "profileType": "SwitchProfile", "defaultProfileName": "Proxy",
    "rules": [{"condition": {"conditionType": "TimeCondition", "startHour": 9, "endHour": 17},
               "profileName": "direct"},
              {"condition": {"conditionType": "WeekdayCondition", "days": "S-----S"},
               "profileName": "direct"}]}
}"#;

#[test]
fn several_switch_profiles_require_profile_flag() {
    let imp = import(TWO_SWITCHES, None);
    assert_eq!(imp.code, EXIT_FATAL);
    assert!(imp.stderr.contains("--profile"), "{}", imp.stderr);
    assert!(
        imp.stderr.contains("\"Home\", \"Office\""),
        "{}",
        imp.stderr
    );
    assert!(imp.toml.is_empty());

    let imp = import(TWO_SWITCHES, Some("Missing"));
    assert_eq!(imp.code, EXIT_FATAL);
    assert!(imp.stderr.contains("not found"), "{}", imp.stderr);

    let imp = import(TWO_SWITCHES, Some("Proxy"));
    assert_eq!(imp.code, EXIT_FATAL);
    assert!(imp.stderr.contains("not a SwitchProfile"), "{}", imp.stderr);
}

#[test]
fn profile_flag_selects_switch_profile() {
    let imp = import(TWO_SWITCHES, Some("Office"));
    assert_eq!(imp.code, 0, "{}", imp.stderr);
    assert!(imp.stderr.contains("imported as socks4a"), "{}", imp.stderr);
    assert_eq!(validate(&imp.toml).0, 0, "{}", imp.toml);
    let cfg = parse(&imp.toml);
    assert_eq!(cfg.profiles["proxy"].kind, ProfileType::Socks4a);
    assert_eq!(cfg.routing.default.as_slice(), ["proxy"]);
    let rules = &cfg.routing.rules;
    assert_eq!(rules[0].time.as_ref().unwrap().as_slice(), ["09:00-17:59"]);
    assert_eq!(
        rules[1].weekday.as_ref().unwrap().as_slice(),
        ["sun", "sat"]
    );

    let imp = import(TWO_SWITCHES, Some("Home"));
    assert_eq!(imp.code, 0);
    let out = route(&imp.toml, Inbound::Socks, "nas.home:445");
    assert!(out.contains("profile=proxy"), "{out}");
}

#[test]
fn switch_profile_cycles_are_rejected() {
    let bak = r#"{
      "-startupProfileName": "A",
      "+A": {"name": "A", "profileType": "SwitchProfile", "defaultProfileName": "direct",
        "rules": [{"condition": {"conditionType": "HostWildcardCondition", "pattern": "*.a"},
                   "profileName": "B"}]},
      "+B": {"name": "B", "profileType": "SwitchProfile", "defaultProfileName": "A", "rules": []}
    }"#;
    let imp = import(bak, None);
    assert_eq!(imp.code, EXIT_FATAL);
    assert!(
        imp.stderr
            .contains("SwitchProfile cycle detected: A -> B -> A"),
        "{}",
        imp.stderr
    );
}

#[test]
fn zero_omega_rule_list_and_base64_backup() {
    let bak = r#"{
      "-startupProfileName": "auto switch",
      "+proxy": {"name": "proxy", "profileType": "FixedProfile",
        "fallbackProxy": {"scheme": "socks5", "host": "127.0.0.1", "port": 1081}},
      "+auto switch": {"name": "auto switch", "profileType": "SwitchProfile",
        "defaultProfileName": "__ruleListOf_auto switch",
        "rules": [{"condition": {"conditionType": "HostWildcardCondition", "pattern": "internal.example"},
                   "profileName": "direct"}]},
      "+__ruleListOf_auto switch": {"name": "__ruleListOf_auto switch",
        "profileType": "RuleListProfile", "format": "AutoProxy",
        "matchProfileName": "proxy", "defaultProfileName": "direct",
        "sourceUrl": "https://example.com/gfwlist.txt",
        "ruleList": "[AutoProxy 0.2.9]\n! comment\n||blocked.example\n@@||ok.blocked.example\n.cdn.example\n/^https?:\\/\\/[^\\/]+\\.re\\.example/\nads.example$third-party\n"}
    }"#;
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(bak);
    let imp = import(&b64, None);
    assert_eq!(imp.code, 0, "{}", imp.stderr);
    assert!(imp.stderr.contains("modifiers"), "{}", imp.stderr);
    assert_eq!(validate(&imp.toml).0, 0, "{}", imp.toml);
    let t = &imp.toml;
    assert!(route(t, Inbound::Socks, "www.blocked.example:443").contains("profile=proxy"));
    assert!(route(t, Inbound::Socks, "blocked.example:443").contains("profile=proxy"));
    assert!(route(t, Inbound::Socks, "ok.blocked.example:443").contains("profile=direct"));
    assert!(route(t, Inbound::Http, "http://x.cdn.example/a").contains("profile=proxy"));
    assert!(route(t, Inbound::Http, "internal.example:80").contains("rule=\"auto switch #1\""));
}

// ---------------------------------------------------------------------------
// The built binary: stdout default and -o overwrite protection
// ---------------------------------------------------------------------------

fn bin(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_rusty-conduit-switch"))
        .args(args)
        .env_remove("RUSTY_CONDUIT_SWITCH_CONFIG")
        .output()
        .unwrap();
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

#[test]
fn binary_import_to_stdout_then_validate() {
    let input = TempPath::with("bin.bak", FULL_BAK);
    let (code, out, err) = bin(&["import-airswitch", input.str()]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("[profiles.corp_proxy]"), "{out}");
    assert!(err.contains("warning: "), "{err}");

    let cfg = TempPath::with("bin.toml", &out);
    let (code, out, err) = bin(&["validate", "--config", cfg.str()]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.contains("config OK"));
    let (code, out, _) = bin(&["test-route", "--config", cfg.str(), "10.9.9.9:22"]);
    assert_eq!(code, Some(0));
    assert!(out.contains("profile=corp_proxy"), "{out}");
}

#[test]
fn binary_output_flag_refuses_overwrite_without_force() {
    let input = TempPath::with("o.bak", FULL_BAK);
    let output = TempPath::new("o.toml");

    let (code, out, err) = bin(&["import-airswitch", input.str(), "-o", output.str()]);
    assert_eq!(code, Some(0), "{err}");
    assert!(out.is_empty(), "nothing on stdout with -o: {out}");
    assert!(err.contains("wrote"), "{err}");
    let first = std::fs::read_to_string(output.path()).unwrap();
    assert!(first.contains("[routing]"));

    std::fs::write(output.path(), "# hand-edited\n").unwrap();
    let (code, _, err) = bin(&["import-airswitch", input.str(), "-o", output.str()]);
    assert_eq!(code, Some(1));
    assert!(err.contains("refusing to overwrite"), "{err}");
    assert!(err.contains("--force"), "{err}");
    assert_eq!(
        std::fs::read_to_string(output.path()).unwrap(),
        "# hand-edited\n"
    );

    let (code, _, err) = bin(&[
        "import-airswitch",
        input.str(),
        "--output",
        output.str(),
        "--force",
    ]);
    assert_eq!(code, Some(0), "{err}");
    assert_eq!(std::fs::read_to_string(output.path()).unwrap(), first);
}

#[test]
fn binary_rejects_invalid_backup() {
    let input = TempPath::with("bad.bak", "this is not a backup");
    let (code, out, err) = bin(&["import-airswitch", input.str()]);
    assert_eq!(code, Some(1));
    assert!(out.is_empty());
    assert!(err.contains("not an AirSwitch backup"), "{err}");
}
