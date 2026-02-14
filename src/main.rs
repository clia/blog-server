// use std::env;
use std::fs::File;
use std::io::prelude::*;
// use std::io::BufReader;
// use std::process;

// use ntex::web::{self, middleware, App, HttpRequest};
// use ntex_files as fs;
// use openssl::ssl::{SslAcceptor, SslFiletype, SslMethod};
// use rustls::{Certificate, PrivateKey, ServerConfig};
// use rustls_pemfile::{certs, pkcs8_private_keys};
use salvo::prelude::*;
use salvo::serve_static::StaticDir;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::OnceLock;

use blog_server::nginx;

// use libdistr::{acme, cert};

// async fn index(req: HttpRequest) -> &'static str {
//     // println!("REQ: {:?}", req);
//     "Hello world!"
// }

static SERVERS: OnceLock<Arc<HashMap<String, nginx::ServerInfo>>> = OnceLock::new();

#[handler]
async fn hello() -> &'static str {
    "Hello world!"
}

#[handler]
async fn debug_servers() -> String {
    if let Some(m) = SERVERS.get() {
        let mut out = Vec::new();
        for (k, v) in m.iter() {
            out.push(format!("{} -> root={:?} locations={:?}", k, v.root, v.locations.iter().map(|l| l.pattern.clone()).collect::<Vec<_>>()));
        }
        return out.join("\n");
    }
    "<no servers configured>".to_string()
}

static HTTP_CLIENT: OnceLock<reqwest::Client> = OnceLock::new();

fn guess_mime(path: &str) -> &'static str {
    match path.rsplit('.').next() {
        Some("html") => "text/html; charset=utf-8",
        Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("txt") => "text/plain; charset=utf-8",
        _ => "application/octet-stream",
    }
}

fn location_matches(req_path: &str, loc_pattern: &str) -> Option<regex::Regex> {
    // If starts with "~" or "~*" treat as regex
    if loc_pattern.starts_with("~*") {
        if let Ok(re) = regex::RegexBuilder::new(&loc_pattern[2..])
            .case_insensitive(true)
            .build()
        {
            return Some(re);
        }
    } else if loc_pattern.starts_with('~') {
        if let Ok(re) = regex::Regex::new(&loc_pattern[1..]) {
            return Some(re);
        }
    }
    None
}

#[handler]
async fn host_info(req: &mut Request, res: &mut Response) {
    // ensure client exists
    let _ = HTTP_CLIENT.get_or_init(|| reqwest::Client::new());

    // Host header -> server lookup
    // Accept both HTTP/1.1 `Host` and HTTP/2/3 pseudo-header `:authority` (browsers send `:authority`).
    let host = req
        .headers()
        .get("host")
        .or_else(|| req.headers().get(":authority"))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.split(':').next())
        .unwrap_or("");

    // lookup by Host header; do NOT fallback to another server when host is missing
    let servers_map = match SERVERS.get() {
        Some(m) => m,
        None => { res.status_code(salvo::http::StatusCode::NOT_FOUND); return; }
    };

    let srv = match servers_map.get(host) {
        Some(s) => {
            tracing::debug!("matched server for host '{}': {:?}", host, s.server_names);
            s.clone()
        }
        None => {
            // unknown Host -> return 404 (no fallback)
            tracing::warn!("no server matched for host '{}'", host);
            res.status_code(salvo::http::StatusCode::NOT_FOUND);
            return;
        }
    };

    // get the raw path from route param (router uses "<*path>")
    let param_path = req.param::<String>("path").unwrap_or_default();
    let req_path = if param_path.is_empty() { "/".to_string() } else { format!("/{}", param_path) };
    tracing::debug!("request path: '{}' (param_path: '{}')", req_path, param_path);

    // find best matching location (order: exact -> prefix (longest) -> regex)
    let mut exact: Option<&nginx::LocationInfo> = None;
    let mut best_prefix: Option<&nginx::LocationInfo> = None;
    let mut best_prefix_len = 0usize;
    let mut regex_match: Option<(&nginx::LocationInfo, regex::Regex)> = None;

    for loc in &srv.locations {
        if let Some(re) = location_matches(&req_path, &loc.pattern) {
            if re.is_match(&req_path) {
                regex_match = Some((loc, re));
                break; // regex matches have lower precedence than exact/prefix but we choose first
            }
            continue;
        }

        // plain pattern -> exact or prefix
        if loc.pattern == req_path {
            exact = Some(loc);
            break;
        }
        if req_path.starts_with(&loc.pattern) && loc.pattern.len() > best_prefix_len {
            best_prefix_len = loc.pattern.len();
            best_prefix = Some(loc);
        }
    }

    let matched_loc = exact.or(best_prefix).or_else(|| regex_match.as_ref().map(|(l, _)| *l));
    
    tracing::debug!("location match result: exact={}, prefix={}, regex={}", 
        exact.is_some(), best_prefix.is_some(), regex_match.is_some());
    if let Some(loc) = matched_loc {
        tracing::debug!("matched location pattern: '{}'", loc.pattern);
    } else {
        tracing::debug!("no location matched, using server-level config");
    }

    // determine action: proxy_pass (location first, then server-wide), else static file from (location.root || server.root)
    if let Some(loc) = matched_loc {
        // proxy_pass in location
        if let Some(pp) = loc.proxy_pass.first().or_else(|| srv.proxy_passes.first()) {
            // simple proxy: only forward GET/HEAD for now (no request-body forwarding)
            let client = HTTP_CLIENT.get().unwrap();
            let upstream_base = pp.trim_end_matches('/');
            // compute path to append: request path minus location pattern when location is prefix
            let suffix = if req_path.starts_with(&loc.pattern) {
                &req_path[loc.pattern.len()..]
            } else { &req_path };
            let upstream_url = format!("{}{}", upstream_base, suffix);

            // only forwarding GET/HEAD for now
            let method = req.method().as_str();
            if method != "GET" && method != "HEAD" {
                res.status_code(salvo::http::StatusCode::NOT_IMPLEMENTED);
                return;
            }

            let mut builder = client.request(method.parse().unwrap_or(reqwest::Method::GET), &upstream_url);

            // copy headers except hop-by-hop
            for (name, value) in req.headers().iter() {
                let name_str = name.as_str();
                match name_str {
                    "connection" | "keep-alive" | "proxy-authorization" | "proxy-authenticate" | "te" | "trailers" | "transfer-encoding" | "upgrade" => continue,
                    _ => {
                        if let Ok(v) = value.to_str() { builder = builder.header(name_str, v); }
                    }
                }
            }

            match builder.send().await {
                Ok(up_resp) => {
                    let status = up_resp.status();
                    let headers = up_resp.headers().clone();
                    let bytes = up_resp.bytes().await.unwrap_or_default();

                    // set status
                    res.status_code(salvo::http::StatusCode::from_u16(status.as_u16()).unwrap_or(salvo::http::StatusCode::OK));

                    // copy a few safe headers (content-type, cache-control)
                    if let Some(ct) = headers.get(reqwest::header::CONTENT_TYPE) {
                        if let Ok(s) = ct.to_str() {
                            let _ = res.headers_mut().insert(salvo::http::header::CONTENT_TYPE, salvo::http::HeaderValue::from_str(s).unwrap());
                        }
                    }
                    if let Some(cc) = headers.get(reqwest::header::CACHE_CONTROL) {
                        if let Ok(s) = cc.to_str() {
                            let _ = res.headers_mut().insert(salvo::http::header::CACHE_CONTROL, salvo::http::HeaderValue::from_str(s).unwrap());
                        }
                    }
                    // write body
                    res.body(bytes);
                    return;
                }
                Err(err) => {
                    tracing::error!("proxy request failed to {}: {}", upstream_url, err);
                    res.status_code(salvo::http::StatusCode::BAD_GATEWAY);
                    return;
                }
            }
        }

        // no proxy_pass -> try to serve static from location.root or server.root
        if let Some(root) = loc.root.as_ref().or_else(|| srv.root.as_ref()) {
            tracing::debug!("using root: '{}'", root);
            let fs_path = if req_path == "/" {
                // check index files
                let mut found = None;
                tracing::debug!("searching for index files in location.index={:?}, server.index={:?}", 
                    loc.index, srv.index);
                for idx in loc.index.iter().chain(srv.index.iter()) {
                    let p = format!("{}/{}", root.trim_end_matches('/'), idx);
                    tracing::debug!("checking index file: '{}'", p);
                    if std::path::Path::new(&p).is_file() { 
                        tracing::info!("found index file: '{}'", p);
                        found = Some(p); 
                        break; 
                    }
                }
                if found.is_none() {
                    tracing::warn!("no index file found in root '{}'", root);
                }
                found
            } else {
                let p = format!("{}{}", root.trim_end_matches('/'), req_path);
                tracing::debug!("checking direct file path: '{}'", p);
                if std::path::Path::new(&p).is_file() { 
                    tracing::info!("found file: '{}'", p);
                    Some(p) 
                } else { 
                    tracing::warn!("file not found: '{}'", p);
                    None 
                }
            };

            if let Some(p) = fs_path {
                match std::fs::read(&p) {
                    Ok(bytes) => {
                        res.headers_mut().insert(salvo::http::header::CONTENT_TYPE, salvo::http::HeaderValue::from_str(guess_mime(&p)).unwrap());
                        res.body(bytes);
                        return;
                    }
                    Err(_) => {
                        res.status_code(salvo::http::StatusCode::INTERNAL_SERVER_ERROR);
                        return;
                    }
                }
            }
        }
    } else {
        // no matching location; try server root
        if let Some(root) = srv.root.as_ref() {
            tracing::debug!("no location matched, using server root: '{}'", root);
            let fs_path = if req_path == "/" {
                let mut found = None;
                tracing::debug!("searching for index files in server.index={:?}", srv.index);
                for idx in srv.index.iter() {
                    let p = format!("{}/{}", root.trim_end_matches('/'), idx);
                    tracing::debug!("checking server-level index file: '{}'", p);
                    if std::path::Path::new(&p).is_file() { 
                        tracing::info!("found server-level index file: '{}'", p);
                        found = Some(p); 
                        break; 
                    }
                }
                if found.is_none() {
                    tracing::warn!("no server-level index file found in root '{}'", root);
                }
                found
            } else {
                let p = format!("{}{}", root.trim_end_matches('/'), req_path);
                tracing::debug!("checking server-level direct file path: '{}'", p);
                if std::path::Path::new(&p).is_file() { 
                    tracing::info!("found server-level file: '{}'", p);
                    Some(p) 
                } else { 
                    tracing::warn!("server-level file not found: '{}'", p);
                    None 
                }
            };

            if let Some(p) = fs_path {
                match std::fs::read(&p) {
                    Ok(bytes) => {
                        res.headers_mut().insert(salvo::http::header::CONTENT_TYPE, salvo::http::HeaderValue::from_str(guess_mime(&p)).unwrap());
                        res.body(bytes);
                        return;
                    }
                    Err(_) => {
                        res.status_code(salvo::http::StatusCode::INTERNAL_SERVER_ERROR);
                        return;
                    }
                }
            }
        }
    }

    // fallback
    res.status_code(salvo::http::StatusCode::NOT_FOUND);
}

#[tokio::main]
async fn main() {
    // Write pid process number.
    let pid_file = File::create("blog-server.pid");
    if let Ok(mut f) = pid_file {
        let _ = f.write_all(format!("{}", std::process::id()).as_bytes());
    }

    let _guard = clia_tracing_config::build()
        .filter_level("trace")
        .with_ansi(true)
        .to_stdout(false)
        .directory("./logs")
        .file_name("blog-server.log")
        .rolling("daily")
        .init();

    // Parse distr.conf via nginx-config + our extractor
    let cfg = std::fs::read_to_string("distr.conf").expect("distr.conf not found");
    let main = nginx_config::parse_main(&cfg).expect("failed to parse distr.conf");
    let mut servers = blog_server::nginx::extract_servers(&main);

    // validate `root` paths — do NOT fallback to ./static; missing files should return 404
    for s in servers.iter_mut() {
        if let Some(root_path) = s.root.as_ref() {
            if !std::path::Path::new(root_path).exists() {
                tracing::warn!("configured root '{}' for server {:?} does not exist; requests will return 404", root_path, s.server_names);
            }
        }

        for loc in s.locations.iter_mut() {
            if let Some(lroot) = loc.root.as_ref() {
                if !std::path::Path::new(lroot).exists() {
                    tracing::warn!("location root '{}' for pattern '{}' (server {:?}) does not exist; requests will return 404", lroot, loc.pattern, s.server_names);
                }
            }
        }
    }

    // build lookup map by server_name (exact matches only)
    let mut map = HashMap::new();
    for s in servers.into_iter() {
        for name in &s.server_names {
            // strip leading symbols used for special patterns in AST display
            let key = name.trim_start_matches("~").to_string();
            map.insert(key, s.clone());
        }
    }
    SERVERS.set(Arc::new(map)).ok();
    // startup diagnostic: log configured server names
    if let Some(sm) = SERVERS.get() {
        let names: Vec<String> = sm.keys().cloned().collect();
        tracing::info!("configured server_names: {:?}", names);
    }

    // collect all listen ports to bind
    use std::collections::BTreeSet;
    let mut ports = BTreeSet::new();
    if let Some(m) = SERVERS.get() {
        for (_k, v) in m.iter() {
            for l in &v.listens {
                if let Some(p) = l.port { ports.insert(p); }
            }
        }
    }
    // ensure default HTTP port if none specified
    if ports.is_empty() { ports.insert(3180); }

    // 必须在任何使用 rustls 之前调用
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("Failed to initialize crypto provider");

    // For each listen port, bind a TcpListener (enable ACME on port 443) and spawn
    // a Server task. This avoids complex generic types from `join()` chaining.
    let mut tasks = Vec::new();
    for p in ports {
        // recreate router per task (Router is cheap here)
        let r = Router::with_hoop(Compression::new().enable_gzip(CompressionLevel::Minsize))
            .push(Router::with_path("/__debug/servers").get(debug_servers))
            .push(Router::with_path("/hello").get(hello))
            .get(host_info)
            .post(host_info)
            .put(host_info)
            .delete(host_info)
            .head(host_info)
            .options(host_info)
            .patch(host_info);

        let task = tokio::spawn(async move {
            if p == 443 {
                let mut b = TcpListener::new(format!("0.0.0.0:{}", p)).acme().cache_path("temp/letsencrypt");
                if let Some(m) = SERVERS.get() {
                    for name in m.keys() {
                        b = b.add_domain(name.clone());
                    }
                }
                let acc = b.bind().await;
                let _ = Server::new(acc).serve(r).await;
            } else {
                let acc = TcpListener::new(format!("0.0.0.0:{}", p)).bind().await;
                let _ = Server::new(acc).serve(r).await;
            }
        });
        tasks.push(task);
    }

    // wait for all server tasks (will run until cancelled)
    for t in tasks {
        let _ = t.await;
    }
}


// #[ntex::main]
// async fn main0() -> std::io::Result<()> {
//     // Write pid process number.
//     let pid_file = File::create("blog-server.pid");
//     if let Ok(mut f) = pid_file {
//         let _ = f.write_all(format!("{}", std::process::id()).as_bytes());
//     }

//     // std::env::set_var("RUST_LOG", "ntex=trace");
//     // env_logger::init();

//     let _guard = clia_tracing_config::build()
//         .filter_level("trace")
//         .with_ansi(true)
//         .to_stdout(false)
//         .directory("./logs")
//         .file_name("blog-server.log")
//         .rolling("daily")
//         .init();

//     // nginx::read_config();

//     let args: Vec<String> = env::args().collect();

//     if args.len() != 3 {
//         println!("Usage: distr {{domain}} {{email}}");
//         process::exit(0x0100);
//     }
//     println!("{:?}", args);

//     let domain = args[1].clone();
//     let email = args[2].clone();
//     println!("domain: {domain}");
//     println!("email: {email}");

//     let res = cert::test_domain_exists(&domain);
//     let exists = match res {
//         Ok(e) => e,
//         Err(err) => {
//             println!("{}", err);
//             false
//         }
//     };
//     println!("exists: {}", exists);

//     if !exists {
//         ntex::rt::spawn(async move {
//             println!("Request cert...");
//             let res = acme::request_cert(&acme::AcmeInfo {
//                 domain: domain.to_owned(),
//                 email: email.to_owned(),
//                 web_root: "./static".to_owned(),
//             });
//             match res {
//                 Ok(crt) => match cert::create_cert_file(&domain, &crt) {
//                     Ok(_) => println!("Cert saved."),
//                     Err(err) => println!("{}", err),
//                 },
//                 Err(err) => {
//                     println!("{}", err);
//                     // process::exit(0x0100);
//                 }
//             }
//         });

//         web::server(|| {
//             App::new()
//                 // enable logger
//                 .wrap(middleware::Logger::default())
//                 .service(
//                     // static files
//                     fs::Files::new("/", "./static/").index_file("index.html"),
//                 )
//         })
//         .bind("0.0.0.0:80")?
//         .run()
//         .await
//     } else {
//         let key_path = format!("./cert/{}.key", domain);
//         let cert_path = format!("./cert/{}.pem", domain);

//         // // load ssl keys
//         // let mut builder = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
//         // builder
//         //     .set_private_key_file(&key_path, SslFiletype::PEM)
//         //     .unwrap();
//         // builder.set_certificate_chain_file(&cert_path).unwrap();

//         // load ssl keys
//         let key_file = &mut BufReader::new(File::open(&key_path).unwrap());
//         println!("{:?}", key_file);
//         // println!("{:?}", pkcs8_private_keys(key_file));
//         let key = PrivateKey(pkcs8_private_keys(key_file).unwrap().remove(0));
//         let cert_file = &mut BufReader::new(File::open(&cert_path).unwrap());
//         let cert_chain = certs(cert_file)
//             .unwrap()
//             .iter()
//             .map(|c| Certificate(c.to_vec()))
//             .collect();
//         let config = ServerConfig::builder()
//             .with_safe_defaults()
//             .with_no_client_auth()
//             .with_single_cert(cert_chain, key)
//             .unwrap();

//         web::server(|| {
//             App::new()
//                 // enable logger
//                 // .wrap(middleware::Logger::default())
//                 .service((
//                     web::resource("/index.html").to(|| async { "Hello world!" }),
//                     web::resource("/").to(index),
//                     // // static files
//                     // fs::Files::new("/", "./html/").index_file("index.html"),
//                     // // web::resource("/").to(|| async { "Hello world! Powered by distr." }),
//                 ))
//         })
//         .bind("0.0.0.0:80")?
//         .bind_rustls("0.0.0.0:443", config)?
//         // .bind_openssl("0.0.0.0:443", builder)?
//         .run()
//         .await
//     }

//     // libdistr::start().await
// }
