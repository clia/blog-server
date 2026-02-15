
/// Lightweight structs that represent server configuration extracted from
/// nginx-style AST (from `nginx-config` crate).
#[derive(Debug, Clone)]
pub struct ListenInfo {
    pub addr: String,    // textual address (ip:port or :port or unix path)
    pub port: Option<u16>,
    pub ssl: bool,
    pub default_server: bool,
}

#[derive(Debug, Clone)]
pub struct LocationInfo {
    pub pattern: String,
    pub root: Option<String>,
    pub index: Vec<String>,
    pub proxy_pass: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct ErrorPageInfo {
    pub codes: Vec<u32>,
    pub uri: String,
}

#[derive(Debug, Clone)]
pub struct AccessLogInfo {
    pub path: String,
    pub format: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ErrorLogInfo {
    pub path: String,
    pub level: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ServerInfo {
    pub listens: Vec<ListenInfo>,
    pub server_names: Vec<String>,
    pub root: Option<String>,
    pub index: Vec<String>,
    pub locations: Vec<LocationInfo>,
    pub error_pages: Vec<ErrorPageInfo>,

    // indicates this server was marked `default_server` on at least one `listen`
    pub default_server: bool,

    // additional fields
    pub access_log: Option<AccessLogInfo>,
    pub error_log: Option<ErrorLogInfo>,
    pub ssl_certificate: Option<String>,
    pub ssl_certificate_key: Option<String>,
    pub client_max_body_size: Option<String>,
    pub proxy_passes: Vec<String>,
    pub keepalive_timeout: Option<String>,
}

impl ServerInfo {
    pub fn new() -> ServerInfo {
        ServerInfo {
            listens: Vec::new(),
            server_names: Vec::new(),
            root: None,
            index: Vec::new(),
            locations: Vec::new(),
            error_pages: Vec::new(),
            default_server: false,
            access_log: None,
            error_log: None,
            ssl_certificate: None,
            ssl_certificate_key: None,
            client_max_body_size: None,
            proxy_passes: Vec::new(),
            keepalive_timeout: None,
        }
    }
}

/// Convert nginx-config `Value` to a readable String. Variables are kept as `$name`.
fn value_to_string(v: &nginx_config::ast::Value) -> String {
    // `nginx-config` implements `Display` for `Value` — use that public API.
    format!("{}", v)
}

fn server_name_to_string(sn: &nginx_config::ast::ServerName) -> String {
    use nginx_config::ast::ServerName::*;
    match sn {
        Exact(s) => s.clone(),
        Suffix(s) => format!(".{}", s),
        StarSuffix(s) => format!("*.{}", s),
        StarPrefix(s) => format!("{}.*", s),
        Regex(s) => format!("~{}", s),
    }
}

fn listen_address_to_string(addr: &nginx_config::ast::Address) -> (String, Option<u16>) {
    use nginx_config::ast::Address::*;
    match addr {
        Ip(sa) => (format!("{}", sa), Some(sa.port())),
        StarPort(p) => (format!(":{}", p), Some(*p)),
        Port(p) => (format!(":{}", p), Some(*p)),
        Unix(path) => (format!("unix:{}", path.display()), None),
    }
}

/// Extract ServerInfo list from a parsed AST `Main`.
pub fn extract_servers(main: &nginx_config::ast::Main) -> Vec<ServerInfo> {
    use nginx_config::ast::Item;

    let mut out = Vec::new();

    fn collect_from_directives(dirs: &[nginx_config::ast::Directive], out: &mut Vec<ServerInfo>) {
        use nginx_config::ast::Item;
        for d in dirs {
            match &d.item {
                Item::Server(srv) => {
                    // same extraction logic as before
                    let mut info = ServerInfo::new();
                    for sd in &srv.directives {
                        match &sd.item {
                            Item::Listen(lst) => {
                                let (addr, port) = listen_address_to_string(&lst.address);
                                info.listens.push(ListenInfo {
                                    addr,
                                    port,
                                    ssl: lst.ssl,
                                    default_server: lst.default_server,
                                });
                                // if any listen is marked `default_server`, mark the server
                                if lst.default_server {
                                    info.default_server = true;
                                }
                            }
                            Item::ServerName(names) => {
                                for n in names {
                                    info.server_names.push(server_name_to_string(n));
                                }
                            }
                            Item::Root(val) => {
                                info.root = Some(value_to_string(val));
                            }
                            Item::Index(vals) => {
                                for v in vals {
                                    info.index.push(value_to_string(v));
                                }
                            }
                            Item::Location(loc) => {
                                let mut li = LocationInfo {
                                    pattern: match &loc.pattern {
                                        nginx_config::ast::LocationPattern::Prefix(p) => p.clone(),
                                        nginx_config::ast::LocationPattern::Exact(p) => p.clone(),
                                        nginx_config::ast::LocationPattern::FinalPrefix(p) => p.clone(),
                                        nginx_config::ast::LocationPattern::Regex(p) => format!("~{}", p),
                                        nginx_config::ast::LocationPattern::RegexInsensitive(p) => format!("~*{}", p),
                                        nginx_config::ast::LocationPattern::Named(n) => n.clone(),
                                    },
                                    root: None,
                                    index: Vec::new(),
                                    proxy_pass: Vec::new(),
                                };
                                for ld in &loc.directives {
                                    match &ld.item {
                                        Item::Root(v) => li.root = Some(value_to_string(v)),
                                        Item::Index(vals) => {
                                            for v in vals {
                                                li.index.push(value_to_string(v));
                                            }
                                        }
                                        Item::ProxyPass(val) => {
                                            li.proxy_pass.push(value_to_string(val));
                                        }
                                        _ => {}
                                    }
                                }
                                info.locations.push(li);
                            }
                            Item::ErrorPage(ep) => {
                                info.error_pages.push(ErrorPageInfo {
                                    codes: ep.codes.clone(),
                                    uri: value_to_string(&ep.uri),
                                });
                            }

                            /* additional fields requested */
                            Item::AccessLog(al) => {
                                match al {
                                    nginx_config::ast::AccessLog::Off => { info.access_log = None; }
                                    nginx_config::ast::AccessLog::On(opts) => {
                                        let path = value_to_string(&opts.path);
                                        let fmt = opts.format.clone();
                                        info.access_log = Some(AccessLogInfo { path, format: fmt });
                                    }
                                }
                            }
                            Item::ErrorLog { file, level } => {
                                let path = value_to_string(file);
                                let lvl = level.as_ref().map(|l| match l {
                                    nginx_config::ast::ErrorLevel::Debug => "debug",
                                    nginx_config::ast::ErrorLevel::Info => "info",
                                    nginx_config::ast::ErrorLevel::Notice => "notice",
                                    nginx_config::ast::ErrorLevel::Warn => "warn",
                                    nginx_config::ast::ErrorLevel::Error => "error",
                                    nginx_config::ast::ErrorLevel::Crit => "crit",
                                    nginx_config::ast::ErrorLevel::Alert => "alert",
                                    nginx_config::ast::ErrorLevel::Emerg => "emerg",
                                }.to_string());
                                info.error_log = Some(ErrorLogInfo { path, level: lvl });
                            }
                            Item::SslCertificate(val) => {
                                info.ssl_certificate = Some(value_to_string(val));
                            }
                            Item::SslCertificateKey(val) => {
                                info.ssl_certificate_key = Some(value_to_string(val));
                            }
                            Item::ClientMaxBodySize(val) => {
                                info.client_max_body_size = Some(value_to_string(val));
                            }
                            Item::ProxyPass(val) => {
                                info.proxy_passes.push(value_to_string(val));
                            }
                            Item::KeepaliveTimeout(val, _opt) => {
                                info.keepalive_timeout = Some(value_to_string(val));
                            }

                            _ => {}
                        }
                    }
                    out.push(info);
                }
                other => {
                    // recurse into children if any
                    if let Some(children) = other.children() {
                        collect_from_directives(children, out);
                    }
                }
            }
        }
    }

    collect_from_directives(&main.directives, &mut out);
    out
}
