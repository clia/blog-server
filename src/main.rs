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

// use libdistr::{acme, cert};

// async fn index(req: HttpRequest) -> &'static str {
//     // println!("REQ: {:?}", req);
//     "Hello world!"
// }

#[handler]
async fn hello() -> &'static str {
    "Hello World"
}

#[tokio::main]
async fn main() {
    // Write pid process number.
    let pid_file = File::create("blog-server.pid");
    if let Ok(mut f) = pid_file {
        let _ = f.write_all(format!("{}", std::process::id()).as_bytes());
    }

    // std::env::set_var("RUST_LOG", "ntex=trace");
    // env_logger::init();

    let _guard = clia_tracing_config::build()
        .filter_level("trace")
        .with_ansi(true)
        .to_stdout(false)
        .directory("./logs")
        .file_name("blog-server.log")
        .rolling("daily")
        .init();

    // tracing_subscriber::fmt().init();

    // let router = Router::new().get(hello);
    let router = Router::with_hoop(Compression::new().enable_gzip(CompressionLevel::Minsize))
        .path("<*path>")
        .get(
            StaticDir::new([
                "static",
                // "static-dir-list/static/boy",
                // "static-dir-list/static/girl",
                // "static/boy",
                // "static/girl",
            ])
            .include_dot_files(false)
            .defaults("index.html")
            .auto_list(true),
        );
    let service = Service::new(router).hoop(ForceHttps::new().https_port(443));

    let acceptor = TcpListener::new("0.0.0.0:443")
        .acme()
        // .directory("letsencrypt", salvo::conn::acme::LETS_ENCRYPT_STAGING)
        .cache_path("temp/letsencrypt")
        .add_domain("clia.cc")
        // .add_domain("clia.us.to")
        // .add_domain("bailog.cn")
        // .add_domain("clia.tech")
        .join(TcpListener::new("0.0.0.0:80"))
        .bind()
        .await;

    let router_http = Router::new().get(hello);
    let acceptor_http = TcpListener::new("0.0.0.0:3180").bind().await;

    // 同时监听 HTTP 和 HTTPS 端口
    tokio::select! {
        _ = Server::new(acceptor).serve(service) => {},
        _ = Server::new(acceptor_http).serve(router_http) => {},
    }
    // Server::new(acceptor).serve(router).await;
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
