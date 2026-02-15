//! Minimal test: does Salvo's StaticDir actually work?
//! Run with: cargo run --example test_static_dir

use salvo::prelude::*;
use salvo::serve_static::StaticDir;

/// Debug handler — prints what the router matched
#[handler]
async fn debug_handler(req: &mut Request) -> String {
    let uri = req.uri().path().to_owned();
    let params: Vec<_> = req
        .params()
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect();
    let tail = req.params().tail().map(|s| s.to_owned());
    format!("uri={uri}  params=[{}]  tail={tail:?}\n", params.join(", "))
}

#[tokio::main]
async fn main() {
    // 使用正确的 {} 语法测试 StaticDir
    // 使用 .goal() 来支持 GET/HEAD 等所有方法
    let router = Router::with_path("{**path}").goal(
        StaticDir::new(["static"])
            .defaults("index.html")
            .auto_list(true),
    );

    println!("StaticDir test on http://127.0.0.1:3456");
    let acceptor = TcpListener::new("127.0.0.1:3456").bind().await;
    Server::new(acceptor).serve(router).await;
}
