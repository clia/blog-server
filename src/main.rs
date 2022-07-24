use std::fs::File;
use std::io::prelude::*;

#[ntex::main]
async fn main() -> std::io::Result<()> {
    // Write pid process number.
    let pid_file = File::create("blog-server.pid");
    if let Ok(mut f) = pid_file {
        let _ = f.write_all(format!("{}", std::process::id()).as_bytes());
    }

    libdistr::start().await
}
