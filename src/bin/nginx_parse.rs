use std::fs;
use std::path::Path;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 从仓库根目录读取 `distr.conf`
    let path = Path::new("distr.conf");
    if !path.exists() {
        eprintln!("File 'distr.conf' not found in project root.");
        std::process::exit(1);
    }
    let contents = fs::read_to_string(path)?;

    // 使用 `nginx-config` 的 `parse_main` 解析顶层配置
    match nginx_config::parse_main(&contents) {
        Ok(main) => {
            // 打印结构化 AST
            println!("Parsed AST:\n{:#?}", main);

            // 提取并打印 Server 信息
            let servers = blog_server::nginx::extract_servers(&main);
            println!("\nExtracted servers summary ({}):\n", servers.len());
            for (i, s) in servers.iter().enumerate() {
                println!("Server #{}: {:#?}\n", i + 1, s);
            }
        }
        Err(err) => {
            eprintln!("parse failed: {}", err);
            // 作为回退，直接打印原始内容
            println!("\nRaw config:\n{}", contents);
        }
    }

    Ok(())
}
