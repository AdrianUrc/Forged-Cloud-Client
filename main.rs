use anyhow::Ok;
use regex::Regex;
use rpassword::read_password;
use rustls::{Certificate, ClientConfig, PrivateKey, RootCertStore};
use rustls_pemfile::{certs, pkcs8_private_keys};
use std::fs::File;
use std::io::BufReader;
use std::io::{self, Write};
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ServerName;

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .with_target(false)
        .with_thread_names(true)
        .init();
    let tls_config = load_tls_client_config();
    let connector = TlsConnector::from(Arc::new(tls_config));

    let banner = r#"
                                                  .-""-.
    ___ _ _ _ _ _ _ _ __ _ _ _  _ _ _ _ __       / .--. \
   |                                      |     / /    \ \
   | ▛▀▘             ▌   ▞▀▖▜ ▗       ▐   |     | |    | |
   | ▙▄▞▀▖▙▀▖▞▀▌▞▀▖▞▀▌   ▌  ▐ ▄ ▞▀▖▛▀▖▜▀  |     | |.-""-.|
   | ▌ ▌ ▌▌  ▚▄▌▛▀ ▌ ▌   ▌ ▖▐ ▐ ▛▀ ▌ ▌▐ ▖ |    ///`.::::.`\
   | ▘ ▝▀ ▘  ▗▄▘▝▀▘▝▀▘   ▝▀  ▘▀▘▝▀▘▘ ▘ ▀  |   ||| ::/  \:: ;
   |__ _ _ _ _ _ _ _ __ _ _  _ _ _ _ _ _ _|   ||; ::\__/:: ;
                                               \\\ '::::' /
                                                `=':-..-'`
    "#;
    println!("{}", banner.to_string());
    println!(" |- - - - - - - - - - Forged Client Setup - - - - - - - - - -|\n");
    let host = read_host("   [*] Enter server IP/DNS (or 'localhost'): ");
    let port = read_port("   [*] Enter server PORT: ");
    println!("\n |- - - - - - - - - - - - - - - - - - - - - - - - - - - - - -|\n");

    let server_addr = format!("{}:{}", host, port);

    let tcp_stream = tokio::net::TcpStream::connect(&server_addr).await?;

    let server_name = ServerName::try_from(host.as_str()).unwrap();
    let tls_stream = connector.connect(server_name, tcp_stream).await?;

    let (mut reader, mut writer) = tokio::io::split(tls_stream);

    read_until_prompt(&mut reader, " [*] Enter password to log in: ").await?;

    send_password(&mut writer).await?;

    interactive_loop(reader, writer).await?;

    return std::io::Result::Ok(());
}

fn load_tls_client_config() -> ClientConfig {
    let mut ca_reader = BufReader::new(File::open("certs/ca.pem").expect("cannot open ca.pem"));
    let mut root_store = RootCertStore::empty();
    root_store
        .add_parsable_certificates(&certs(&mut ca_reader).expect("failed to read CA certificate"));

    let mut cert_reader =
        BufReader::new(File::open("certs/client-cert.pem").expect("cannot open client-cert.pem"));
    let client_cert_chain: Vec<Certificate> = certs(&mut cert_reader)
        .expect("failed to read client certificates")
        .into_iter()
        .map(Certificate)
        .collect();
    let mut key_reader =
        BufReader::new(File::open("certs/client-key.pem").expect("cannot open client_key.pem"));
    let mut keys: Vec<PrivateKey> = pkcs8_private_keys(&mut key_reader)
        .expect("failed to read client private key")
        .into_iter()
        .map(PrivateKey)
        .collect();

    assert!(!keys.is_empty(), "no private keys found in client_key.pem");

    ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store) // verify SERVER cert
        .with_client_auth_cert(client_cert_chain, keys.remove(0)) // send CLIENT cert+key
        .expect("invalid client certificate or key")
}
fn read_port(prompt: &str) -> u16 {
    loop {
        print!("{}", prompt);
        std::io::Write::flush(&mut std::io::stdout()).unwrap();
        let mut input = String::new();
        if std::io::stdin().read_line(&mut input).is_ok() {
            if let std::result::Result::Ok(port) = input.trim().parse::<u16>() {
                if port > 0 {
                    return port;
                }
            }
        }
        println!(" [!] Invalid port. Please enter a number between 1 and 65535.");
    }
}
fn read_host(prompt: &str) -> String {
    let dns_regex = Regex::new(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$").unwrap();

    loop {
        print!("{}", prompt);
        io::stdout().flush().unwrap();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_ok() {
            let trimmed = input.trim();

            // localhost
            if trimmed.eq_ignore_ascii_case("localhost") {
                return "127.0.0.1".to_string();
            }

            // verify IP
            if trimmed.parse::<core::net::IpAddr>().is_ok() {
                return trimmed.to_string();
            }

            // verify dns
            if dns_regex.is_match(trimmed) {
                return trimmed.to_string();
            }

            println!(
                " [!] Invalid address. Enter a valid IP, 'localhost', or DNS (example: example.duckdns.org)."
            );
        }
    }
}
async fn read_until_prompt<R: AsyncReadExt + Unpin>(
    reader: &mut R,
    prompt: &str,
) -> tokio::io::Result<()> {
    let mut buffer = vec![0u8; 1024];
    let mut collected = Vec::new();

    loop {
        let n = reader.read(&mut buffer).await?;
        if n == 0 {
            break; // conexión cerrada
        }
        collected.extend_from_slice(&buffer[..n]);

        print!("{}", String::from_utf8_lossy(&buffer[..n]));
        std::io::stdout().flush().unwrap();

        if String::from_utf8_lossy(&collected).contains(prompt) {
            break;
        }
    }
    tokio::io::Result::Ok(())
}
async fn send_password<W: AsyncWriteExt + Unpin>(writer: &mut W) -> tokio::io::Result<()> {
    std::io::stdout().flush().unwrap();
    let password = read_password().expect("Cannot read password.");
    writer.write_all(password.trim_end().as_bytes()).await?;
    writer.write_all(b"\n").await?;
    tokio::io::Result::Ok(())
}
async fn interactive_loop<R, W>(mut reader: R, mut writer: W) -> tokio::io::Result<()>
where
    R: AsyncReadExt + Unpin,
    W: AsyncWriteExt + Unpin,
{
    let (tx, mut rx) = tokio::sync::mpsc::channel::<String>(32);

    tokio::spawn(async move {
        let mut input = String::new();
        loop {
            input.clear();
            io::stdout().flush().unwrap();
            if io::stdin().read_line(&mut input).is_ok() {
                if tx.send(input.clone()).await.is_err() {
                    break; // canal cerrado
                }
            }
        }
    });

    let mut buffer = vec![0u8; 1024];

    loop {
        tokio::select! {
            n = reader.read(&mut buffer) => {
                let n = n?;
                if n == 0 {
                    println!("\n [Server disconnected]");
                    break;
                }
                print!("{}", String::from_utf8_lossy(&buffer[..n]));
                io::stdout().flush().unwrap();
            }

            Some(input) = rx.recv() => {
                let trimmed = input.trim().to_string();

                if trimmed.starts_with("UPLOAD ") {
                    if let Err(e) = handle_upload(&trimmed, &mut writer).await {
                        println!(" [UPLOAD ERROR] {}", e);
                        print!(" [*] > ");
                        std::io::stdout().flush().unwrap();
                    }

                    continue;
                }
                writer.write_all(input.as_bytes()).await?;
            }

        }
    }

    tokio::io::Result::Ok(())
}
async fn handle_upload(cmd: &str, writer: &mut (impl AsyncWriteExt + Unpin)) -> anyhow::Result<()> {
    let mut parts = cmd.split_whitespace();
    parts.next(); //UPLOAD
    let Some(path) = parts.next() else {
        println!(" [ERROR] Usage: 'UPLOAD <path_to_file>'.");
        print!(" [*] > ");
        std::io::stdout().flush().unwrap();
        return Ok(());
    };
    let file_path = std::path::Path::new(path);
    if !file_path.exists() {
        println!(" [ERROR] Path doesn't exists.");
        print!(" [*] > ");
        std::io::stdout().flush().unwrap();
        return Ok(());
    }
    let file = std::fs::File::open(file_path)?;
    let metadata = file.metadata()?;
    let size_bytes = metadata.size();

    let header = format!(
        "UPLOAD {} {}",
        file_path.file_name().unwrap().to_str().unwrap(),
        size_bytes
    );
    let mut f = tokio::fs::File::open(file_path).await?;
    writer.write_all(header.as_bytes()).await?;
    writer.write_all(b"\n").await?;
    let mut buf = [0u8; 4096];
    loop {
        let n = f.read(&mut buf).await?;
        if n == 0 {
            // EOF
            break;
        }
        writer.write_all(&buf[..n]).await?;
    }
    Ok(())
}
