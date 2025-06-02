// app_one/src/main.rs
use shared_crypto::rsa::RSAKeys; // Example of using the shared library
use std::io::{self, Write};
use num_bigint::BigUint; // For message conversion

// Placeholder for the other app's public key and URL
struct PeerInfo {
    public_key: Option<(BigUint, BigUint)>, // (e, n)
    webhook_url: String,
}

fn main() -> io::Result<()> {
    println!("App One starting...");

    // 1. Generate own RSA keys
    let my_keys = match RSAKeys::generate(512) { // Using 512 bits for faster testing, use 2048+ for real use
        Ok(keys) => {
            println!("My RSA keys generated.");
            keys
        }
        Err(e) => {
            eprintln!("Failed to generate keys: {}", e);
            return Ok(());
        }
    };

    // TODO: Implement HTTP server for webhook
    // TODO: Implement CLI for sending messages and initiating key exchange
    // TODO: Implement logic for key exchange (sending own public key, receiving peer's public key)
    // TODO: Store peer's public key and webhook URL

    println!("App One setup complete. Waiting for actions or incoming messages...");
    // Dummy loop
    loop {
        print!("Enter command (type 'exit' to quit): ");
        io::stdout().flush()?;
        let mut command = String::new();
        if io::stdin().read_line(&mut command)? == 0 { // Handle EOF
            break;
        }
        if command.trim() == "exit" {
            break;
        }
        // Process other commands
    }

    Ok(())
}