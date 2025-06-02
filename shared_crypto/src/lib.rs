// sistema_chat_criptografado/shared_crypto/src/lib.rs

// Declaração dos módulos da biblioteca.
pub mod rsa;
pub mod base64;
pub mod sha256;
pub mod models;

// Exporta as structs e funções públicas principais para fácil acesso pelas aplicações.
pub use rsa::RSAKeys;
pub use base64::{base64_encode, base64_decode};
pub use sha256::{sha256_from_bytes, sha256_from_stream, format_hash_hex, is_valid_sha256_hex_format};
pub use models::{PublicKeyExchangeMessage, EncryptedChatMessage};
