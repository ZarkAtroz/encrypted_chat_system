// sistema_chat_criptografado/shared_crypto/src/models.rs

use serde::{Serialize, Deserialize};

/// Mensagem para trocar chaves públicas e URLs de webhook.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PublicKeyExchangeMessage {
    pub e: String,           // Expoente público (e) como string
    pub n: String,           // Módulo (n) como string
    pub webhook_url: String, // URL do webhook do remetente
    pub sender_id: String,   // Identificador de quem enviou a chave (ex: "App_Um")
}

/// Mensagem de chat criptografada.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EncryptedChatMessage {
    pub ciphertext_b64: String, // Texto cifrado (BigUint -> bytes -> Base64 string)
    pub sender_id: String,      // Identificador de quem enviou a mensagem
}
