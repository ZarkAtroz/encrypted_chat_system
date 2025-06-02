// sistema_chat_criptografado/app_dois/src/main.rs

use shared_crypto::rsa::{RSAKeys};
use shared_crypto::base64::{base64_encode, base64_decode};
use shared_crypto::models::{PublicKeyExchangeMessage, EncryptedChatMessage};
use num_bigint::BigUint;
use std::io::{self, Write};
use std::sync::{Arc, Mutex};
use actix_web::{web, App, HttpServer, Responder, HttpResponse};
use reqwest::Client;
use inquire::{Select, Text, Confirm};
use clearscreen::clear;

struct AppState {
    my_keys: Option<RSAKeys>,
    peer_public_key: Option<(BigUint, BigUint)>,
    peer_webhook_url: Option<String>,
    my_id: String,
    my_webhook_port: u16,
}

async fn handle_key_exchange(
    req_body: web::Json<PublicKeyExchangeMessage>,
    data: web::Data<Arc<Mutex<AppState>>>,
) -> impl Responder {
    println!("[DEBUG] Handler handle_key_exchange chamado.");
    let mut app_state = data.lock().unwrap();
    
    match req_body.e.parse::<BigUint>() {
        Ok(e_val) => match req_body.n.parse::<BigUint>() {
            Ok(n_val) => {
                app_state.peer_public_key = Some((e_val, n_val));
                app_state.peer_webhook_url = Some(req_body.webhook_url.clone());
                println!("\n✅ Chave pública de '{}' recebida e URL do webhook definida para: {}", req_body.sender_id, req_body.webhook_url);
                println!("    Agora você pode enviar mensagens para ele.");
                
                if let Some(my_keys) = &app_state.my_keys {
                    let my_public_key_msg = PublicKeyExchangeMessage {
                        e: my_keys.public_key.0.to_string(),
                        n: my_keys.public_key.1.to_string(),
                        webhook_url: format!("http://localhost:{}", app_state.my_webhook_port),
                        sender_id: app_state.my_id.clone(),
                    };
                    HttpResponse::Ok().json(my_public_key_msg)
                } else {
                    eprintln!("[DEBUG] Minhas chaves não geradas ao responder key exchange.");
                    HttpResponse::InternalServerError().body("Minhas chaves RSA não foram geradas ainda.")
                }
            }
            Err(e) => {
                eprintln!("[DEBUG] Erro parse N em key exchange: {}", e);
                HttpResponse::BadRequest().body("Formato de 'n' da chave pública inválido.")
            },
        },
        Err(e) => {
            eprintln!("[DEBUG] Erro parse E em key exchange: {}", e);
            HttpResponse::BadRequest().body("Formato de 'e' da chave pública inválido.")
        },
    }
}

async fn handle_chat_message(
    req_body: web::Json<EncryptedChatMessage>,
    data: web::Data<Arc<Mutex<AppState>>>,
) -> impl Responder {
    let _stdout_lock = io::stdout().lock();
    println!(""); 

    let app_state = data.lock().unwrap();

    if let Some(my_keys) = &app_state.my_keys {
        match base64_decode(&req_body.ciphertext_b64) {
            Ok(cipher_bytes) => {
                let cipher_num = BigUint::from_bytes_be(&cipher_bytes);
                match my_keys.decrypt(&cipher_num) {
                    Ok(decrypted_num) => {
                        let decrypted_bytes = decrypted_num.to_bytes_be();
                        match String::from_utf8(decrypted_bytes) {
                            Ok(decrypted_message) => {
                                println!("\r<-- [{}] {}", req_body.sender_id, decrypted_message);
                                HttpResponse::Ok().body("Mensagem recebida e decifrada com sucesso.")
                            }
                            Err(e) => {
                                eprintln!("[DEBUG CHAT RECEBIDO] Erro ao converter bytes decifrados para UTF-8: {}. Bytes: {:?}", e, decrypted_num.to_bytes_be());
                                HttpResponse::InternalServerError().body("Erro ao decifrar mensagem (não é UTF-8 válido).")
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[DEBUG CHAT RECEBIDO] Erro ao descriptografar: {}. Ciphertext (num): {}", e, cipher_num);
                        HttpResponse::InternalServerError().body(format!("Erro ao descriptografar: {}", e))
                    }
                }
            }
            Err(e) => {
                eprintln!("[DEBUG CHAT RECEBIDO] Erro de decodificação Base64: {}", e);
                HttpResponse::BadRequest().body(format!("Erro de decodificação Base64: {}", e))
            }
        }
    } else {
        eprintln!("[DEBUG CHAT RECEBIDO] Tentativa de descriptografar sem minhas chaves RSA.");
        HttpResponse::InternalServerError().body("Minhas chaves RSA não estão disponíveis para descriptografar.")
    }
}

async fn start_chat_mode(
    app_state_arc: Arc<Mutex<AppState>>,
    http_client: &Client,
) -> io::Result<()> {
    clear().unwrap_or_else(|e| eprintln!("Erro ao limpar tela: {}", e));
    println!("--- Modo Chat ---");
    println!("Você está conectado. Digite suas mensagens abaixo.");
    println!("Digite '/sair' ou '/exit' para voltar ao menu principal.");
    println!("----------------------------------------------------");

    loop {
        let (can_chat, my_id_clone, peer_public_key_clone, peer_url_clone) = {
            let state = app_state_arc.lock().unwrap();
            if state.my_keys.is_none() {
                println!("❌ Erro: Suas chaves RSA não foram geradas. Por favor, gere-as no menu principal.");
                (false, String::new(), None, None)
            } else if state.peer_public_key.is_none() || state.peer_webhook_url.is_none() {
                println!("❌ Erro: A chave pública do peer ou a URL do webhook não está definida. Realize a troca de chaves no menu principal.");
                (false, String::new(), None, None)
            } else {
                (
                    true,
                    state.my_id.clone(),
                    state.peer_public_key.clone(),
                    state.peer_webhook_url.clone(),
                )
            }
        };

        if !can_chat {
            println!("\nPressione Enter para voltar ao menu principal...");
            io::stdout().flush()?;
            io::stdin().read_line(&mut String::new())?;
            break;
        }
        
        let peer_public_key = peer_public_key_clone.unwrap();
        let peer_url = peer_url_clone.unwrap();

        print!("Você: ");
        io::stdout().flush()?;

        let mut message_text = String::new();
        if io::stdin().read_line(&mut message_text)? == 0 {
            println!("EOF detectado. Saindo do modo chat...");
            break;
        }
        let message_text = message_text.trim();

        if message_text.eq_ignore_ascii_case("/sair") || message_text.eq_ignore_ascii_case("/exit") {
            println!("Saindo do modo chat...");
            break;
        }

        if message_text.is_empty() {
            continue;
        }

        let message_bytes = message_text.as_bytes();
        let message_biguint = BigUint::from_bytes_be(message_bytes);

        match RSAKeys::encrypt_with_external_key(&message_biguint, &peer_public_key.0, &peer_public_key.1) {
            Ok(encrypted_biguint) => {
                let encrypted_bytes = encrypted_biguint.to_bytes_be();
                let ciphertext_b64 = base64_encode(&encrypted_bytes);

                let chat_message_payload = EncryptedChatMessage {
                    ciphertext_b64,
                    sender_id: my_id_clone.clone(),
                };

                let client_clone = http_client.clone();
                let url_clone = peer_url.clone();
                let payload_clone = chat_message_payload.clone();

                tokio::spawn(async move {
                    println!("[CHAT->] Enviando para {}...", url_clone);
                    match client_clone.post(&format!("{}/chat", url_clone))
                                .json(&payload_clone)
                                .send()
                                .await 
                    {
                        Ok(response) => {
                            if !response.status().is_success() {
                                let status = response.status();
                                match response.text().await {
                                    Ok(text) => eprintln!("\r[ERRO ENVIO]: Status {}, Resposta: {}", status, text),
                                    Err(_) => eprintln!("\r[ERRO ENVIO]: Status {} e erro ao ler corpo.", status),
                                }
                            }
                        }
                        Err(e) => eprintln!("\r[ERRO ENVIO]: Rede - {}", e),
                    }
                });
            }
            Err(e) => {
                eprintln!("\r[ERRO CRIPTO]: {}", e);
                print!("Você: ");
                io::stdout().flush()?;
            }
        }
    }
    clear().unwrap_or_else(|e| eprintln!("Erro ao limpar tela: {}", e));
    Ok(())
}


#[tokio::main]
async fn main() -> io::Result<()> {
    clear().unwrap_or_else(|e| eprintln!("Erro ao limpar tela: {}",e));

    // ***** ALTERAÇÕES PRINCIPAIS PARA APP_DOIS *****
    let app_id = "App_Dois".to_string();
    let my_port: u16 = 8081;
    // ***** FIM DAS ALTERAÇÕES PRINCIPAIS *****

    println!("[DEBUG] App ID: {}, Porta: {}", app_id, my_port);

    let app_state = Arc::new(Mutex::new(AppState {
        my_keys: None,
        peer_public_key: None,
        peer_webhook_url: None,
        my_id: app_id.clone(),
        my_webhook_port: my_port,
    }));
    println!("[DEBUG] AppState inicializado.");

    let server_state_ref = Arc::clone(&app_state);
    let my_address = format!("127.0.0.1:{}", my_port);
    
    println!("[DEBUG] Servidor HTTP irá configurar rotas ao ser construído por cada worker.");

    let server_handle = tokio::spawn(async move {
        println!("[DEBUG THREAD SERVIDOR] Iniciando HttpServer para {} em http://{}", app_id, my_address); 
        HttpServer::new(move || {
            App::new()
                .app_data(web::Data::new(Arc::clone(&server_state_ref)))
                .route("/key-exchange", web::post().to(handle_key_exchange))
                .route("/chat", web::post().to(handle_chat_message))
        })
        .bind(&my_address)
        .expect(&format!("[PANIC] Não foi possível ligar o servidor à porta {}", my_port))
        .run()
        .await
        .expect("[PANIC] Falha ao executar o servidor HTTP (run.await falhou)");
        println!("[DEBUG THREAD SERVIDOR] Servidor HTTP para {} foi encerrado.", app_id);
    });
    println!("[DEBUG] Spawn do servidor HTTP solicitado e thread principal continua.");

    let http_client = Client::new();

    loop {
        clear().unwrap_or_else(|e| eprintln!("Erro ao limpar tela: {}",e));
        
        let current_app_id;
        let current_my_port;
        { 
            let state_locked = app_state.lock().unwrap();
            current_app_id = state_locked.my_id.clone();
            current_my_port = state_locked.my_webhook_port;
        }
        println!("\n--- {} (Porta {}) ---", current_app_id, current_my_port);

        let options = vec![
            "1. Gerar Minhas Chaves RSA",
            "2. Trocar Chave Pública com Outro Peer",
            "3. Enviar Mensagem Criptografada (Única)",
            "4. Ver Estado Atual (Minhas Chaves/Info do Peer)",
            "5. Entrar no Modo Chat",
            "6. Sair",
        ];
        
        io::stdout().flush()?;
        let choice_str = match Select::new("O que você gostaria de fazer?", options).prompt() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Erro ao ler a seleção: {}. Saindo.", e);
                break;
            }
        };

        match choice_str {
            "1. Gerar Minhas Chaves RSA" => {
                let bits_str = Text::new("Digite o número de bits para as chaves RSA (ex: 512, 1024):").with_initial_value("512").prompt().unwrap_or_default();
                match bits_str.trim().parse::<usize>() {
                    Ok(bits) => {
                        println!("Gerando chaves de {} bits...", bits);
                        let mut state = app_state.lock().unwrap();
                        match RSAKeys::generate(bits) {
                            Ok(keys) => {
                                println!("✅ Chaves RSA geradas com sucesso!");
                                state.my_keys = Some(keys);
                            }
                            Err(e) => eprintln!("❌ Erro ao gerar chaves: {}", e),
                        }
                    }
                    Err(_) => eprintln!("Entrada inválida para o número de bits."),
                }
            }
            "2. Trocar Chave Pública com Outro Peer" => {
                let (my_keys_clone_opt, my_webhook_url_for_exchange, my_id_clone_for_exchange, default_peer_port_str) = {
                    let state_guard = app_state.lock().unwrap(); 
                    if state_guard.my_keys.is_none() {
                        println!("Gere suas chaves RSA primeiro (Opção 1).");
                        (None, String::new(), String::new(), "0".to_string())
                    } else {
                        (
                            Some(state_guard.my_keys.as_ref().unwrap().clone()),
                            format!("http://localhost:{}", state_guard.my_webhook_port),
                            state_guard.my_id.clone(),
                            // ***** ALTERAÇÃO PARA APP_DOIS *****
                            (if state_guard.my_webhook_port == 8081 {"8080"} else {"8081"}).to_string() 
                        )
                    }
                };
                
                if my_keys_clone_opt.is_none() { 
                    continue;
                }
                let my_keys_clone = my_keys_clone_opt.unwrap();
                        
                let peer_url_prompt = format!("Digite a URL do webhook do outro peer (ex: http://localhost:{}):", default_peer_port_str);
                let peer_url = Text::new(&peer_url_prompt).with_initial_value(&format!("http://localhost:{}", default_peer_port_str)).prompt().unwrap_or_default();

                if peer_url.is_empty() {
                    println!("URL do peer não pode ser vazia.");
                    continue;
                }

                let my_public_key_msg = PublicKeyExchangeMessage {
                    e: my_keys_clone.public_key.0.to_string(),
                    n: my_keys_clone.public_key.1.to_string(),
                    webhook_url: my_webhook_url_for_exchange,
                    sender_id: my_id_clone_for_exchange,
                };

                println!("[DEBUG] Enviando chave para: {}/key-exchange", peer_url);
                match http_client.post(&format!("{}/key-exchange", peer_url))
                            .json(&my_public_key_msg)
                            .send()
                            .await
                {
                    Ok(response) => {
                        println!("[DEBUG] Resposta da troca de chaves status: {}", response.status());
                        if response.status().is_success() {
                            match response.json::<PublicKeyExchangeMessage>().await {
                                Ok(peer_response_key_msg) => {
                                    match peer_response_key_msg.e.parse::<BigUint>() {
                                        Ok(e_val) => match peer_response_key_msg.n.parse::<BigUint>() {
                                            Ok(n_val) => {
                                                let mut state_after_network = app_state.lock().unwrap();
                                                state_after_network.peer_public_key = Some((e_val, n_val));
                                                state_after_network.peer_webhook_url = Some(peer_response_key_msg.webhook_url.clone());
                                                println!("✅ Chave pública do peer ({}) recebida e URL do webhook definida para: {}", peer_response_key_msg.sender_id, peer_response_key_msg.webhook_url);
                                            }
                                            Err(e) => eprintln!("Erro ao decodificar 'n' da chave pública do peer: {}", e),
                                        },
                                        Err(e) => eprintln!("Erro ao decodificar 'e' da chave pública do peer: {}", e),
                                    }
                                }
                                Err(e) => eprintln!("Erro ao parsear resposta JSON do peer: {}", e),
                            }
                        } else {
                            let status = response.status();
                            match response.text().await {
                                Ok(text) => eprintln!("Erro ao enviar chave pública: Status HTTP {}. Resposta: {}", status, text),
                                Err(_) => eprintln!("Erro ao enviar chave pública: Status HTTP {} e erro ao ler corpo da resposta.", status),
                            }
                        }
                    }
                    Err(e) => eprintln!("Erro de rede ao trocar chaves: {}", e),
                }
            }
            "3. Enviar Mensagem Criptografada (Única)" => {
                 let (peer_public_key_clone_opt, peer_url_clone_opt, my_id_clone, keys_present) = {
                    let state_guard = app_state.lock().unwrap();
                    if state_guard.peer_public_key.is_none() || state_guard.peer_webhook_url.is_none() {
                        println!("Troque chaves com outro peer primeiro (Opção 2).");
                        (None, None, "".to_string(), false)
                    } else if state_guard.my_keys.is_none() {
                         println!("Gere suas chaves RSA primeiro (Opção 1).");
                        (None, None, "".to_string(), false)
                    } else {
                        (
                            Some(state_guard.peer_public_key.as_ref().unwrap().clone()),
                            Some(state_guard.peer_webhook_url.as_ref().unwrap().clone()),
                            state_guard.my_id.clone(),
                            true
                        )
                    }
                };

                if !keys_present {
                    continue;
                }
                
                let peer_public_key_clone = peer_public_key_clone_opt.unwrap();
                let peer_url_clone = peer_url_clone_opt.unwrap();

                let message_text = Text::new("Digite sua mensagem de texto (única):").prompt().unwrap_or_default();
                if message_text.is_empty() {
                    println!("Mensagem vazia.");
                    continue;
                }
                
                let message_bytes = message_text.as_bytes();
                let message_biguint = BigUint::from_bytes_be(message_bytes);

                println!("[DEBUG] Criptografando mensagem para {}: BigUint(len {} bytes) = {}...", my_id_clone, message_bytes.len(), message_text);
                match RSAKeys::encrypt_with_external_key(&message_biguint, &peer_public_key_clone.0, &peer_public_key_clone.1) {
                    Ok(encrypted_biguint) => {
                        let encrypted_bytes = encrypted_biguint.to_bytes_be();
                        let ciphertext_b64 = base64_encode(&encrypted_bytes);
                        println!("[DEBUG] Ciphertext B64: {}", ciphertext_b64);

                        let chat_message = EncryptedChatMessage {
                            ciphertext_b64,
                            sender_id: my_id_clone,
                        };

                        println!("[DEBUG] Enviando mensagem criptografada para {}/chat...", peer_url_clone);
                        match http_client.post(&format!("{}/chat", peer_url_clone))
                                    .json(&chat_message)
                                    .send()
                                    .await
                        {
                            Ok(response) => {
                                println!("[DEBUG] Resposta do envio de chat status: {}", response.status());
                                if response.status().is_success() {
                                    println!("✅ Mensagem enviada com sucesso!");
                                } else {
                                    let status = response.status();
                                    match response.text().await {
                                        Ok(text) => eprintln!("❌ Erro ao enviar mensagem: Status HTTP {}. Resposta: {}", status, text),
                                        Err(_) => eprintln!("❌ Erro ao enviar mensagem: Status HTTP {} e erro ao ler corpo da resposta.", status),
                                    }
                                }
                            }
                            Err(e) => eprintln!("❌ Erro de rede ao enviar mensagem: {}", e),
                        }
                    }
                    Err(e) => eprintln!("❌ Erro ao criptografar mensagem: {}", e),
                }
            }
            "4. Ver Estado Atual (Minhas Chaves/Info do Peer)" => {
                let state = app_state.lock().unwrap();
                println!("\n--- Estado da {} ---", state.my_id);
                if let Some(keys) = &state.my_keys {
                    println!("Minhas Chaves RSA Geradas:");
                    println!("  Pública (e, n): (e={}, n={})", keys.public_key.0, keys.public_key.1);
                } else {
                    println!("Nenhuma chave RSA minha foi gerada.");
                }
                if let Some(peer_key) = &state.peer_public_key {
                    println!("Chave Pública do Peer Recebida:");
                    println!("  (e, n): (e={}, n={})", peer_key.0, peer_key.1);
                } else {
                    println!("Nenhuma chave pública de peer recebida.");
                }
                if let Some(peer_url) = &state.peer_webhook_url {
                    println!("URL do Webhook do Peer: {}", peer_url);
                } else {
                    println!("URL do Webhook do Peer não definida.");
                }
                println!("---------------------------------");
            }
            "5. Entrar no Modo Chat" => {
                let app_state_clone_for_chat = Arc::clone(&app_state);
                let http_client_for_chat = http_client.clone(); 
                
                if let Err(e) = start_chat_mode(app_state_clone_for_chat, &http_client_for_chat).await {
                    eprintln!("Erro no modo chat: {}", e);
                }
            }
            "6. Sair" => {
                println!("Saindo...");
                if !server_handle.is_finished() {
                    println!("[DEBUG] A thread do servidor ainda pode estar rodando. Tentando abortar...");
                    server_handle.abort();
                }
                break;
            }
            _ => unreachable!("Opção de menu desconhecida selecionada."),
        }
        println!("\nPressione Enter para continuar...");
        io::stdout().flush()?;
        io::stdin().read_line(&mut String::new())?;
    }
    Ok(())
}
