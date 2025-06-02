// sistema_chat_criptografado/shared_crypto/src/rsa.rs

use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{Zero, One};
use num_integer::Integer;
use rand::RngCore; // Para OsRng.fill_bytes
use rand::rngs::OsRng;
use crate::sha256::sha256_from_bytes; // Importa sua função SHA-256

const H_LEN: usize = 32; // Comprimento da saída do SHA-256 em bytes (256 bits / 8)

#[derive(Clone, Debug)]
pub struct RSAKeys {
    pub public_key: (BigUint, BigUint),  // (e, n) - Chave Pública
    pub private_key: (BigUint, BigUint), // (d, n) - Chave Privada
}

// --- MGF1 (Mask Generation Function) usando SHA-256 ---
// Baseado na RFC 8017, Seção B.2.1
fn mgf1_sha256(mgf_seed: &[u8], mask_len: usize) -> Result<Vec<u8>, &'static str> {
    // hLen é H_LEN (32 bytes para SHA-256)
    if mask_len > (1 << 32) * H_LEN { // Limite teórico para mask_len (geralmente 2^32 * hLen)
        return Err("Máscara solicitada muito longa para MGF1.");
    }
    let mut t = Vec::with_capacity(mask_len);
    // num_iterations = ceil(mask_len / hLen)
    let num_iterations = (mask_len + H_LEN - 1) / H_LEN;

    for counter in 0..num_iterations {
        let c = (counter as u32).to_be_bytes(); // Representação de 4 bytes do contador
        let mut data_to_hash = Vec::with_capacity(mgf_seed.len() + c.len());
        data_to_hash.extend_from_slice(mgf_seed);
        data_to_hash.extend_from_slice(&c);
        
        let hash_output = sha256_from_bytes(&data_to_hash); // Usa sua SHA-256
        t.extend_from_slice(&hash_output);
    }
    t.truncate(mask_len); // Pega apenas os primeiros mask_len bytes
    Ok(t)
}

// --- EME-OAEP Encoding ---
// Baseado na RFC 8017, Seção 7.1.1 (EME-OAEP-Encode)
// P (parâmetros de codificação) é assumido como a string vazia.
// k é o comprimento do módulo RSA n em bytes.
fn eme_oaep_encode(message: &[u8], k: usize, p_hash: &[u8; H_LEN]) -> Result<Vec<u8>, &'static str> {
    let m_len = message.len();

    // Comprimento da mensagem M deve ser <= k - 2*hLen - 2
    if m_len > k.saturating_sub(2 * H_LEN).saturating_sub(2) {
        return Err("Mensagem muito longa para OAEP encode.");
    }
    if k < 2 * H_LEN + 2 { // Checagem de consistência
        return Err("Comprimento da chave (k) muito pequeno para OAEP.");
    }


    // PS é uma string de zeros de comprimento ps_len
    let ps_len = k - m_len - 2 * H_LEN - 2;
    let ps = vec![0u8; ps_len];

    // DB = pHash || PS || 0x01 || M
    // db_len = hLen + ps_len + 1 + m_len = k - hLen - 1
    let db_len = k - H_LEN - 1;
    let mut db = Vec::with_capacity(db_len);
    db.extend_from_slice(p_hash);
    db.extend_from_slice(&ps);
    db.push(0x01);
    db.extend_from_slice(message);

    if db.len() != db_len { // Verificação de sanidade
        return Err("Erro interno no cálculo do comprimento de DB no OAEP encode.");
    }

    let mut seed = [0u8; H_LEN];
    OsRng.fill_bytes(&mut seed); // Gera seed aleatório de hLen bytes

    let db_mask = mgf1_sha256(&seed, db_len)?; // MGF(seed, k - hLen - 1)
    
    let mut masked_db = Vec::with_capacity(db_len);
    for i in 0..db_len {
        masked_db.push(db[i] ^ db_mask[i]); // maskedDB = DB \xor dbMask
    }

    let seed_mask = mgf1_sha256(&masked_db, H_LEN)?; // MGF(maskedDB, hLen)
    
    let mut masked_seed = [0u8; H_LEN];
    for i in 0..H_LEN {
        masked_seed[i] = seed[i] ^ seed_mask[i]; // maskedSeed = seed \xor seedMask
    }

    // EM = 0x00 || maskedSeed || maskedDB
    let mut em = Vec::with_capacity(k);
    em.push(0x00); // Primeiro byte 0x00
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);
    
    if em.len() != k { // Verificação de sanidade
         return Err("Erro interno no cálculo do comprimento de EM no OAEP encode.");
    }
    Ok(em)
}

// --- EME-OAEP Decoding ---
// Baseado na RFC 8017, Seção 7.1.2 (EME-OAEP-Decode)
// k é o comprimento do módulo RSA n em bytes.
fn eme_oaep_decode(em: &[u8], k: usize, p_hash: &[u8; H_LEN]) -> Result<Vec<u8>, &'static str> {
    if em.len() != k {
        return Err("Comprimento da mensagem codificada (EM) inválido para OAEP decode.");
    }
    if k < 2 * H_LEN + 2 {
        return Err("Erro de descriptografia OAEP (k muito pequeno)."); // "Decryption error"
    }

    // 1. Separa EM: Y (1 byte), maskedSeed (hLen bytes), maskedDB (k - hLen - 1 bytes)
    let y = em[0];
    let masked_seed = &em[1..1 + H_LEN];
    let masked_db = &em[1 + H_LEN..];

    if masked_db.len() != k - H_LEN - 1 { // Verificação de sanidade
         return Err("Erro de descriptografia OAEP."); // "Decryption error"
    }

    // 2. Calcula seed e DB
    let seed_mask = mgf1_sha256(masked_db, H_LEN)?; // MGF(maskedDB, hLen)
    
    let mut seed = [0u8; H_LEN];
    for i in 0..H_LEN {
        seed[i] = masked_seed[i] ^ seed_mask[i]; // seed = maskedSeed \xor seedMask
    }

    let db_mask = mgf1_sha256(&seed, k - H_LEN - 1)?; // MGF(seed, k - hLen - 1)
    
    let mut db = Vec::with_capacity(masked_db.len());
    for i in 0..masked_db.len() {
        db.push(masked_db[i] ^ db_mask[i]); // DB = maskedDB \xor dbMask
    }

    // 3. Separa DB: pHash' (hLen bytes), PS (zeros), 0x01, M
    //    DB = pHash' || PS || 0x01 || M
    let p_hash_prime_from_db = &db[0..H_LEN];
    
    // Verificações de consistência (RFC 8017, 7.1.2, passo 3.c)
    // Para evitar ataques de timing, é recomendado que as verificações
    // não retornem imediatamente em caso de falha, mas que um erro seja sinalizado
    // e o processamento continue de forma indistinguível (em termos de tempo)
    // de um caso de sucesso, até que todas as verificações sejam feitas.
    // Aqui, por simplicidade, retornaremos erro, mas em uma implementação de produção,
    // seria melhor usar uma abordagem de tempo constante ou acumular erros.
    
    let mut valid_padding = true;

    if y != 0x00 {
        valid_padding = false;
    }
    // Comparação de pHash com pHash' (deve ser constante em tempo)
    if p_hash_prime_from_db.iter().zip(p_hash.iter()).any(|(a,b)| a != b) {
        valid_padding = false;
    }

    // Encontrar o separador 0x01 e verificar PS
    let mut separator_index: Option<usize> = None;
    for i in H_LEN..db.len() {
        if db[i] == 0x01 {
            separator_index = Some(i);
            break;
        }
        if db[i] != 0x00 { // Todos os bytes em PS (entre pHash' e 0x01) devem ser zero
            valid_padding = false;
            // Não interrompa o loop para evitar timing attack, mas o padding já é inválido.
        }
    }

    if separator_index.is_none() { // Separador 0x01 não encontrado
        valid_padding = false;
    }
    
    if !valid_padding {
        return Err("Erro de descriptografia OAEP."); // "Decryption error"
    }

    let message_start_index = separator_index.unwrap() + 1;
    Ok(db[message_start_index..].to_vec())
}


impl RSAKeys {
    pub fn generate(bits: usize) -> Result<RSAKeys, &'static str> {
        if bits < 528 { // Mínimo prático para OAEP com SHA-256 (k >= 2*32 + 2 = 66 bytes)
            // A geração de primos pode falhar antes se phi(n) < e
            // return Err("Tamanho de bits muito pequeno para OAEP com SHA-256 (mínimo 528).");
        }
        if bits % 2 != 0 {
            return Err("O tamanho de bits para o módulo n deve ser par.");
        }

        const MAX_PRIME_ATTEMPTS: u32 = 5000;

        let p = generate_large_prime(bits / 2, MAX_PRIME_ATTEMPTS)?;
        let mut q = generate_large_prime(bits / 2, MAX_PRIME_ATTEMPTS)?;
        while p == q {
            q = generate_large_prime(bits / 2, MAX_PRIME_ATTEMPTS)?;
        }

        let n = &p * &q;
        let phi = (&p - BigUint::one()) * (&q - BigUint::one());
        let e = BigUint::from(65537u32);

        if e >= phi {
            return Err("Expoente público 'e' (65537) deve ser menor que φ(n). Tente um tamanho de bits maior.");
        }
        if phi.gcd(&e) != BigUint::one() {
            return Err("Expoente público 'e' não é coprimo com φ(n).");
        }

        let d = modinv(&e, &phi).ok_or("Não foi possível calcular o inverso modular 'd'.")?;

        Ok(RSAKeys {
            public_key: (e, n.clone()),
            private_key: (d, n),
        })
    }

    // --- Criptografia RSAES-OAEP ---
    // P (parâmetros de codificação) é uma string vazia por padrão.
    pub fn encrypt_oaep(&self, message_bytes: &[u8]) -> Result<BigUint, &'static str> {
        let (e, n) = &self.public_key;
        let k = (n.bits() + 7) / 8; // Comprimento do módulo n em bytes

        let p_hash_array = sha256_from_bytes(b""); // P é a string vazia

        let em = eme_oaep_encode(message_bytes, k as usize, &p_hash_array)?;
        let em_int = BigUint::from_bytes_be(&em);
        
        // Verifica se em_int < n (o que deve ser verdade se k é o tamanho de n em bytes
        // e o primeiro byte de EM é 0x00)
        if &em_int >= n {
            return Err("Mensagem codificada (EM) é maior ou igual ao módulo n.");
        }
        Ok(em_int.modpow(e, n))
    }
    
    pub fn encrypt_oaep_with_external_key(message_bytes: &[u8], peer_e: &BigUint, peer_n: &BigUint) -> Result<BigUint, &'static str> {
        let k = (peer_n.bits() + 7) / 8;
        let p_hash_array = sha256_from_bytes(b"");

        let em = eme_oaep_encode(message_bytes, k as usize, &p_hash_array)?;
        let em_int = BigUint::from_bytes_be(&em);

        if &em_int >= peer_n {
             return Err("Mensagem codificada (EM) é maior ou igual ao módulo n do peer.");
        }
        Ok(em_int.modpow(peer_e, peer_n))
    }

    // --- Descriptografia RSAES-OAEP ---
    pub fn decrypt_oaep(&self, ciphertext_int: &BigUint) -> Result<Vec<u8>, &'static str> {
        let (d, n) = &self.private_key;
        let k = (n.bits() + 7) / 8; 

        if ciphertext_int >= n {
            // Isso não deveria acontecer se o ciphertext foi corretamente gerado com o mesmo n.
            return Err("Texto cifrado é maior ou igual ao módulo n.");
        }

        let em_int = ciphertext_int.modpow(d, n);
        let mut em_bytes = em_int.to_bytes_be();

        // Garante que em_bytes tenha comprimento k (preenchendo com zeros à esquerda)
        // Isso é crucial porque a representação BigUint->bytes pode omitir zeros à esquerda.
        if em_bytes.len() < k as usize {
            let mut padded_em_bytes = vec![0u8; k as usize - em_bytes.len()];
            padded_em_bytes.append(&mut em_bytes);
            em_bytes = padded_em_bytes;
        } else if em_bytes.len() > k as usize {
            // Isso é um erro inesperado, indica problema na conversão ou ciphertext inválido.
            return Err("Texto cifrado descriptografado (EM) tem comprimento inesperado (maior que k).");
        }
        
        let p_hash_array = sha256_from_bytes(b"");
        eme_oaep_decode(&em_bytes, k as usize, &p_hash_array)
    }

    // Seus métodos originais (sem OAEP) para referência ou uso interno se necessário:
    pub fn encrypt_raw(&self, message: &BigUint) -> Result<BigUint, &'static str> {
        if message >= &self.public_key.1 {
            return Err("Mensagem (como número) é muito grande para o módulo n da chave.");
        }
        Ok(message.modpow(&self.public_key.0, &self.public_key.1))
    }

    pub fn encrypt_raw_with_external_key(message: &BigUint, peer_e: &BigUint, peer_n: &BigUint) -> Result<BigUint, &'static str> {
        if message >= peer_n {
            return Err("Mensagem (como número) é muito grande para o módulo n da chave do destinatário.");
        }
        Ok(message.modpow(peer_e, peer_n))
    }

    pub fn decrypt_raw(&self, ciphertext: &BigUint) -> Result<BigUint, &'static str> {
        if ciphertext >= &self.private_key.1 {
            return Err("Texto cifrado (como número) é muito grande para o módulo n da chave.");
        }
        Ok(ciphertext.modpow(&self.private_key.0, &self.private_key.1))
    }
}

// Funções auxiliares (generate_large_prime, is_probably_prime, modinv)
// (Cole suas implementações existentes aqui - elas são necessárias e não mudam para OAEP)
fn generate_large_prime(bits: usize, max_attempts: u32) -> Result<BigUint, &'static str> {
    if bits == 0 { return Err("Número de bits para o primo não pode ser zero."); }
    
    let mut rng = OsRng;
    for _ in 0..max_attempts {
        let mut candidate = rng.gen_biguint(bits as u64);
        if bits > 1 {
            candidate.set_bit(bits as u64 - 1, true); 
            candidate.set_bit(0, true);             
        } else if bits == 1 { // Caso de teste, não prático para RSA
            // Para bits=1, o único primo possível é 1 se permitirmos (não usual), ou nenhum.
            // A lógica de set_bit(0,true) já o tornaria 1.
            // is_probably_prime retornará false para 1.
            // Para evitar loop infinito ou comportamento estranho com bits=1:
             if bits == 1 { return Err("Tamanho de bit 1 não é suportado para gerar primos RSA.");}
        }
        if is_probably_prime(&candidate, 20) { // k=20 iterações para Miller-Rabin
            return Ok(candidate);
        }
    }
    Err("Não foi possível gerar um número primo no número máximo de tentativas.")
}

fn is_probably_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::one() { return false; } 
    if n.bits() <= 2 { // 2 e 3 são primos
        return n == &BigUint::from(2u32) || n == &BigUint::from(3u32);
    }
    if n.is_even() { return false; } // Primos (exceto 2) são ímpares

    // Decompor n-1 em 2^s * d
    let mut d = n - BigUint::one();
    let mut s: u32 = 0; 
    while d.is_even() {
        d /= 2u32; // d >>= 1;
        s += 1;
    }

    let mut rng = OsRng;
    let n_minus_1 = n - BigUint::one(); // n-1
    let two = BigUint::from(2u32);

    for _ in 0..k { // k iterações do teste de Miller-Rabin
        // Escolher 'a' aleatoriamente em [2, n-2]
        // gen_biguint_range é [low, high)
        let lower_bound_a = two.clone();
        // upper_bound_a deve ser n-1 para que o range seja [2, n-2] (inclusive)
        // Se n for 3, n-1 é 2. O range [2,2) é vazio.
        // Se n for 2, n-1 é 1. O range [2,1) é vazio.
        // O teste original é para a em [2, n-2].
        // Se n=3, n-2 = 1. Range [2,1] não existe.
        // Se n=2, n-2 = 0. Range [2,0] não existe.
        // Os casos base n=2, n=3 já foram tratados.
        let upper_bound_a = n_minus_1.clone(); // Para gen_biguint_range, isso significa até n-2
                                             
        if lower_bound_a >= upper_bound_a { // Acontece se n for muito pequeno (ex: n=2, n=3)
             // Já tratado pelos casos base, mas para segurança:
            if n.bits() <=2 { continue; } // Ou retorne true se já passou pelos casos base.
            // Para n > 3, lower_bound_a (2) será < upper_bound_a (n-1).
        }
        let a = rng.gen_biguint_range(&lower_bound_a, &upper_bound_a);
        
        let mut x = a.modpow(&d, n); // x = a^d mod n
        
        if x == BigUint::one() || x == n_minus_1 { continue; } // Provavelmente primo, próxima iteração
        
        let mut r = 0u32;
        // Loop s-1 vezes
        while r < s.saturating_sub(1) { // Evita underflow se s=0 (não deveria acontecer aqui)
            x = x.modpow(&two, n); // x = x^2 mod n
            if x == n_minus_1 { break; } // Provavelmente primo, próxima iteração
            r += 1;
        }
        
        if x != n_minus_1 { return false; } // Composto
    }
    true // Provavelmente primo após k iterações
}

// Algoritmo Euclidiano Estendido para BigInt (para lidar com resultados negativos)
fn extended_gcd_signed(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x1, y1) = extended_gcd_signed(&(b % a), a);
        (g, y1 - (b / a) * &x1, x1)
    }
}

// Inverso modular: a^-1 mod m
fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    if m.is_zero() || m.is_one() { // Inverso não definido para módulo 0 ou 1
        return None;
    }

    // Converte para BigInt para usar o extended_gcd_signed
    let a_signed = BigInt::from(a.clone());
    let m_signed = BigInt::from(m.clone());
    let (g, x, _) = extended_gcd_signed(&a_signed, &m_signed);

    // Se gcd(a, m) não é 1, então o inverso não existe
    if g != BigInt::one() {
        None
    } else {
        // x pode ser negativo, ajusta para estar em [0, m-1]
        // (x % m + m) % m
        let result_signed = (&x % &m_signed + &m_signed) % &m_signed;
        Some(result_signed.to_biguint().expect("Falha ao converter resultado do inverso modular para BigUint, deveria ser positivo."))
    }
}
