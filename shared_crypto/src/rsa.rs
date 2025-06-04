// sistema_chat_criptografado/shared_crypto/src/rsa.rs

use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{Zero, One};
use num_integer::Integer;
use rand::RngCore; 
use rand::rngs::OsRng;
use crate::sha256::sha256_from_bytes; 

const H_LEN: usize = 32; // Comprimento da saída do SHA-256 em bytes

const SHA256_DIGEST_INFO_PREFIX: [u8; 19] = [
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
];


#[derive(Clone, Debug)]
pub struct RSAKeys {
    pub public_key: (BigUint, BigUint),  // (e, n) - Chave Pública
    pub private_key: (BigUint, BigUint), // (d, n) - Chave Privada
}

fn mgf1_sha256(mgf_seed: &[u8], mask_len: usize) -> Result<Vec<u8>, &'static str> {
    if mask_len > (1 << 32) * H_LEN { 
        return Err("Máscara solicitada muito longa para MGF1.");
    }
    let mut t = Vec::with_capacity(mask_len);
    let num_iterations = (mask_len + H_LEN - 1) / H_LEN; 

    for counter in 0..num_iterations {
        let c = (counter as u32).to_be_bytes(); 
        let mut data_to_hash = Vec::with_capacity(mgf_seed.len() + c.len());
        data_to_hash.extend_from_slice(mgf_seed);
        data_to_hash.extend_from_slice(&c);
        
        let hash_output = sha256_from_bytes(&data_to_hash); 
        t.extend_from_slice(&hash_output);
    }
    t.truncate(mask_len); 
    Ok(t)
}

fn eme_oaep_encode(message: &[u8], k: usize, p_hash: &[u8; H_LEN]) -> Result<Vec<u8>, &'static str> {
    let m_len = message.len();
    if m_len > k.saturating_sub(2 * H_LEN).saturating_sub(2) {
        return Err("Mensagem muito longa para OAEP encode.");
    }
    if k < 2 * H_LEN + 2 { 
        return Err("Comprimento da chave (k) muito pequeno para OAEP.");
    }
    let ps_len = k - m_len - 2 * H_LEN - 2;
    let ps = vec![0u8; ps_len];
    let db_len = k - H_LEN - 1;
    let mut db = Vec::with_capacity(db_len);
    db.extend_from_slice(p_hash);
    db.extend_from_slice(&ps);
    db.push(0x01);
    db.extend_from_slice(message);
    if db.len() != db_len { 
        return Err("Erro interno no cálculo do comprimento de DB no OAEP encode.");
    }
    let mut seed = [0u8; H_LEN];
    OsRng.fill_bytes(&mut seed);
    let db_mask = mgf1_sha256(&seed, db_len)?;
    let mut masked_db = Vec::with_capacity(db_len);
    for i in 0..db_len {
        masked_db.push(db[i] ^ db_mask[i]);
    }
    let seed_mask = mgf1_sha256(&masked_db, H_LEN)?;
    let mut masked_seed = [0u8; H_LEN];
    for i in 0..H_LEN {
        masked_seed[i] = seed[i] ^ seed_mask[i];
    }
    let mut em = Vec::with_capacity(k);
    em.push(0x00);
    em.extend_from_slice(&masked_seed);
    em.extend_from_slice(&masked_db);
    if em.len() != k {
         return Err("Erro interno no cálculo do comprimento de EM no OAEP encode.");
    }
    Ok(em)
}

fn eme_oaep_decode(em: &[u8], k: usize, p_hash: &[u8; H_LEN]) -> Result<Vec<u8>, &'static str> {
    if em.len() != k {
        return Err("Comprimento da mensagem codificada (EM) inválido para OAEP decode.");
    }
    if k < 2 * H_LEN + 2 {
        return Err("Erro de descriptografia OAEP (k muito pequeno)."); 
    }
    let y = em[0];
    let masked_seed = &em[1..1 + H_LEN];
    let masked_db = &em[1 + H_LEN..];
    if masked_db.len() != k - H_LEN - 1 { 
         return Err("Erro de descriptografia OAEP (comprimento maskedDB)."); 
    }
    let seed_mask = mgf1_sha256(masked_db, H_LEN)?;
    let mut seed = [0u8; H_LEN];
    for i in 0..H_LEN {
        seed[i] = masked_seed[i] ^ seed_mask[i]; 
    }
    let db_mask = mgf1_sha256(&seed, k - H_LEN - 1)?;
    let mut db = Vec::with_capacity(masked_db.len());
    for i in 0..masked_db.len() {
        db.push(masked_db[i] ^ db_mask[i]); 
    }
    let p_hash_prime_from_db = &db[0..H_LEN];
    let mut valid_padding = true;
    if y != 0x00 {
        valid_padding = false;
    }
    if p_hash_prime_from_db.iter().zip(p_hash.iter()).any(|(a,b)| a != b) {
        valid_padding = false;
    }
    let mut separator_index: Option<usize> = None;
    for i in H_LEN..db.len() {
        if db[i] == 0x01 {
            separator_index = Some(i);
            break;
        }
        if db[i] != 0x00 { 
            valid_padding = false;
        }
    }
    if separator_index.is_none() { 
        valid_padding = false;
    }
    if !valid_padding {
        return Err("Erro de descriptografia OAEP (padding inválido)."); 
    }
    let message_start_index = separator_index.unwrap() + 1;
    Ok(db[message_start_index..].to_vec())
}


impl RSAKeys {
    pub fn generate(bits: usize) -> Result<RSAKeys, &'static str> {
        if bits < 528 { 
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

    pub fn encrypt_oaep(&self, message_bytes: &[u8]) -> Result<BigUint, &'static str> {
        let (e, n) = &self.public_key; 
        let k_u64 = (n.bits() + 7) / 8; 
        let k = k_u64 as usize; // Converter k para usize
        let p_hash_array = sha256_from_bytes(b""); 
        let em = eme_oaep_encode(message_bytes, k, &p_hash_array)?;
        let em_int = BigUint::from_bytes_be(&em);
        if &em_int >= n {
            return Err("Mensagem codificada (EM) é maior ou igual ao módulo n.");
        }
        Ok(em_int.modpow(e, n)) 
    }
    
    pub fn encrypt_oaep_with_external_key(message_bytes: &[u8], peer_e: &BigUint, peer_n: &BigUint) -> Result<BigUint, &'static str> {
        let k_u64 = (peer_n.bits() + 7) / 8;
        let k = k_u64 as usize; // Converter k para usize
        let p_hash_array = sha256_from_bytes(b"");
        let em = eme_oaep_encode(message_bytes, k, &p_hash_array)?;
        let em_int = BigUint::from_bytes_be(&em);
        if &em_int >= peer_n {
             return Err("Mensagem codificada (EM) é maior ou igual ao módulo n do peer.");
        }
        Ok(em_int.modpow(peer_e, peer_n))
    }

    pub fn decrypt_oaep(&self, ciphertext_int: &BigUint) -> Result<Vec<u8>, &'static str> {
        let (d, n) = &self.private_key;
        let k_u64 = (n.bits() + 7) / 8; 
        let k = k_u64 as usize; // Converter k para usize
        if ciphertext_int >= n {
            return Err("Texto cifrado é maior ou igual ao módulo n.");
        }
        let em_int = ciphertext_int.modpow(d, n);
        let mut em_bytes = em_int.to_bytes_be();
        if em_bytes.len() < k {
            let mut padded_em_bytes = vec![0u8; k - em_bytes.len()];
            padded_em_bytes.append(&mut em_bytes);
            em_bytes = padded_em_bytes;
        } else if em_bytes.len() > k {
            return Err("Texto cifrado descriptografado (EM) tem comprimento inesperado (maior que k).");
        }
        let p_hash_array = sha256_from_bytes(b"");
        eme_oaep_decode(&em_bytes, k, &p_hash_array)
    }

    pub fn sign_pkcs1_v1_5(&self, message_bytes: &[u8]) -> Result<BigUint, &'static str> {
        let (d, n) = &self.private_key;
        let k_u64 = (n.bits() + 7) / 8; 
        let k = k_u64 as usize; // CORREÇÃO: k para usize

        let message_hash = sha256_from_bytes(message_bytes); 

        let mut t_bytes = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + H_LEN);
        t_bytes.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
        t_bytes.extend_from_slice(&message_hash);
        let t_len = t_bytes.len(); // t_len é usize

        // CORREÇÃO: Comparar e subtrair usize com usize
        if k < t_len + 11 {
            return Err("Módulo da chave muito pequeno para assinatura PKCS1-v1.5 com este hash.");
        }

        let ps_len = k - t_len - 3; // Agora k, t_len e 3 são todos usize (ou convertidos)
        let ps = vec![0xFFu8; ps_len]; // ps_len é usize

        let mut em_bytes = Vec::with_capacity(k); // k é usize
        em_bytes.push(0x00);
        em_bytes.push(0x01);
        em_bytes.extend_from_slice(&ps);
        em_bytes.push(0x00);
        em_bytes.extend_from_slice(&t_bytes);

        if em_bytes.len() != k {
            return Err("Erro interno no cálculo do comprimento de EM para assinatura.");
        }

        let em_int = BigUint::from_bytes_be(&em_bytes);
        Ok(em_int.modpow(d, n))
    }

    pub fn verify_pkcs1_v1_5_with_external_key(
        message_bytes: &[u8], 
        signature_int: &BigUint,
        sender_e: &BigUint,
        sender_n: &BigUint
    ) -> Result<bool, &'static str> {
        let k_u64 = (sender_n.bits() + 7) / 8; 
        let k = k_u64 as usize; // CORREÇÃO: k para usize

        if signature_int >= sender_n {
            return Ok(false); 
        }

        let em_prime_int = signature_int.modpow(sender_e, sender_n);
        let mut em_prime_bytes = em_prime_int.to_bytes_be();

        if em_prime_bytes.len() < k {
            let mut padded_bytes = vec![0u8; k - em_prime_bytes.len()];
            padded_bytes.append(&mut em_prime_bytes);
            em_prime_bytes = padded_bytes;
        } else if em_prime_bytes.len() > k {
             return Err("EM' recuperado com comprimento inválido durante a verificação.");
        }

        if em_prime_bytes.get(0) != Some(&0x00) || em_prime_bytes.get(1) != Some(&0x01) {
            return Ok(false); 
        }

        let mut ps_end_marker_index: Option<usize> = None;
        // CORREÇÃO: em_prime_bytes.len() já é k (usize)
        for i in 2..k { 
            if em_prime_bytes[i] == 0x00 {
                ps_end_marker_index = Some(i);
                break;
            }
            if em_prime_bytes[i] != 0xFF {
                return Ok(false); 
            }
        }

        let ps_end_marker_index = match ps_end_marker_index {
            Some(idx) => idx,
            None => return Ok(false), 
        };
        
        // ps_len = ps_end_marker_index - 2
        if ps_end_marker_index < 2 + 8 { 
             return Ok(false); 
        }

        let t_prime_from_em = &em_prime_bytes[ps_end_marker_index + 1..];

        let original_message_hash = sha256_from_bytes(message_bytes);
        let mut expected_t_bytes = Vec::with_capacity(SHA256_DIGEST_INFO_PREFIX.len() + H_LEN);
        expected_t_bytes.extend_from_slice(&SHA256_DIGEST_INFO_PREFIX);
        expected_t_bytes.extend_from_slice(&original_message_hash);
        
        if t_prime_from_em == expected_t_bytes {
            Ok(true) 
        } else {
            Ok(false) 
        }
    }

    pub fn verify_pkcs1_v1_5_with_own_key(&self, message_bytes: &[u8], signature_int: &BigUint) -> Result<bool, &'static str> {
        Self::verify_pkcs1_v1_5_with_external_key(message_bytes, signature_int, &self.public_key.0, &self.public_key.1)
    }

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

fn generate_large_prime(bits: usize, max_attempts: u32) -> Result<BigUint, &'static str> {
    if bits == 0 { return Err("Número de bits para o primo não pode ser zero."); }
    if bits == 1 { return Err("Tamanho de bit 1 não é suportado para gerar primos RSA.");}
    
    let mut rng = OsRng;
    for _ in 0..max_attempts {
        let mut candidate = rng.gen_biguint(bits as u64);
        candidate.set_bit(bits as u64 - 1, true); 
        candidate.set_bit(0, true);             
        if is_probably_prime(&candidate, 20) { 
            return Ok(candidate);
        }
    }
    Err("Não foi possível gerar um número primo no número máximo de tentativas.")
}

fn is_probably_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::one() { return false; } 
    if n == &BigUint::from(2u32) || n == &BigUint::from(3u32) { return true; }
    if n.is_even() { return false; } 

    let mut d = n - BigUint::one();
    let mut s: u32 = 0; 
    while d.is_even() {
        d /= 2u32; 
        s += 1;
    }

    let mut rng = OsRng;
    let n_minus_one = n - BigUint::one(); // Declarado aqui
    let two = BigUint::from(2u32);

    for _ in 0..k { 
        let lower_bound_a = two.clone();
        let upper_bound_a = n_minus_one.clone(); 
                                             
        if lower_bound_a >= upper_bound_a { 
            if n.bits() <=2 { continue; } 
        }
        let a = rng.gen_biguint_range(&lower_bound_a, &upper_bound_a);
        let mut x = a.modpow(&d, n); 
        
        if x == BigUint::one() || x == n_minus_one { continue; } // CORREÇÃO: n_minus_one
        
        let mut r = 0u32;
        while r < s.saturating_sub(1) { 
            x = x.modpow(&two, n); 
            if x == n_minus_one { break; } // CORREÇÃO: n_minus_one
            r += 1;
        }
        if x != n_minus_one { return false; } // CORREÇÃO: n_minus_one
    }
    true 
}

fn extended_gcd_signed(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    if a.is_zero() {
        (b.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (g, x1, y1) = extended_gcd_signed(&(b % a), a);
        (g, y1 - (b / a) * &x1, x1)
    }
}

fn modinv(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    if m.is_zero() || m.is_one() { 
        return None;
    }
    let a_signed = BigInt::from(a.clone());
    let m_signed = BigInt::from(m.clone());
    let (g, x, _) = extended_gcd_signed(&a_signed, &m_signed);
    if g != BigInt::one() {
        None
    } else {
        let result_signed = (&x % &m_signed + &m_signed) % &m_signed;
        Some(result_signed.to_biguint().expect("Falha ao converter resultado do inverso modular para BigUint, deveria ser positivo."))
    }
}
