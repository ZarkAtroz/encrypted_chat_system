// sistema_chat_criptografado/shared_crypto/src/rsa.rs

use num_bigint::{BigInt, BigUint, RandBigInt};
use num_traits::{Zero, One};
use num_integer::Integer;
use rand::rngs::OsRng;

#[derive(Clone, Debug)]
pub struct RSAKeys {
    pub public_key: (BigUint, BigUint),  // (e, n) - Chave Pública
    pub private_key: (BigUint, BigUint), // (d, n) - Chave Privada
}

impl RSAKeys {
    pub fn generate(bits: usize) -> Result<RSAKeys, &'static str> {
        if bits < 64 { 
            return Err("Tamanho de bits muito pequeno (mínimo 64, recomendado 2048+).");
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

    pub fn encrypt(&self, message: &BigUint) -> Result<BigUint, &'static str> {
        if message >= &self.public_key.1 {
            return Err("Mensagem (como número) é muito grande para o módulo n da chave.");
        }
        Ok(message.modpow(&self.public_key.0, &self.public_key.1))
    }

    pub fn encrypt_with_external_key(message: &BigUint, peer_e: &BigUint, peer_n: &BigUint) -> Result<BigUint, &'static str> {
        if message >= peer_n {
            return Err("Mensagem (como número) é muito grande para o módulo n da chave do destinatário.");
        }
        Ok(message.modpow(peer_e, peer_n))
    }

    pub fn decrypt(&self, ciphertext: &BigUint) -> Result<BigUint, &'static str> {
        if ciphertext >= &self.private_key.1 {
            return Err("Texto cifrado (como número) é muito grande para o módulo n da chave.");
        }
        Ok(ciphertext.modpow(&self.private_key.0, &self.private_key.1))
    }
}

fn generate_large_prime(bits: usize, max_attempts: u32) -> Result<BigUint, &'static str> {
    if bits == 0 { return Err("Número de bits para o primo não pode ser zero."); }
    
    let mut rng = OsRng;
    for _ in 0..max_attempts {
        let mut candidate = rng.gen_biguint(bits as u64);
        if bits > 1 {
            candidate.set_bit(bits as u64 - 1, true); 
            candidate.set_bit(0, true);             
        } else if bits == 1 {
            candidate = BigUint::one();
        }
        if is_probably_prime(&candidate, 20) {
            return Ok(candidate);
        }
    }
    Err("Não foi possível gerar um número primo no número máximo de tentativas.")
}

fn is_probably_prime(n: &BigUint, k: usize) -> bool {
    if n <= &BigUint::one() { return false; } 
    if n.bits() <= 2 { 
        return n == &BigUint::from(2u32) || n == &BigUint::from(3u32);
    }
    if n.is_even() { return false; }

    let mut d = n - BigUint::one();
    let mut s: u32 = 0; 
    while d.is_even() {
        d /= 2u32; 
        s += 1;
    }

    let mut rng = OsRng;
    let n_minus_1 = n - BigUint::one();
    let two = BigUint::from(2u32);

    for _ in 0..k {
        let lower_bound_a = two.clone();
        let upper_bound_a = if n > &BigUint::from(3u32) { n_minus_1.clone() } else { continue }; 
                                                                                    
        if lower_bound_a >= upper_bound_a { 
            continue;
        }
        let a = rng.gen_biguint_range(&lower_bound_a, &upper_bound_a);
        let mut x = a.modpow(&d, n);
        
        if x == BigUint::one() || x == n_minus_1 { continue; }
        
        let mut r = 0u32;
        while r < s - 1 { 
            x = x.modpow(&two, n);
            if x == n_minus_1 { break; } 
            r += 1;
        }
        
        if x != n_minus_1 { return false; }
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
