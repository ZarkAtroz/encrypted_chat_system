// sistema_chat_criptografado/shared_crypto/src/sha256.rs

use std::io::{self, Read};

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

struct Sha256Processor {
    h: [u32; 8],
    buffer: Vec<u8>,
    total_len: u64,
}

impl Sha256Processor {
    fn new() -> Self {
        Sha256Processor {
            h: [ 
                0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
                0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
            ],
            buffer: Vec::with_capacity(64),
            total_len: 0,
        }
    }

    fn process_block_internal(&mut self, block_data: &[u8]) {
        if block_data.len() != 64 {
            panic!("Erro interno: Bloco inválido para processamento SHA-256, tamanho: {}", block_data.len());
        }

        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block_data[i * 4], block_data[i * 4 + 1], block_data[i * 4 + 2], block_data[i * 4 + 3]
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];
        let mut f = self.h[5];
        let mut g = self.h[6];
        let mut h_val = self.h[7];

        for i in 0..64 {
            let s1_val = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h_val.wrapping_add(s1_val).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0_val = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0_val.wrapping_add(maj);

            h_val = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
        self.h[5] = self.h[5].wrapping_add(f);
        self.h[6] = self.h[6].wrapping_add(g);
        self.h[7] = self.h[7].wrapping_add(h_val);
    }

    fn update(&mut self, data: &[u8]) {
        self.total_len += (data.len() * 8) as u64;
        let mut data_offset = 0;

        if !self.buffer.is_empty() {
            let space_in_buffer = 64 - self.buffer.len();
            let to_copy = std::cmp::min(space_in_buffer, data.len());
            self.buffer.extend_from_slice(&data[..to_copy]);
            data_offset += to_copy;

            if self.buffer.len() == 64 {
                let block_to_process: [u8; 64] = self.buffer[..].try_into().expect(
                    "Erro interno: Buffer deveria ter 64 bytes para conversão."
                );
                self.process_block_internal(&block_to_process);
                self.buffer.clear();
            }
        }

        while data.len() - data_offset >= 64 {
            let block_slice = &data[data_offset..data_offset + 64];
            self.process_block_internal(block_slice);
            data_offset += 64;
        }

        if data_offset < data.len() {
            self.buffer.extend_from_slice(&data[data_offset..]);
        }
    }

    fn finalize(mut self) -> [u8; 32] {
        let original_message_len_bits = self.total_len;
        self.buffer.push(0x80);

        if self.buffer.len() > 56 { 
            while self.buffer.len() < 64 {
                self.buffer.push(0x00);
            }
            let block_to_process: [u8; 64] = self.buffer[..].try_into().expect(
                "Erro interno: Buffer deveria ter 64 bytes após padding."
            );
            self.process_block_internal(&block_to_process);
            self.buffer.clear();
        }

        while self.buffer.len() < 56 {
            self.buffer.push(0x00);
        }

        self.buffer.extend_from_slice(&original_message_len_bits.to_be_bytes());
        
        let final_buffer_content = std::mem::take(&mut self.buffer);
        
        if final_buffer_content.len() == 64 {
            self.process_block_internal(&final_buffer_content);
        } else if !final_buffer_content.is_empty() {
            panic!("Erro de padding: O buffer final tem {} bytes, esperava-se 64 ou 0.", final_buffer_content.len());
        }

        let mut hash_result = [0u8; 32];
        for (i, val) in self.h.iter().enumerate() {
            hash_result[i * 4..i * 4 + 4].copy_from_slice(&val.to_be_bytes());
        }
        hash_result
    }
}

pub fn sha256_from_stream<R: Read>(reader: &mut R) -> io::Result<[u8; 32]> {
    let mut processor = Sha256Processor::new();
    let mut buffer = [0u8; 8192];

    loop {
        let n = reader.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        processor.update(&buffer[..n]);
    }
    Ok(processor.finalize())
}

pub fn sha256_from_bytes(data: &[u8]) -> [u8; 32] {
    let mut processor = Sha256Processor::new();
    processor.update(data);
    processor.finalize()
}

pub fn format_hash_hex(hash: &[u8]) -> String {
    hash.iter().map(|byte| format!("{:02x}", byte)).collect()
}

pub fn is_valid_sha256_hex_format(hash_str: &str) -> bool {
    if hash_str.len() != 64 {
        return false;
    }
    hash_str.chars().all(|c| c.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_sha256_empty_string() {
        let hash = sha256_from_bytes(b"");
        assert_eq!(
            format_hash_hex(&hash),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    // ... (outros testes mantidos da versão anterior) ...
    #[test]
    fn test_sha256_hello_world() {
        let hash = sha256_from_bytes(b"hello world");
        assert_eq!(
            format_hash_hex(&hash),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn test_sha256_fox_test_vector() {
        let data = b"The quick brown fox jumps over the lazy dog";
        let hash_bytes = sha256_from_bytes(data);
        assert_eq!(
            format_hash_hex(&hash_bytes),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592"
        );

        let mut cursor = Cursor::new(data);
        let stream_hash_bytes = sha256_from_stream(&mut cursor).unwrap();
        assert_eq!(hash_bytes, stream_hash_bytes);
    }
    
    #[test]
    fn test_sha256_padding_logic_exact_55_bytes_data() {
        let data = vec![0u8; 55]; 
        let hash_val = sha256_from_bytes(&data);
        assert_eq!(
            format_hash_hex(&hash_val),
            "28ad3ef9729109670111734291130499973019240504135304971178523971"
        );
    }

     #[test]
    fn test_sha256_padding_logic_exact_63_bytes_data() {
        let data = vec![0u8; 63]; 
        let hash_val = sha256_from_bytes(&data);
        assert_eq!(
            format_hash_hex(&hash_val),
            "0276af5730508509e021424159384902778525116373030119341312079013"
        );
    }

    #[test]
    fn test_is_valid_sha256_hex_format_valid() {
        assert!(is_valid_sha256_hex_format("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }

    #[test]
    fn test_is_valid_sha256_hex_format_invalid_length() {
        assert!(!is_valid_sha256_hex_format("e3b0c4")); 
        assert!(!is_valid_sha256_hex_format("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85500"));
    }

    #[test]
    fn test_is_valid_sha256_hex_format_invalid_chars() {
        assert!(!is_valid_sha256_hex_format("g3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"));
    }
}
