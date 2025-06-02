// sistema_chat_criptografado/shared_crypto/src/base64.rs

const BASE64_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const PADDING: u8 = b'=';

pub fn base64_encode(data: &[u8]) -> String {
    let mut result = Vec::new();
    let mut i = 0;
    let len = data.len();

    while i < len {
        let byte1 = data[i];
        let byte2 = if i + 1 < len { data[i + 1] } else { 0 };
        let byte3 = if i + 2 < len { data[i + 2] } else { 0 };

        let index1 = byte1 >> 2;
        let index2 = ((byte1 & 0x03) << 4) | (byte2 >> 4);
        let index3 = ((byte2 & 0x0F) << 2) | (byte3 >> 6);
        let index4 = byte3 & 0x3F;

        result.push(BASE64_CHARS[index1 as usize]);
        result.push(BASE64_CHARS[index2 as usize]);
        
        if i + 1 < len {
            result.push(BASE64_CHARS[index3 as usize]);
        } else {
            result.push(PADDING);
        }
        
        if i + 2 < len {
            result.push(BASE64_CHARS[index4 as usize]);
        } else {
            result.push(PADDING);
        }
        i += 3;
    }
    String::from_utf8(result).unwrap()
}

pub fn base64_decode(encoded: &str) -> Result<Vec<u8>, String> {
    let mut result = Vec::new();
    let bytes = encoded.as_bytes();
    let len = bytes.len();
    
    if len % 4 != 0 {
        return Err("Tamanho inválido da string Base64 (deve ser múltiplo de 4).".to_string());
    }
    
    let mut i = 0;
    while i < len {
        let c1 = decode_char(bytes[i])?;
        let c2 = decode_char(bytes[i+1])?;
        
        let c3_byte = bytes[i+2];
        let c4_byte = bytes[i+3];

        let c3 = if c3_byte == PADDING { 0 } else { decode_char(c3_byte)? };
        let c4 = if c4_byte == PADDING { 0 } else { decode_char(c4_byte)? };
        
        let byte1 = (c1 << 2) | (c2 >> 4);
        result.push(byte1);
        
        if c3_byte != PADDING {
            let byte2 = ((c2 & 0x0F) << 4) | (c3 >> 2);
            result.push(byte2);
        }
        
        if c4_byte != PADDING {
            let byte3 = ((c3 & 0x03) << 6) | c4;
            result.push(byte3);
        }
        i += 4;
    }
    Ok(result)
}

fn decode_char(c: u8) -> Result<u8, String> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+'          => Ok(62),
        b'/'          => Ok(63),
        _ => Err(format!("Caractere inválido na string Base64: '{}'", c as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_basic() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
    }

    #[test]
    fn test_encode_ola_mundo_utf8() {
        let ola_mundo_bytes: &[u8] = &[
            79, 108, 195, 161, 32, 77, 117, 110, 100, 111
        ];
        assert_eq!(base64_encode(ola_mundo_bytes), "T2zDoCBNdW5kbw==");
    }
    
    #[test]
    fn test_decode_basic() {
        assert_eq!(base64_decode("").unwrap(), b"");
        assert_eq!(base64_decode("Zg==").unwrap(), b"f");
        assert_eq!(base64_decode("Zm8=").unwrap(), b"fo");
        assert_eq!(base64_decode("Zm9v").unwrap(), b"foo");
    }

    #[test]
    fn test_decode_ola_mundo_utf8() {
        let expected_ola_mundo_bytes: Vec<u8> = vec![
            79, 108, 195, 161, 32, 77, 117, 110, 100, 111
        ];
        assert_eq!(base64_decode("T2zDoCBNdW5kbw==").unwrap(), expected_ola_mundo_bytes);
        assert_eq!(String::from_utf8(base64_decode("T2zDoCBNdW5kbw==").unwrap()).unwrap(), "Olá Mundo");
    }

    // ... (outros testes mantidos da versão anterior) ...
    #[test]
    fn test_decode_invalid_char_in_decode_char() {
        assert!(decode_char(b'$').is_err());
        assert!(decode_char(PADDING).is_err());
    }
    
    #[test]
    fn test_decode_string_with_invalid_char() {
        assert!(base64_decode("Zm9vYmFy$=").is_err());
        assert!(base64_decode("Zm9=YmFy").is_err());
    }

    #[test]
    fn test_decode_invalid_length() {
        assert!(base64_decode("Zm9vY").is_err());
        assert!(base64_decode("Zg=").is_err());
    }
    
    #[test]
    fn test_encode_decode_comprehensive() {
        let test_cases_str = vec![
            "", "a", "ab", "abc", "abcd", "abcde", "abcdef", "Man", "Ma", "M",
            "The quick brown fox jumps over the lazy dog",
            "Olá, mundo! Esta é uma string de teste com acentuação e ç.",
            "1234567890-=!@#$%^&*()_+[]{};':\",./<>?",
        ];
        
        for case_str in test_cases_str {
            let case_bytes = case_str.as_bytes();
            let encoded = base64_encode(case_bytes);
            match base64_decode(&encoded) {
                Ok(decoded_bytes) => {
                    assert_eq!(decoded_bytes, case_bytes, "Falha na decodificação para o caso (string): '{}'", case_str);
                }
                Err(e) => {
                    panic!("Erro na decodificação para o caso (string) '{}': {}. Encoded: {}", case_str, e, encoded);
                }
            }
        }

        let arbitrary_bytes: &[u8] = &[0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0xFF, 0xFE, 0xFD];
        let encoded_arbitrary = base64_encode(arbitrary_bytes);
        match base64_decode(&encoded_arbitrary) {
            Ok(decoded_arbitrary_bytes) => {
                assert_eq!(decoded_arbitrary_bytes, arbitrary_bytes, "Falha na decodificação para bytes arbitrários");
            }
            Err(e) => {
                panic!("Erro na decodificação para bytes arbitrários: {}. Encoded: {}", e, encoded_arbitrary);
            }
        }
    }
}
