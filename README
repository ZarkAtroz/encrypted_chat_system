# Sistema de Chat Criptografado Ponto a Ponto em Rust

Este projeto implementa um sistema de chat ponto a ponto (P2P) em Rust, onde dois usuários podem trocar mensagens criptografadas e assinadas digitalmente. As primitivas criptográficas RSA (com padding OAEP para criptografia e PKCS#1 v1.5 para assinaturas), SHA-256 e Base64 foram implementadas manualmente como parte da biblioteca `shared_crypto`.

## Funcionalidades Principais

* **Geração de Pares de Chaves RSA:** Cada aplicação de chat pode gerar seu próprio par de chaves pública/privada RSA.
* **Troca de Chaves Públicas:** Os usuários podem trocar suas chaves públicas através de um mecanismo de webhook HTTP.
* **Criptografia de Mensagens:** As mensagens são criptografadas usando RSA com o esquema de padding OAEP (Optimal Asymmetric Encryption Padding) e a chave pública do destinatário, garantindo a **confidencialidade**.
* **Assinaturas Digitais:** As mensagens originais (antes da criptografia) são assinadas digitalmente usando RSA com o esquema de padding RSASSA-PKCS1-v1_5 e a chave privada do remetente. Isso garante a **autenticidade** (quem enviou) e a **integridade** (que a mensagem não foi alterada) dos dados.
* **Comunicação via HTTP:** As aplicações utilizam o framework Axum para criar servidores HTTP que recebem mensagens e chaves, e a crate Reqwest para enviar essas informações.
* **Interface de Linha de Comando (CLI):** Uma interface interativa (usando a crate `inquire`) permite aos usuários gerenciar chaves, trocar chaves e conversar.
* **Codificação Base64:** Os dados binários (texto cifrado, assinaturas) são codificados em Base64 para transmissão segura em payloads JSON.
* **Hashing SHA-256:** Usado como parte dos esquemas de padding OAEP e de assinatura.

## Estrutura do Projeto

O projeto é organizado como um workspace Cargo com os seguintes membros:

* `app_um/`: Contém o código para a primeira aplicação de chat (`App_Um`).
* `app_dois/`: Contém o código para a segunda aplicação de chat (`App_Dois`).
* `shared_crypto/`: Uma biblioteca compartilhada que contém as implementações manuais das funcionalidades criptográficas:
    * `rsa.rs`: Implementação de RSA (geração de chaves, exponenciação modular), padding OAEP para criptografia, e padding PKCS#1 v1.5 para assinaturas.
    * `sha256.rs`: Implementação do algoritmo de hash SHA-256.
    * `base64.rs`: Implementação de codificação e decodificação Base64.
    * `models.rs`: Define as estruturas de dados para as mensagens trocadas (ex: `PublicKeyExchangeMessage`, `EncryptedChatMessage`).

## Conceitos Criptográficos Implementados

* **RSA (Rivest-Shamir-Adleman):**
    * Geração de chaves (p, q, n, e, d).
    * Criptografia: $c = m^e \pmod n$
    * Descriptografia: $m = c^d \pmod n$
* **RSAES-OAEP (Optimal Asymmetric Encryption Padding):**
    * Esquema de padding para criptografia RSA que adiciona aleatoriedade e previne ataques comuns ao RSA "livro-texto".
    * Utiliza uma função de hash (SHA-256) e uma Mask Generation Function (MGF1).
* **RSASSA-PKCS1-v1_5 (RSA Signature Scheme with Appendix - PKCS#1 v1.5):**
    * Esquema de padding para assinaturas digitais RSA.
    * Envolve a criação de uma estrutura `DigestInfo` (contendo um OID para SHA-256 e o hash da mensagem) que é então padronizada e processada com a chave privada.
* **SHA-256:**
    * Função de hash criptográfica que produz um resumo de 256 bits (32 bytes) de uma mensagem. Usada no OAEP e nas assinaturas.
* **Base64:**
    * Esquema de codificação para representar dados binários em formato de texto ASCII, seguro para transmissão em JSON/HTTP.

## Como Compilar e Executar

### Pré-requisitos

* Rust e Cargo instalados (visite [rustup.rs](https://rustup.rs/)).

### Compilando o Projeto

1.  Clone o repositório (se aplicável) ou navegue até o diretório raiz do projeto `sistema_chat_criptografado`.
2.  Execute o comando de build do Cargo:
    ```bash
    cargo build
    ```
    Isso compilará todas as crates no workspace.

### Executando as Aplicações

Você precisará de dois terminais separados para rodar `App_Um` e `App_Dois` simultaneamente.

**Terminal 1: Executando `App_Um` (Porta Padrão: 8080)**

1.  Navegue até o diretório de `App_Um`:
    ```bash
    cd app_um
    ```
2.  Execute a aplicação:
    ```bash
    cargo run
    ```

**Terminal 2: Executando `App_Dois` (Porta Padrão: 8081)**

1.  Navegue até o diretório de `App_Dois`:
    ```bash
    cd app_dois 
    ```
    (Se você estiver na raiz do projeto, seria `cd ../app_dois` se acabou de sair de `app_um`, ou `cd app_dois` da raiz).
2.  Execute a aplicação:
    ```bash
    cargo run
    ```

### Fluxo de Uso Básico

1.  **Gerar Chaves (Opção 1):**
    * Em AMBAS as aplicações (`App_Um` e `App_Dois`), selecione a opção 1 para gerar seus respectivos pares de chaves RSA.
    * Recomenda-se usar 1024 bits ou mais (o mínimo para OAEP/SHA-256 funcionar com esta implementação é 528 bits).

2.  **Trocar Chaves Públicas (Opção 2):**
    * No `App_Um`, escolha a opção 2. Quando solicitado pela URL do peer, digite a URL do `App_Dois` (ex: `http://localhost:8081`).
    * No `App_Dois`, escolha a opção 2. Quando solicitado pela URL do peer, digite a URL do `App_Um` (ex: `http://localhost:8080`).
    * Ambas as aplicações devem confirmar o recebimento da chave pública uma da outra.

3.  **Conversar (Opção 5 - Modo Chat ou Opção 3 - Mensagem Única):**
    * Após a troca de chaves bem-sucedida, você pode usar a opção 5 para entrar no modo chat interativo ou a opção 3 para enviar mensagens individuais.
    * As mensagens serão criptografadas com a chave pública do destinatário e assinadas com a chave privada do remetente. O destinatário descriptografará a mensagem e verificará a assinatura.

## Detalhes Técnicos

* **Networking:**
    * O framework [Axum](https://github.com/tokio-rs/axum) é usado para construir os servidores HTTP em cada aplicação, lidando com os endpoints `/key-exchange` e `/chat`.
    * A crate [Reqwest](https://crates.io/crates/reqwest) é usada como cliente HTTP para enviar as requisições POST para os peers.
* **Interface de Linha de Comando (CLI):**
    * A crate [inquire](https://crates.io/crates/inquire) é utilizada para criar uma CLI interativa e amigável.
* **Serialização/Deserialização:**
    * A crate [Serde](https://crates.io/crates/serde) (com `serde_json`) é usada para serializar e deserializar os payloads das mensagens (JSON) trocadas via HTTP.

## Considerações de Segurança e Limitações

Este projeto foi desenvolvido com foco no aprendizado e na implementação manual de conceitos criptográficos. Para um sistema de produção seguro, as seguintes considerações são cruciais:

1.  **Implementações Manuais de Criptografia:** Implementar algoritmos criptográficos e esquemas de padding do zero é propenso a erros sutis que podem levar a vulnerabilidades. Para produção, é **fortemente recomendado** usar bibliotecas criptográficas padrão, bem testadas e auditadas pela comunidade (ex: as crates do grupo RustCrypto como `rsa`, `sha2`, `oaep`, `pkcs1`, `rand`).
2.  **Segurança da Troca de Chaves:** O mecanismo atual de troca de chaves (digitar URLs) é básico e vulnerável a ataques "man-in-the-middle" (MITM). Em um sistema real, seria necessário um método mais seguro para autenticar os peers e verificar a autenticidade das chaves públicas trocadas (ex: certificados digitais, fingerprints de chaves verificados fora da banda).
3.  **Perfect Forward Secrecy (PFS):** O esquema atual não oferece PFS. Se uma chave privada de longo prazo for comprometida, todas as mensagens passadas criptografadas com a chave pública correspondente podem ser descriptografadas. Sistemas modernos usam chaves de sessão efêmeras (ex: via Diffie-Hellman) para fornecer PFS.
4.  **Gerenciamento de Chaves:** Não há um sistema robusto para armazenamento seguro de chaves privadas, rotação de chaves ou revogação de chaves.
5.  **Proteção contra Replay Attacks:** Não há mecanismos explícitos para prevenir que um adversário capture uma mensagem criptografada e a reenvie posteriormente. Nonces ou timestamps poderiam ser adicionados.
6.  **Análise de Tempo Constante:** As implementações manuais de criptografia podem não ser de tempo constante, potencialmente vazando informações através de ataques de canal lateral baseados em timing. Bibliotecas padrão geralmente levam isso em consideração.
7.  **Tamanho da Chave:** Embora o sistema suporte diferentes tamanhos de chave, chaves RSA menores que 2048 bits não são recomendadas para segurança a longo prazo. A implementação atual requer um mínimo de 528 bits para OAEP/SHA-256 e assinatura PKCS#1v1.5/SHA-256 funcionarem corretamente.

## Possíveis Melhorias Futuras

* Substituir as implementações criptográficas manuais por crates padrão do RustCrypto.
* Implementar um protocolo de acordo de chave mais seguro (ex: Signal Protocol, ou uma variação de Diffie-Hellman autenticado).
* Adicionar Perfect Forward Secrecy usando chaves de sessão.
* Melhorar a interface do usuário (GUI em vez de CLI).
* Implementar armazenamento persistente de chaves e contatos.
* Adicionar suporte para conversas em grupo.

---

Este projeto serve como uma excelente ferramenta educacional para entender os fundamentos da criptografia de chave pública, padding e assinaturas digitais em um contexto prático.
