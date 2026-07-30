# Scientific Table of Contents: Mini Vault Project Report

## 1. Front Matter
*   **Team Information:** Team name and the student IDs of the three members.
*   **Task Assignment:** Clear declaration of the specific roles and technical contributions for each group member.

## 2. System Architecture
*   **Architecture Diagram:** Visual representation detailing the system design of the Mini Vault.
*   **System Overview:** High-level summary bridging the Secure Storage (KV Engine) and the Encryption/Signing as a Service (Transit Engine).

## 3. Feature 0: Initialization and Registration
*   **Vault Initialization (0.1):** Technical explanation of the Master Passphrase implementation, including the Key Derivation Function (KDF) using Argon2id or PBKDF2, and the management of the Data Encryption Key (DEK).
*   **User Authentication (0.2):** Technical explanation of the registration and login flow, detailing password hashing using bcrypt or argon2, and the lifecycle of the session token.

## 4. Feature 1: Secure Storage (KV Engine)
*   **Encrypted-at-Rest Storage (1.1):** Technical explanation of the AES-256-GCM payload encryption, covering random nonce generation and data integrity verification via authentication tags.
*   **Ownership-Based Access Control (1.2):** Technical explanation of the prefix-based path isolation mechanism and how the system evaluates session tokens to block cross-user access attempts.

## 5. Feature 2: Transit Engine (Encryption & Signing)
*   **Named Key Management (2.1):** Technical explanation of how random AES-256 keys are generated, and how they are encrypted with the DEK before being securely written to disk.
*   **Encryption and Decryption APIs (2.2):** Technical explanation of the encrypt and decrypt request flows, including constructing self-describing ciphertexts and detecting tampered payloads.
*   **Named-Key Access Control (2.3):** Technical explanation of strict permission validation binding keys to user emails, and how unauthorized usage attempts are rejected and logged.
*   **Sign and Verify Service (2.4):** Technical explanation of asymmetric key pair generation (RSA or ED25519) and how message integrity and digital signatures are validated without exposing the private key.

## 6. Advanced Features (Optional)
*   **Extra Credit Implementation:** Technical explanations for any completed advanced features (e.g., Shamir's Secret Sharing, KV versioning, multi-factor authentication, tamper-evident audit log, etc.).

## 7. Demonstration and Testing
*   **Test Data Files:** References or inclusion of required test data, specifically an encrypted KV data file and a sample ciphertext from the Transit engine.
*   **Demo Screenshots:** Visual evidence of the system operating successfully, including unlocking, write/read operations, denied access cases, and the rejection of tampered messages.