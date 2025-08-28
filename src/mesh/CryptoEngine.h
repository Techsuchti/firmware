#pragma once
// XChaCha20-Poly1305 implementation includes
#if MESHTASTIC_USE_LIBSODIUM
#include <sodium.h>
#else
// Embedded XChaCha20-Poly1305 implementation placeholder
// Include your preferred embedded crypto library here
// Examples: tiny-AES-c, micro-ecc, or custom implementation
#include "xchacha20poly1305.h"
// Placeholder for embedded implementation
#endif

#include "concurrency/LockGuard.h"
#include "configuration.h"
#include "mesh-pb-constants.h"
#include <arduino.h>

extern concurrency::Lock *cryptLock;

struct CryptoKey {
    uint8_t bytes[32];
    /// # of bytes, or -1 to mean "invalid key - do not use"
    int8_t length;
};

/**
 * see docs/software/crypto.md for details.
 *
 */
#define MAX_BLOCKSIZE 256
#define TEST_CURVE25519_FIELD_OPS // Exposes Curve25519::isWeakPoint() for testing keys

// XChaCha20-Poly1305 constants
#define XCHACHA20_POLY1305_KEY_SIZE 32
#define XCHACHA20_POLY1305_NONCE_SIZE 24
#define XCHACHA20_POLY1305_TAG_SIZE 16

class CryptoEngine {
  public:
#if !(MESHTASTIC_EXCLUDE_PKI)
    uint8_t public_key[32] = {0};
#endif
    
    virtual ~CryptoEngine() {}
    
#if !(MESHTASTIC_EXCLUDE_PKI)
#if !(MESHTASTIC_EXCLUDE_PKI_KEYGEN)
    virtual void generateKeyPair(uint8_t *pubKey, uint8_t *privKey);
    virtual bool regeneratePublicKey(uint8_t *pubKey, uint8_t *privKey);
#endif
    void clearKeys();
    void setDHPrivateKey(uint8_t *_private_key);
    
    virtual bool encryptCurve25519(uint32_t toNode, uint32_t fromNode, meshtastic_UserLite_public_key_t remotePublic,
                                   uint64_t packetNum, size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut);
    virtual bool decryptCurve25519(uint32_t fromNode, meshtastic_UserLite_public_key_t remotePublic, uint64_t packetNum,
                                   size_t numBytes, const uint8_t *bytes, uint8_t *bytesOut);
    virtual bool setDHPublicKey(uint8_t *publicKey);
    virtual void hash(uint8_t *bytes, size_t numBytes);
#endif
    
    // XChaCha20-Poly1305 encryption/decryption methods
    /**
     * Encrypt data using XChaCha20-Poly1305 AEAD cipher
     * @param key 32-byte encryption key
     * @param nonce 24-byte nonce (XChaCha20 extended nonce)
     * @param plaintext Input data to encrypt
     * @param plaintext_len Length of plaintext
     * @param ciphertext Output buffer (must be at least plaintext_len + 16 bytes for tag)
     * @param ciphertext_len Output length (will be plaintext_len + 16)
     * @param ad Additional authenticated data (optional, can be NULL)
     * @param ad_len Length of additional data
     * @return true on success, false on failure
     */
    virtual bool encryptXChaCha20Poly1305(const uint8_t *key, const uint8_t *nonce,
                                          const uint8_t *plaintext, size_t plaintext_len,
                                          uint8_t *ciphertext, size_t *ciphertext_len,
                                          const uint8_t *ad, size_t ad_len);
    
    /**
     * Decrypt data using XChaCha20-Poly1305 AEAD cipher
     * @param key 32-byte decryption key
     * @param nonce 24-byte nonce (XChaCha20 extended nonce)
     * @param ciphertext Input encrypted data (including 16-byte tag)
     * @param ciphertext_len Length of ciphertext (including tag)
     * @param plaintext Output buffer for decrypted data
     * @param plaintext_len Output length (will be ciphertext_len - 16)
     * @param ad Additional authenticated data (must match encryption, can be NULL)
     * @param ad_len Length of additional data
     * @return true on success, false on failure
     */
    virtual bool decryptXChaCha20Poly1305(const uint8_t *key, const uint8_t *nonce,
                                          const uint8_t *ciphertext, size_t ciphertext_len,
                                          uint8_t *plaintext, size_t *plaintext_len,
                                          const uint8_t *ad, size_t ad_len);
    
  protected:
    uint8_t private_key[32] = {0};
};

extern CryptoEngine *crypto;
