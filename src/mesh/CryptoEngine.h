#pragma once

// XChaCha20-Poly1305 implementation includes
#if MESHTASTIC_USE_LIBSODIUM
#include <sodium.h>
#else
// Embedded XChaCha20-Poly1305 implementation placeholder
// Include your preferred embedded crypto library here
// Examples: tiny-AES-c, micro-ecc, or custom implementation
#include "xchacha20poly1305.h" // Placeholder for embedded implementation
#endif

#include "AES.h"
#include "CTR.h"
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

class CryptoEngine
{
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
    virtual void aesSetKey(const uint8_t *key, size_t key_len);
    virtual void aesEncrypt(uint8_t *in, uint8_t *out);
    AESSmall256 *aes = NULL;
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
                                          const uint8_t *ad = nullptr, size_t ad_len = 0);

    /**
     * Decrypt data using XChaCha20-Poly1305 AEAD cipher
     * @param key 32-byte decryption key
     * @param nonce 24-byte nonce (XChaCha20 extended nonce)
     * @param ciphertext Input encrypted data (includes 16-byte tag)
     * @param ciphertext_len Length of ciphertext
     * @param plaintext Output buffer (must be at least ciphertext_len - 16 bytes)
     * @param plaintext_len Output length (will be ciphertext_len - 16)
     * @param ad Additional authenticated data (optional, can be NULL)
     * @param ad_len Length of additional data
     * @return true on success, false on failure
     */
    virtual bool decryptXChaCha20Poly1305(const uint8_t *key, const uint8_t *nonce,
                                          const uint8_t *ciphertext, size_t ciphertext_len,
                                          uint8_t *plaintext, size_t *plaintext_len,
                                          const uint8_t *ad = nullptr, size_t ad_len = 0);

    /**
     * Generate a secure random nonce for XChaCha20-Poly1305
     * @param nonce Output buffer for 24-byte nonce
     */
    virtual void generateXChaCha20Nonce(uint8_t *nonce);

    /**
     * Set the key used for encrypt, decrypt.
     *
     * As a special case: If all bytes are zero, we assume _no encryption_ and send all data in cleartext.
     *
     * @param numBytes must be 16 (AES128), 32 (AES256) or 0 (no crypt)
     * @param bytes a _static_ buffer that will remain valid for the life of this crypto instance (i.e. this class will cache the
     * provided pointer)
     */
    virtual void setKey(const CryptoKey &k);

    /**
     * Encrypt a packet
     *
     * @param bytes is updated in place
     */
    virtual void encryptPacket(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes);
    virtual void decrypt(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes);
    virtual void encryptAESCtr(CryptoKey key, uint8_t *nonce, size_t numBytes, uint8_t *bytes);

#ifndef PIO_UNIT_TESTING
  protected:
#endif
    /** Our per packet nonce */
    uint8_t nonce[16] = {0};
    CryptoKey key = {};
    CTRCommon *ctr = NULL;

    // XChaCha20-Poly1305 specific fields
    uint8_t xchacha20_key[XCHACHA20_POLY1305_KEY_SIZE] = {0};  ///< Current XChaCha20-Poly1305 key
    uint8_t xchacha20_nonce[XCHACHA20_POLY1305_NONCE_SIZE] = {0};  ///< Current XChaCha20-Poly1305 nonce
    bool xchacha20_initialized = false;  ///< Flag indicating if XChaCha20-Poly1305 is initialized

#if !(MESHTASTIC_EXCLUDE_PKI)
    uint8_t shared_key[32] = {0};
    uint8_t private_key[32] = {0};
#endif

    /**
     * Init our 128 bit nonce for a new packet
     *
     * The NONCE is constructed by concatenating (from MSB to LSB):
     * a 64 bit packet number (stored in little endian order)
     * a 32 bit sending node number (stored in little endian order)
     * a 32 bit block counter (starts at zero)
     */
    void initNonce(uint32_t fromNode, uint64_t packetId, uint32_t extraNonce = 0);

    /**
     * Initialize XChaCha20-Poly1305 extended nonce from packet information
     * @param fromNode Sender node ID
     * @param packetId Packet identifier
     * @param nonce Output buffer for 24-byte XChaCha20 nonce
     */
    void initXChaCha20Nonce(uint32_t fromNode, uint64_t packetId, uint8_t *nonce);
};

extern CryptoEngine *crypto;
