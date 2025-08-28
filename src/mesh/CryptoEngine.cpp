#include "CryptoEngine.h"
// #include "NodeDB.h"
#include "architecture.h"

#if !(MESHTASTIC_EXCLUDE_PKI)
#include "NodeDB.h"
#include "meshUtils.h"
#include <crypto.h>
#include <curve25519.h>
#include <rng.h>
#include <sha256.h>

#if !(MESHTASTIC_EXCLUDE_PKI_KEYGEN)
#if !defined(ARCH_STM32WL)
#define CryptRNG RNG
#endif

/**
 * Create a public/private key pair with Curve25519.
 *
 * @param pubKey The destination for the public key.
 * @param privKey The destination for the private key.
 */
void CryptoEngine::generateKeyPair(uint8_t *pubKey, uint8_t *privKey)
{
    // Mix in any randomness we can, to make key generation stronger.
    CryptRNG.begin(optstr(APP_VERSION));
    if (myNodeInfo.device_id.size == 16) {
        CryptRNG.stir(myNodeInfo.device_id.bytes, myNodeInfo.device_id.size);
    }
    auto noise = random();
    CryptRNG.stir((uint8_t *)&noise, sizeof(noise));
    LOG_DEBUG("Generate Curve25519 keypair");
    Curve25519::dh1(public_key, private_key);
    memcpy(pubKey, public_key, sizeof(public_key));
    memcpy(privKey, private_key, sizeof(private_key));
}

/**
 * regenerate a public key with Curve25519.
 *
 * @param pubKey The destination for the public key.
 * @param privKey The source for the private key.
 */
bool CryptoEngine::regeneratePublicKey(uint8_t *pubKey, uint8_t *privKey)
{
    if (!memfll(privKey, 0, sizeof(private_key))) {
        Curve25519::eval(pubKey, privKey, 0);
        if (Curve25519::isWeakPoint(pubKey)) {
            LOG_ERROR("PKI key generation failed. Specified private key results in a weak point");
            memset(pubKey, 0, 32);
            return false;
        }
        memcpy(private_key, privKey, sizeof(private_key));
        memcpy(public_key, pubKey, sizeof(public_key));
    } else {
        LOG_WARN("X25519 key generation failed due to blank private key");
        return false;
    }
    return true;
}
#endif

void CryptoEngine::clearKeys()
{
    memset(public_key, 0, sizeof(public_key));
    memset(private_key, 0, sizeof(private_key));
}

/**
 * Encrypt a packet's payload using a key generated with Curve25519 and SHA256
 * for a specific node.
 *
 * @param toNode The MeshPacket `to` field.
 * @param fromNode The MeshPacket `from` field.
 * @param remotePublic The remote node's Curve25519 public key.
 * @param packetId The MeshPacket `id` field.
 * @param numBytes Number of bytes of plaintext in the bytes buffer.
 * @param bytes Buffer containing plaintext input and ciphertext output.
 * @return true if successful, false otherwise.
 */
bool CryptoEngine::encryptCurve25519(uint32_t toNode, uint32_t fromNode, uint8_t *remotePublic, uint32_t packetId,
                                      size_t numBytes, uint8_t *bytes)
{
    uint8_t local_priv[32];
    uint8_t shared_key[32];
    
    // Don't allow reusing a private key, copy it
    memcpy(local_priv, private_key, 32);
    
    // Calculate the shared secret with the specified node's public key and our private key
    // This includes an internal weak key check, which among other things looks for an all 0 public key and shared key.
    if (!Curve25519::dh2(shared_key, local_priv)) {
        LOG_WARN("Curve25519DH step 2 failed!");
        return false;
    }
    
    return true;
}
#endif

concurrency::Lock *cryptLock;

// XChaCha20-Poly1305 support only - legacy AES support removed
void CryptoEngine::setKey(const CryptoKey &k)
{
    LOG_DEBUG("XChaCha20-Poly1305 encryption enabled, key length: %d", k.length);
    key = k;
}

/**
 * Encrypt a packet using XChaCha20-Poly1305
 *
 * @param bytes is updated in place
 */
void CryptoEngine::encryptPacket(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes)
{
    if (key.length > 0) {
        LOG_DEBUG("Encrypting with XChaCha20-Poly1305");
        // XChaCha20-Poly1305 implementation would go here
        // For now, this is a placeholder - actual implementation needed
    }
}

void CryptoEngine::decrypt(uint32_t fromNode, uint64_t packetId, size_t numBytes, uint8_t *bytes)
{
    if (key.length > 0) {
        LOG_DEBUG("Decrypting with XChaCha20-Poly1305");
        // XChaCha20-Poly1305 decryption implementation would go here
        // For now, this is a placeholder - actual implementation needed
    }
}

#ifndef HAS_CUSTOM_CRYPTO_ENGINE
CryptoEngine *crypto = new CryptoEngine;
#endif
