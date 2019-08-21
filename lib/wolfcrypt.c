/*
 * Copyright (c) 2016 DeNA Co., Ltd., Kazuho Oku
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#ifndef _XOPEN_SOURCE
#define _XOPEN_SOURCE 700 /* required for glibc to use getaddrinfo, etc. */
#endif
#include <errno.h>

#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "user_settings.h"
#include "picotls.h"
#include "picotls/wolfcrypt.h"

void ptls_wolfcrypt_random_bytes(void *buf, size_t len)
{
    return;
}

#if defined(USE_WOLFSSL_KX)

struct st_wolf_secp256r1_key_exchange_t {
    ptls_key_exchange_context_t super;
    ecc_key* privkey;
};

static int wc_secp256r1_on_exchange(ptls_key_exchange_context_t **_ctx, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_wolf_secp256r1_key_exchange_t *ctx = (struct st_wolf_secp256r1_key_exchange_t *)*_ctx;
    int ret;
    ecc_key* peerECCKey = NULL;
    word32 secretLen = SECP256R1_SHARED_SECRET_SIZE;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if (peerkey.len != SECP256R1_PUBLIC_KEY_SIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }

    if ((secret->base = (uint8_t *)XMALLOC(SECP256R1_SHARED_SECRET_SIZE, NULL, NULL)) == NULL){
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    peerECCKey = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, NULL);
    if (peerECCKey == NULL) {
        WOLFSSL_MSG("PeerEccKey Memory error");
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    ret = wc_ecc_init(peerECCKey);
    if (ret != 0) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;    
    }

    /* Point is validated by import function. */
    if (wc_ecc_import_x963(peerkey.base, peerkey.len, peerECCKey) != 0) {
        ret = ECC_PEERKEY_ERROR;
        goto Exit;
    }

    ret = wc_ecc_shared_secret(ctx->privkey, peerECCKey, secret->base, &secretLen);
    secret->len = (size_t)secretLen;

Exit:
    if (peerECCKey != NULL){
        wc_ecc_free(peerECCKey);
        XFREE(peerECCKey, NULL, NULL);
        peerECCKey = NULL;
    }

    if (release) {
        wc_ecc_free(ctx->privkey);
        if (ctx->privkey != NULL){
            XFREE(ctx->privkey, NULL, NULL);
            ctx->privkey = NULL;
        }
        XFREE(ctx->super.pubkey.base, NULL, NULL);
        ctx->super.pubkey.base = NULL;
        XFREE(ctx, NULL, NULL);
        *_ctx = NULL;
    }
    return ret;
}

static int wc_secp256r1_create_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx)
{
    struct st_wolf_secp256r1_key_exchange_t *ctx;
    byte*  keyData = NULL;
    word32 dataSize = SECP256R1_PUBLIC_KEY_SIZE;
    ecc_key* key;
    WC_RNG rng;
    wc_InitRng(&rng);
    int ret = 0;

    if ((ctx = (struct st_wolf_secp256r1_key_exchange_t *)XMALLOC(sizeof(*ctx), NULL, NULL)) == NULL){
        return PTLS_ERROR_NO_MEMORY;
    }
    ctx->super = (ptls_key_exchange_context_t){algo, {NULL}, wc_secp256r1_on_exchange};

    key = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, NULL);
    if (key == NULL) {
        WOLFSSL_MSG("EccTempKey Memory error");
        return PTLS_ERROR_NO_MEMORY;
    }

    /* Make an Private key. */
    if(wc_ecc_init(key) != 0){
        ret = ECC_EXPORT_ERROR;
        goto Exit;
    }
    ret = wc_ecc_make_key(&rng, SECP256R1_PRIVATE_KEY_SIZE, key);
    if (ret != 0) {
        goto Exit;
    }

    /* Allocate space for the public key. */
    keyData = (byte*)XMALLOC(SECP256R1_PUBLIC_KEY_SIZE, NULL, NULL);
    if (keyData == NULL) {
        WOLFSSL_MSG("Key data Memory error");
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    if (wc_ecc_export_x963(key, keyData, &dataSize) != 0) {
        ret = ECC_EXPORT_ERROR;
        goto Exit;
    }

    ctx->privkey = key;
    ctx->super.pubkey.base = keyData;
    ctx->super.pubkey.len = (size_t)dataSize;

Exit:
    wc_FreeRng(&rng);
    if(ret == 0){
        *_ctx = &ctx->super;
    } else {
       if(keyData != NULL){
            XFREE(keyData, NULL, NULL);
            keyData = NULL;
        }
        wc_ecc_free(key);
        if (key != NULL){
            XFREE(key, NULL, NULL);
            key = NULL;
        }
        XFREE(ctx, NULL, NULL);
        *_ctx = NULL;
    }
    return ret;
}

static int wc_secp256r1_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                               ptls_iovec_t peerkey)
{
    ecc_key* privKey = NULL;
    ecc_key* peerECCKey = NULL;
    word32 pubLen = SECP256R1_PUBLIC_KEY_SIZE;
    word32 secretLen = SECP256R1_SHARED_SECRET_SIZE;
    WC_RNG rng;
    wc_InitRng(&rng);
    int ret;

    *pubkey = (ptls_iovec_t){NULL};
    *secret = (ptls_iovec_t){NULL};

    if (peerkey.len != SECP256R1_PUBLIC_KEY_SIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }

    /* inport peerkey */
    peerECCKey = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, NULL);
    if (peerECCKey == NULL) {
        WOLFSSL_MSG("PeerEccKey Memory error");
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    ret = wc_ecc_init(peerECCKey);
    if (ret != 0) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;    
    }

    /* Point is validated by import function. */
    if (wc_ecc_import_x963_ex(peerkey.base, peerkey.len, peerECCKey, ECC_SECP256R1) != 0) {
        ret = ECC_PEERKEY_ERROR;
        goto Exit;
    }

    /* crease private key */
    privKey = (ecc_key*)XMALLOC(sizeof(ecc_key), NULL, NULL);
    if (privKey == NULL) {
        WOLFSSL_MSG("EccTempKey Memory error");
        return PTLS_ERROR_NO_MEMORY;
    }
    if(wc_ecc_init(privKey) != 0){
        ret = ECC_EXPORT_ERROR;
        goto Exit;
    }
    ret = wc_ecc_make_key(&rng, SECP256R1_PRIVATE_KEY_SIZE, privKey);
    if (ret != 0) {
        goto Exit;
    }

    /* export publickey from privatekey */
    if ((pubkey->base = (uint8_t *)XMALLOC(SECP256R1_PUBLIC_KEY_SIZE, NULL, NULL)) == NULL){
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (wc_ecc_export_x963(privKey, pubkey->base, &pubLen) != 0) {
        ret = ECC_EXPORT_ERROR;
        goto Exit;
    }
    pubkey->len = (size_t)pubLen;

    /* calculate secrets*/
    if ((secret->base = (uint8_t *)XMALLOC(SECP256R1_SHARED_SECRET_SIZE, NULL, NULL)) == NULL){
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    ret = wc_ecc_shared_secret(privKey, peerECCKey, secret->base, &secretLen);
    secret->len = (size_t)secretLen;

Exit:
    wc_FreeRng(&rng);
    wc_ecc_free(privKey);
    if (privKey != NULL){
        XFREE(privKey, NULL, NULL);
        privKey = NULL;
    }
    wc_ecc_free(peerECCKey);
    if (peerECCKey != NULL){
        XFREE(peerECCKey, NULL, NULL);
        peerECCKey = NULL;
    }
    if (ret != 0){
        XFREE(pubkey->base, NULL, NULL);
        *pubkey = (ptls_iovec_t){NULL};
        XFREE(secret->base, NULL, NULL);
        *secret = (ptls_iovec_t){NULL};
    }
    return ret;
}

struct st_wolf_x25519_key_exchange_t {
    ptls_key_exchange_context_t super;
    curve25519_key* privkey;
};

static int wc_x25519_on_exchange(ptls_key_exchange_context_t **_ctx, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_wolf_x25519_key_exchange_t *ctx = (struct st_wolf_x25519_key_exchange_t *)*_ctx;
    int ret;
    curve25519_key* peerX25519Key = NULL;
    word32 secretLen = CURVE25519_KEYSIZE;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if (peerkey.len != CURVE25519_KEYSIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }

    if ((secret->base = XMALLOC(CURVE25519_KEYSIZE, NULL, NULL)) == NULL){
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    peerX25519Key = (curve25519_key*)XMALLOC(sizeof(curve25519_key), NULL, NULL);
    if (peerX25519Key == NULL) {
        WOLFSSL_MSG("PeerEccKey Memory error");
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    ret = wc_curve25519_init(peerX25519Key);
    if (ret != 0) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;    
    }

    /* Point is validated by import function. */
    if (wc_curve25519_import_public_ex(peerkey.base, peerkey.len, peerX25519Key, EC25519_LITTLE_ENDIAN) != 0) {
        ret = ECC_PEERKEY_ERROR;
        goto Exit;
    }

    ret = wc_curve25519_shared_secret_ex(ctx->privkey, peerX25519Key, secret->base, &secretLen, EC25519_LITTLE_ENDIAN);
    secret->len = (size_t)secretLen;

Exit:
    if (peerX25519Key != NULL){
        wc_curve25519_free(peerX25519Key);
        XFREE(peerX25519Key, NULL, NULL);
    }

    if (release) {
        wc_curve25519_free(ctx->privkey);
        if (ctx->privkey != NULL){
            XFREE(ctx->privkey, NULL, NULL);
            ctx->privkey = NULL;
        }
        XFREE(ctx->super.pubkey.base, NULL, NULL);
        XFREE(ctx, NULL, NULL);
        *_ctx = NULL;
    }
    return ret;
}

static int wc_x25519_create_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx)
{
    struct st_wolf_x25519_key_exchange_t *ctx;
    byte*  keyData = NULL;
    word32 dataSize = CURVE25519_KEYSIZE;
    curve25519_key* key;
    WC_RNG rng;
    wc_InitRng(&rng);
    int ret = 0;

    if ((ctx = (struct st_wolf_x25519_key_exchange_t *)XMALLOC(sizeof(*ctx), NULL, NULL)) == NULL){
        return PTLS_ERROR_NO_MEMORY;
    }
    ctx->super = (ptls_key_exchange_context_t){algo, {NULL}, wc_x25519_on_exchange};

    key = (curve25519_key*)XMALLOC(sizeof(curve25519_key), NULL, NULL);
    if (key == NULL) {
        WOLFSSL_MSG("EccTempKey Memory error");
        return PTLS_ERROR_NO_MEMORY;
    }

    /* Make an Private key. */
    if(wc_curve25519_init(key) != 0){
        ret = ECC_EXPORT_ERROR;
        goto Exit;
    }
    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, key);
    if (ret != 0) {
        goto Exit;
    }

    /* Allocate space for the public key. */
    keyData = (byte*)XMALLOC(CURVE25519_KEYSIZE, NULL, NULL);
    if (keyData == NULL) {
        WOLFSSL_MSG("Key data Memory error");
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    if (wc_curve25519_export_public_ex(key, keyData, &dataSize, EC25519_LITTLE_ENDIAN) != 0) {
        ret = ECC_EXPORT_ERROR;
        goto Exit;
    }

    ctx->privkey = key;
    ctx->super.pubkey.base = keyData;
    ctx->super.pubkey.len = (size_t)dataSize;

Exit:
    wc_FreeRng(&rng);
    if(ret == 0){
        *_ctx = &ctx->super;
    } else {
       if(keyData != NULL){
            XFREE(keyData, NULL, NULL);
        }
        wc_curve25519_free(key);
        if (key != NULL){
            XFREE(key, NULL, NULL);
            key = NULL;
        }
        XFREE(ctx, NULL, NULL);
        *_ctx = NULL;
    }
    return ret;
}

static int wc_x25519_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                               ptls_iovec_t peerkey)
{
    curve25519_key* privKey = NULL;
    curve25519_key* peerX25519Key = NULL;
    word32 pubLen = CURVE25519_KEYSIZE;
    word32 secretLen = CURVE25519_KEYSIZE;
    WC_RNG rng;
    wc_InitRng(&rng);
    int ret;

    *pubkey = (ptls_iovec_t){NULL};
    *secret = (ptls_iovec_t){NULL};

    if (peerkey.len != CURVE25519_KEYSIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }

    /* inport peerkey */
    peerX25519Key = (curve25519_key*)XMALLOC(sizeof(curve25519_key), NULL, NULL);
    if (peerX25519Key == NULL) {
        WOLFSSL_MSG("PeerEccKey Memory error");
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    ret = wc_curve25519_init(peerX25519Key);
    if (ret != 0) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;    
    }

    /* Point is validated by import function. */
    if (wc_curve25519_import_public_ex(peerkey.base, peerkey.len, peerX25519Key, EC25519_LITTLE_ENDIAN) != 0) {
        ret = ECC_PEERKEY_ERROR;
        goto Exit;
    }

    /* crease private key */
    privKey = (curve25519_key*)XMALLOC(sizeof(curve25519_key), NULL, NULL);
    if (privKey == NULL) {
        WOLFSSL_MSG("EccTempKey Memory error");
        return PTLS_ERROR_NO_MEMORY;
    }
    if(wc_curve25519_init(privKey) != 0){
        ret = ECC_EXPORT_ERROR;
        goto Exit;
    }
    ret = wc_curve25519_make_key(&rng, CURVE25519_KEYSIZE, privKey);
    if (ret != 0) {
        goto Exit;
    }

    /* export publickey from privatekey */
    if ((pubkey->base = XMALLOC(CURVE25519_KEYSIZE, NULL, NULL)) == NULL){
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (wc_curve25519_export_public_ex(privKey, pubkey->base, &pubLen, EC25519_LITTLE_ENDIAN) != 0) {
        ret = ECC_EXPORT_ERROR;
        goto Exit;
    }
    pubkey->len = (size_t)pubLen;

    /* calculate secrets*/
    if ((secret->base = XMALLOC(CURVE25519_KEYSIZE, NULL, NULL)) == NULL){
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    ret = wc_curve25519_shared_secret_ex(privKey, peerX25519Key, secret->base, &secretLen, EC25519_LITTLE_ENDIAN);
    secret->len = (size_t)secretLen;

Exit:
    wc_FreeRng(&rng);
    wc_curve25519_free(privKey);
    if (privKey != NULL){
        XFREE(privKey, NULL, NULL);
        privKey = NULL;
    }
    wc_curve25519_free(peerX25519Key);
    if (peerX25519Key != NULL){
        XFREE(peerX25519Key, NULL, NULL);
        peerX25519Key = NULL;
    }
    if (ret != 0){
        XFREE(pubkey->base, NULL, NULL);
        *pubkey = (ptls_iovec_t){NULL};
        XFREE(secret->base, NULL, NULL);
        *secret = (ptls_iovec_t){NULL};
    }
    return ret;
}

ptls_key_exchange_algorithm_t ptls_wolfcrypt_secp256r1 = {PTLS_GROUP_SECP256R1, wc_secp256r1_create_key_exchange, wc_secp256r1_key_exchange};
ptls_key_exchange_algorithm_t *ptls_wolfcrypt_key_exchanges[] = {&ptls_wolfcrypt_secp256r1, NULL};

ptls_key_exchange_algorithm_t ptls_wolfcrypt_x25519 = {PTLS_GROUP_X25519, wc_x25519_create_key_exchange, wc_x25519_key_exchange};
#endif /* USE_WOLFSSL_KX */

ptls_define_hash(sha256, wc_Sha256, wc_InitSha256, wc_Sha256Update, wc_Sha256Final);
ptls_define_hash(sha384, wc_Sha384, wc_InitSha384, wc_Sha384Update, wc_Sha384Final);

ptls_hash_algorithm_t ptls_wolfcrypt_sha256 = {PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE,
                                                sha256_create, PTLS_ZERO_DIGEST_SHA256};
ptls_hash_algorithm_t ptls_wolfcrypt_sha384 = {PTLS_SHA384_BLOCK_SIZE, PTLS_SHA384_DIGEST_SIZE,
                                                sha384_create, PTLS_ZERO_DIGEST_SHA384};

#if defined(USE_WOLFSSL_AEAD)

struct wolfctr_context_t {
    ptls_cipher_context_t super;
    Aes wolf_aes;
};

static void wc_aesctr_dispose(ptls_cipher_context_t *_ctx)
{
    struct wolfctr_context_t *ctx = (struct wolfctr_context_t *)_ctx;
    ptls_clear_memory(ctx, sizeof(*ctx));
}

static void wc_aesctr_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct wolfctr_context_t *ctx = (struct wolfctr_context_t *)_ctx;
    ctx->wolf_aes.left = 0;
    memset(ctx->wolf_aes.tmp ,0 ,AES_BLOCK_SIZE);
    wc_AesSetIV(&ctx->wolf_aes, iv);
}

static void wc_aesctr_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct wolfctr_context_t *ctx = (struct wolfctr_context_t *)_ctx;
    wc_AesCtrEncrypt(&ctx->wolf_aes, output, input, len);
}

static int wc_aesctr_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key, size_t key_size)
{
    struct wolfctr_context_t *ctx = (struct wolfctr_context_t *)_ctx;
    ctx->super.do_dispose = wc_aesctr_dispose;
    ctx->super.do_init = wc_aesctr_init;
    ctx->super.do_transform = wc_aesctr_transform;
    wc_AesSetKeyDirect(&ctx->wolf_aes, key, key_size, NULL, AES_ENCRYPTION);
    return 0;
}

static int aes128ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return wc_aesctr_setup_crypto(ctx, is_enc, key, PTLS_AES128_KEY_SIZE);
}

static int aes256ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return wc_aesctr_setup_crypto(ctx, is_enc, key, PTLS_AES256_KEY_SIZE);
}

struct wolfgcm_context_t {
    ptls_aead_context_t super;
    Aes wolf_aes;
    byte initialCounter[AES_BLOCK_SIZE];
    void* aad;
    size_t aadlen;
    size_t clen;
};

static WC_INLINE void IncrementCounter(byte* inOutCtr)
{
    int i;

    /* in network byte order so start at end and work back */
    for (i = AES_BLOCK_SIZE - 1; i >= AES_BLOCK_SIZE - CTR_SZ; i--) {
        if (++inOutCtr[i])  /* we're done unless we overflow */
            return;
    }
}

static void wc_aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct wolfgcm_context_t *ctx = (struct wolfgcm_context_t *)_ctx;

    /* clear all memory except super */
    ptls_clear_memory((uint8_t *)ctx + sizeof(ctx->super), sizeof(*ctx) - sizeof(ctx->super));
}

static void wc_aesgcm_encrypt_init(ptls_aead_context_t *_ctx, const void *iv, const void *aad, size_t aadlen)
{
    struct wolfgcm_context_t *ctx = (struct wolfgcm_context_t *)_ctx;

    ctx->clen = 0;
    ctx->aad = XMALLOC(aadlen, NULL, NULL);
    XMEMCPY(ctx->aad, aad, aadlen);
    ctx->aadlen = aadlen;

    /* initialCounter = = IV || 0^31 || 1 */
    XMEMSET(ctx->initialCounter, 0, AES_BLOCK_SIZE);
    XMEMCPY(ctx->initialCounter, iv, PTLS_AESGCM_IV_SIZE);
    ctx->initialCounter[AES_BLOCK_SIZE - 1] = 1;

    /* Set counter */
    ctx->wolf_aes.left = 0;
    wc_AesSetIV(&ctx->wolf_aes, ctx->initialCounter);
    IncrementCounter((byte *)ctx->wolf_aes.reg);
}

static size_t wc_aesgcm_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct wolfgcm_context_t *ctx = (struct wolfgcm_context_t *)_ctx;

    wc_AesCtrEncrypt(&ctx->wolf_aes, output, input, inlen);

    ctx->clen += inlen;
    return inlen;
}

static size_t wc_aesgcm_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct wolfgcm_context_t *ctx = (struct wolfgcm_context_t *)_ctx;
    byte scratch[AES_BLOCK_SIZE];

    GHASH(&ctx->wolf_aes, ctx->aad, ctx->aadlen, (byte *)output - ctx->clen, ctx->clen,
            (byte *)output, PTLS_AESGCM_TAG_SIZE);
    wc_AesEncryptDirect(&ctx->wolf_aes, scratch, ctx->initialCounter);
    xorbuf(output, scratch, PTLS_AESGCM_TAG_SIZE);

    XFREE(ctx->aad, NULL, NULL);
    return PTLS_AESGCM_TAG_SIZE;
}

static size_t wc_aesgcm_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, const void *iv,
                             const void *aad, size_t aadlen)
{
    struct wolfgcm_context_t *ctx = (struct wolfgcm_context_t *)_ctx;
    int ret=0;

    if (inlen < PTLS_AESGCM_TAG_SIZE)
        return SIZE_MAX;
    size_t tag_offset = inlen - PTLS_AESGCM_TAG_SIZE;

    if ((ret = wc_AesGcmDecrypt(&ctx->wolf_aes, output, input, tag_offset, iv, PTLS_AESGCM_IV_SIZE, (byte *)input + tag_offset,
                       PTLS_AESGCM_TAG_SIZE, aad, aadlen)) != 0)
        return SIZE_MAX;

    return tag_offset;
}

static int wc_aead_aesgcm_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, size_t key_size)
{
    struct wolfgcm_context_t *ctx = (struct wolfgcm_context_t *)_ctx;

    ctx->super.dispose_crypto = wc_aesgcm_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt_init = wc_aesgcm_encrypt_init;
        ctx->super.do_encrypt_update = wc_aesgcm_encrypt_update;
        ctx->super.do_encrypt_final = wc_aesgcm_encrypt_final;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = wc_aesgcm_decrypt;
    }

    wc_AesGcmSetKey(&ctx->wolf_aes, key, key_size);
    return 0;
}

static int aead_aes128gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return wc_aead_aesgcm_setup_crypto(ctx, is_enc, key, PTLS_AES128_KEY_SIZE);
}

static int aead_aes256gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return wc_aead_aesgcm_setup_crypto(ctx, is_enc, key, PTLS_AES256_KEY_SIZE);
}

ptls_cipher_algorithm_t ptls_wolfcrypt_aes128ctr = { "AES128-CTR", 
    PTLS_AES128_KEY_SIZE, 1 /* block size */, PTLS_AES_IV_SIZE, sizeof(struct wolfctr_context_t), aes128ctr_setup_crypto};
ptls_aead_algorithm_t ptls_wolfcrypt_aes128gcm = { "AES128-GCM", &ptls_wolfcrypt_aes128ctr, NULL, PTLS_AES128_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE, sizeof(struct wolfgcm_context_t), aead_aes128gcm_setup_crypto};

ptls_cipher_algorithm_t ptls_wolfcrypt_aes256ctr = { "AES256-CTR",
    PTLS_AES256_KEY_SIZE, 1 /* block size */, PTLS_AES_IV_SIZE, sizeof(struct wolfctr_context_t), aes256ctr_setup_crypto};
ptls_aead_algorithm_t ptls_wolfcrypt_aes256gcm = {"AES256-GCM", &ptls_wolfcrypt_aes256ctr, NULL, PTLS_AES256_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE, sizeof(struct wolfgcm_context_t), aead_aes256gcm_setup_crypto};

ptls_cipher_suite_t ptls_wolfcrypt_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_wolfcrypt_aes128gcm,
                                                       &ptls_wolfcrypt_sha256};
ptls_cipher_suite_t ptls_wolfcrypt_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_wolfcrypt_aes256gcm,
                                                       &ptls_wolfcrypt_sha384};

ptls_cipher_suite_t *ptls_wolfcrypt_cipher_suites[] = {&ptls_wolfcrypt_aes256gcmsha384, &ptls_wolfcrypt_aes128gcmsha256, NULL};
#endif /* USE_WOLFSSL_AEAD */

#if 0
struct chacha20_context_t {
    ptls_cipher_context_t super;
    cf_chacha20_ctx chacha;
    uint8_t key[PTLS_CHACHA20_KEY_SIZE];
};

static void chacha20_dispose(ptls_cipher_context_t *_ctx)
{
    struct chacha20_context_t *ctx = (struct chacha20_context_t *)_ctx;
    ptls_clear_memory(ctx, sizeof(*ctx));
}

static void chacha20_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct chacha20_context_t *ctx = (struct chacha20_context_t *)_ctx;
    ctx->chacha.nblock = 0;
    ctx->chacha.ncounter = 0;
    memcpy(ctx->chacha.nonce, iv, sizeof ctx->chacha.nonce);
}

static void chacha20_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct chacha20_context_t *ctx = (struct chacha20_context_t *)_ctx;
    cf_chacha20_cipher(&ctx->chacha, input, output, len);
}

static int chacha20_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key)
{
    struct chacha20_context_t *ctx = (struct chacha20_context_t *)_ctx;
    ctx->super.do_dispose = chacha20_dispose;
    ctx->super.do_init = chacha20_init;
    ctx->super.do_transform = chacha20_transform;
    cf_chacha20_init(&ctx->chacha, key, PTLS_CHACHA20_KEY_SIZE, (const uint8_t *)"01234567" /* not used */);
    return 0;
}

struct chacha20poly1305_context_t {
    ptls_aead_context_t super;
    uint8_t key[PTLS_CHACHA20_KEY_SIZE];
    cf_chacha20_ctx chacha;
    cf_poly1305 poly;
    size_t aadlen;
    size_t textlen;
};

static void chacha20poly1305_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    /* clear all memory except super */
    ptls_clear_memory(&ctx->key, sizeof(*ctx) - offsetof(struct chacha20poly1305_context_t, key));
}

static const uint8_t zeros64[64] = {0};

static void chacha20poly1305_encrypt_pad(cf_poly1305 *poly, size_t n)
{
    if (n % 16 != 0)
        cf_poly1305_update(poly, zeros64, 16 - (n % 16));
}

static void chacha20poly1305_finalize(struct chacha20poly1305_context_t *ctx, uint8_t *tag)
{
    uint8_t lenbuf[16];

    chacha20poly1305_encrypt_pad(&ctx->poly, ctx->textlen);

    write64_le(ctx->aadlen, lenbuf);
    write64_le(ctx->textlen, lenbuf + 8);
    cf_poly1305_update(&ctx->poly, lenbuf, sizeof(lenbuf));

    cf_poly1305_finish(&ctx->poly, tag);
}

static void chacha20poly1305_init(ptls_aead_context_t *_ctx, const void *iv, const void *aad, size_t aadlen)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;
    uint8_t tmpbuf[64];

    /* init chacha */
    memset(tmpbuf, 0, 16 - PTLS_CHACHA20POLY1305_IV_SIZE);
    memcpy(tmpbuf + 16 - PTLS_CHACHA20POLY1305_IV_SIZE, iv, PTLS_CHACHA20POLY1305_IV_SIZE);
    cf_chacha20_init_custom(&ctx->chacha, ctx->key, sizeof(ctx->key), tmpbuf, 4);

    /* init poly1305 (by using first 16 bytes of the key stream of the first block) */
    cf_chacha20_cipher(&ctx->chacha, zeros64, tmpbuf, 64);
    cf_poly1305_init(&ctx->poly, tmpbuf, tmpbuf + 16);

    ptls_clear_memory(tmpbuf, sizeof(tmpbuf));

    /* aad */
    if (aadlen != 0) {
        cf_poly1305_update(&ctx->poly, aad, aadlen);
        chacha20poly1305_encrypt_pad(&ctx->poly, aadlen);
    }

    ctx->aadlen = aadlen;
    ctx->textlen = 0;
}

static size_t chacha20poly1305_encrypt_update(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    cf_chacha20_cipher(&ctx->chacha, input, output, inlen);
    cf_poly1305_update(&ctx->poly, output, inlen);
    ctx->textlen += inlen;

    return inlen;
}

static size_t chacha20poly1305_encrypt_final(ptls_aead_context_t *_ctx, void *output)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    chacha20poly1305_finalize(ctx, output);

    ptls_clear_memory(&ctx->chacha, sizeof(ctx->chacha));
    return PTLS_CHACHA20POLY1305_TAG_SIZE;
}

static size_t chacha20poly1305_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, const void *iv,
                                       const void *aad, size_t aadlen)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;
    uint8_t tag[PTLS_CHACHA20POLY1305_TAG_SIZE];
    size_t ret;

    if (inlen < sizeof(tag))
        return SIZE_MAX;

    chacha20poly1305_init(&ctx->super, iv, aad, aadlen);

    cf_poly1305_update(&ctx->poly, input, inlen - sizeof(tag));
    ctx->textlen = inlen - sizeof(tag);

    chacha20poly1305_finalize(ctx, tag);
    if (mem_eq(tag, (const uint8_t *)input + inlen - sizeof(tag), sizeof(tag))) {
        cf_chacha20_cipher(&ctx->chacha, input, output, inlen - sizeof(tag));
        ret = inlen - sizeof(tag);
    } else {
        ret = SIZE_MAX;
    }

    ptls_clear_memory(tag, sizeof(tag));
    ptls_clear_memory(&ctx->poly, sizeof(ctx->poly));

    return ret;
}

static int aead_chacha20poly1305_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key)
{
    struct chacha20poly1305_context_t *ctx = (struct chacha20poly1305_context_t *)_ctx;

    ctx->super.dispose_crypto = chacha20poly1305_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt_init = chacha20poly1305_init;
        ctx->super.do_encrypt_update = chacha20poly1305_encrypt_update;
        ctx->super.do_encrypt_final = chacha20poly1305_encrypt_final;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = chacha20poly1305_decrypt;
    }

    memcpy(ctx->key, key, sizeof(ctx->key));
    return 0;
}

#endif /* Unimplemented */

#if 0
ptls_cipher_algorithm_t ptls_wolfcrypt_chacha20 = {
    "CHACHA20",           PTLS_CHACHA20_KEY_SIZE, 1 /* block size */, PTLS_CHACHA20_IV_SIZE, sizeof(struct chacha20_context_t),
    chacha20_setup_crypto};
ptls_aead_algorithm_t ptls_wolfcrypt_chacha20poly1305 = {"CHACHA20-POLY1305",
                                                          &ptls_wolfcrypt_chacha20,
                                                          NULL,
                                                          PTLS_CHACHA20_KEY_SIZE,
                                                          PTLS_CHACHA20POLY1305_IV_SIZE,
                                                          PTLS_CHACHA20POLY1305_TAG_SIZE,
                                                          sizeof(struct chacha20poly1305_context_t),
                                                          aead_chacha20poly1305_setup_crypto};
#endif /* Unimplemented */

#if 0
ptls_cipher_suite_t ptls_wolfcrypt_chacha20poly1305sha256 = {PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
                                                              &ptls_wolfcrypt_chacha20poly1305, &ptls_wolfcrypt_sha256};
#endif /* Unimplemented */
