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

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>

#include "userq_settings.h"
#include "picotls.h"
#include "picotls/wolfcrypt.h"

#if defined(USE_WOLFSSL)
#if 0
void ptls_wolfcrypt_random_bytes(void *buf, size_t len)
{
    return;
}

#define X25519_KEY_SIZE 32

struct st_x25519_key_exchange_t {
    ptls_key_exchange_context_t super;
    uint8_t priv[X25519_KEY_SIZE];
    uint8_t pub[X25519_KEY_SIZE];
};

static void x25519_create_keypair(uint8_t *priv, uint8_t *pub)
{
    ptls_minicrypto_random_bytes(priv, X25519_KEY_SIZE);
    cf_curve25519_mul_base(pub, priv);
}

static int x25519_derive_secret(ptls_iovec_t *secret, const uint8_t *clientpriv, const uint8_t *clientpub,
                                const uint8_t *serverpriv, const uint8_t *serverpub)
{
    if ((secret->base = malloc(X25519_KEY_SIZE)) == NULL)
        return PTLS_ERROR_NO_MEMORY;

    cf_curve25519_mul(secret->base, clientpriv != NULL ? clientpriv : serverpriv, clientpriv != NULL ? serverpub : clientpub);
    secret->len = X25519_KEY_SIZE;
    return 0;
}

static int x25519_on_exchange(ptls_key_exchange_context_t **_ctx, int release, ptls_iovec_t *secret, ptls_iovec_t peerkey)
{
    struct st_x25519_key_exchange_t *ctx = (struct st_x25519_key_exchange_t *)*_ctx;
    int ret;

    if (secret == NULL) {
        ret = 0;
        goto Exit;
    }

    if (peerkey.len != X25519_KEY_SIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ret = x25519_derive_secret(secret, ctx->priv, ctx->pub, NULL, peerkey.base);

Exit:
    if (release) {
        ptls_clear_memory(ctx->priv, sizeof(ctx->priv));
        free(ctx);
        *_ctx = NULL;
    }
    return ret;
}

static int x25519_create_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_key_exchange_context_t **_ctx)
{
    struct st_x25519_key_exchange_t *ctx;

    if ((ctx = (struct st_x25519_key_exchange_t *)malloc(sizeof(*ctx))) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    ctx->super = (ptls_key_exchange_context_t){algo, ptls_iovec_init(ctx->pub, sizeof(ctx->pub)), x25519_on_exchange};
    x25519_create_keypair(ctx->priv, ctx->pub);

    *_ctx = &ctx->super;
    return 0;
}

static int x25519_key_exchange(ptls_key_exchange_algorithm_t *algo, ptls_iovec_t *pubkey, ptls_iovec_t *secret,
                               ptls_iovec_t peerkey)
{
    uint8_t priv[X25519_KEY_SIZE], *pub = NULL;
    int ret;

    if (peerkey.len != X25519_KEY_SIZE) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    if ((pub = malloc(X25519_KEY_SIZE)) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }

    x25519_create_keypair(priv, pub);
    if ((ret = x25519_derive_secret(secret, NULL, peerkey.base, priv, pub)) != 0)
        goto Exit;

    *pubkey = ptls_iovec_init(pub, X25519_KEY_SIZE);
    ret = 0;

Exit:
    ptls_clear_memory(priv, sizeof(priv));
    if (pub != NULL && ret != 0)
        ptls_clear_memory(pub, X25519_KEY_SIZE);
    return ret;
}
#endif /* Unimplemented */

struct wolfctr_context_t {
    ptls_cipher_context_t super;
    Aes wolf_aes;
};

static void aesctr_dispose(ptls_cipher_context_t *_ctx)
{
    struct wolfctr_context_t *ctx = (struct wolfctr_context_t *)_ctx;
    ptls_clear_memory(ctx, sizeof(*ctx));
}

static void aesctr_init(ptls_cipher_context_t *_ctx, const void *iv)
{
    struct wolfctr_context_t *ctx = (struct wolfctr_context_t *)_ctx;
    ctx->wolf_aes.left = 0;
    memset(ctx->wolf_aes.tmp ,0 ,AES_BLOCK_SIZE);
    wc_AesSetIV(&ctx->wolf_aes, iv);
}

static void aesctr_transform(ptls_cipher_context_t *_ctx, void *output, const void *input, size_t len)
{
    struct wolfctr_context_t *ctx = (struct wolfctr_context_t *)_ctx;
    wc_AesCtrEncrypt(&ctx->wolf_aes, output, input, len);
}

static int aesctr_setup_crypto(ptls_cipher_context_t *_ctx, int is_enc, const void *key, size_t key_size)
{
    struct wolfctr_context_t *ctx = (struct wolfctr_context_t *)_ctx;
    ctx->super.do_dispose = aesctr_dispose;
    ctx->super.do_init = aesctr_init;
    ctx->super.do_transform = aesctr_transform;
    wc_AesSetKeyDirect(&ctx->wolf_aes, key, key_size, NULL, AES_ENCRYPTION);
    return 0;
}

static int aes128ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesctr_setup_crypto(ctx, is_enc, key, PTLS_AES128_KEY_SIZE);
}

static int aes256ctr_setup_crypto(ptls_cipher_context_t *ctx, int is_enc, const void *key)
{
    return aesctr_setup_crypto(ctx, is_enc, key, PTLS_AES256_KEY_SIZE);
}

struct aesgcm_context_t {
    ptls_aead_context_t super;
    Aes wolf_aes;
};

static void aesgcm_dispose_crypto(ptls_aead_context_t *_ctx)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    /* clear all memory except super */
    ptls_clear_memory((uint8_t *)ctx + sizeof(ctx->super), sizeof(*ctx) - sizeof(ctx->super));
}

static size_t aesgcm_encrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, const void *iv,
                             const void *aad, size_t aadlen)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    wc_AesGcmEncrypt(&ctx->wolf_aes, output, input, inlen, iv, PTLS_AESGCM_IV_SIZE, (byte *)output + inlen,
                        PTLS_AESGCM_TAG_SIZE, aad, aadlen);

    return inlen + PTLS_AESGCM_TAG_SIZE;
}

static size_t aesgcm_decrypt(ptls_aead_context_t *_ctx, void *output, const void *input, size_t inlen, const void *iv,
                             const void *aad, size_t aadlen)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;
    int ret=0;

    if (inlen < PTLS_AESGCM_TAG_SIZE)
        return SIZE_MAX;
    size_t tag_offset = inlen - PTLS_AESGCM_TAG_SIZE;

    if ((ret = wc_AesGcmDecrypt(&ctx->wolf_aes, output, input, tag_offset, iv, PTLS_AESGCM_IV_SIZE, (byte *)input + tag_offset,
                       PTLS_AESGCM_TAG_SIZE, aad, aadlen)) != 0)
        return SIZE_MAX;

    return tag_offset;
}

static int aead_aesgcm_setup_crypto(ptls_aead_context_t *_ctx, int is_enc, const void *key, size_t key_size)
{
    struct aesgcm_context_t *ctx = (struct aesgcm_context_t *)_ctx;

    ctx->super.dispose_crypto = aesgcm_dispose_crypto;
    if (is_enc) {
        ctx->super.do_encrypt = aesgcm_encrypt;
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = NULL;
    } else {
        ctx->super.do_encrypt = NULL;
        ctx->super.do_encrypt_init = NULL;
        ctx->super.do_encrypt_update = NULL;
        ctx->super.do_encrypt_final = NULL;
        ctx->super.do_decrypt = aesgcm_decrypt;
    }

    wc_AesGcmSetKey(&ctx->wolf_aes, key, key_size);
    return 0;
}

static int aead_aes128gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return aead_aesgcm_setup_crypto(ctx, is_enc, key, PTLS_AES128_KEY_SIZE);
}

static int aead_aes256gcm_setup_crypto(ptls_aead_context_t *ctx, int is_enc, const void *key)
{
    return aead_aesgcm_setup_crypto(ctx, is_enc, key, PTLS_AES256_KEY_SIZE);
}

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

ptls_key_exchange_algorithm_t ptls_minicrypto_x25519 = {PTLS_GROUP_X25519, x25519_create_key_exchange, x25519_key_exchange};
#endif /* Unimplemented */

ptls_define_hash(sha256, wc_Sha256, wc_InitSha256, wc_Sha256Update, wc_Sha256Final);
ptls_define_hash(sha384, wc_Sha384, wc_InitSha384, wc_Sha384Update, wc_Sha384Final);

ptls_cipher_algorithm_t ptls_wolfcrypt_aes128ctr = {
    "AES128-CTR",          PTLS_AES128_KEY_SIZE, 1 /* block size */, PTLS_AES_IV_SIZE, sizeof(struct wolfctr_context_t),
    aes128ctr_setup_crypto};
ptls_aead_algorithm_t ptls_wolfcrypt_aes128gcm = {
    "AES128-GCM",        &ptls_wolfcrypt_aes128ctr, NULL,      PTLS_AES128_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE,       sizeof(struct aesgcm_context_t), aead_aes128gcm_setup_crypto};
ptls_cipher_algorithm_t ptls_wolfcrypt_aes256ctr = {
    "AES256-CTR",          PTLS_AES256_KEY_SIZE, 1 /* block size */, PTLS_AES_IV_SIZE, sizeof(struct wolfctr_context_t),
    aes256ctr_setup_crypto};
ptls_aead_algorithm_t ptls_wolfcrypt_aes256gcm = {
    "AES256-GCM",        &ptls_wolfcrypt_aes256ctr, NULL,      PTLS_AES256_KEY_SIZE,
    PTLS_AESGCM_IV_SIZE, PTLS_AESGCM_TAG_SIZE,       sizeof(struct aesgcm_context_t), aead_aes256gcm_setup_crypto};

ptls_hash_algorithm_t ptls_wolfcrypt_sha256 = {PTLS_SHA256_BLOCK_SIZE, PTLS_SHA256_DIGEST_SIZE, sha256_create,
                                                PTLS_ZERO_DIGEST_SHA256};
ptls_hash_algorithm_t ptls_wolfcrypt_sha384 = {PTLS_SHA384_BLOCK_SIZE, PTLS_SHA384_DIGEST_SIZE, sha384_create,
                                                PTLS_ZERO_DIGEST_SHA384};
#if 0
ptls_cipher_algorithm_t ptls_minicrypto_chacha20 = {
    "CHACHA20",           PTLS_CHACHA20_KEY_SIZE, 1 /* block size */, PTLS_CHACHA20_IV_SIZE, sizeof(struct chacha20_context_t),
    chacha20_setup_crypto};
ptls_aead_algorithm_t ptls_minicrypto_chacha20poly1305 = {"CHACHA20-POLY1305",
                                                          &ptls_minicrypto_chacha20,
                                                          NULL,
                                                          PTLS_CHACHA20_KEY_SIZE,
                                                          PTLS_CHACHA20POLY1305_IV_SIZE,
                                                          PTLS_CHACHA20POLY1305_TAG_SIZE,
                                                          sizeof(struct chacha20poly1305_context_t),
                                                          aead_chacha20poly1305_setup_crypto};
#endif /* Unimplemented */

ptls_cipher_suite_t ptls_wolfcrypt_aes128gcmsha256 = {PTLS_CIPHER_SUITE_AES_128_GCM_SHA256, &ptls_wolfcrypt_aes128gcm,
                                                       &ptls_wolfcrypt_sha256};
ptls_cipher_suite_t ptls_wolfcrypt_aes256gcmsha384 = {PTLS_CIPHER_SUITE_AES_256_GCM_SHA384, &ptls_wolfcrypt_aes256gcm,
                                                       &ptls_wolfcrypt_sha384};

#if 0
ptls_cipher_suite_t ptls_minicrypto_chacha20poly1305sha256 = {PTLS_CIPHER_SUITE_CHACHA20_POLY1305_SHA256,
                                                              &ptls_minicrypto_chacha20poly1305, &ptls_minicrypto_sha256};
#endif /* Unimplemented */

ptls_cipher_suite_t *ptls_wolfcrypt_cipher_suites[] = {&ptls_wolfcrypt_aes256gcmsha384, &ptls_wolfcrypt_aes128gcmsha256
                                                        , NULL};
#endif /* USE_WOLFSSL */