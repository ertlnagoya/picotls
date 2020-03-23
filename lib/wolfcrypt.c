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

#include <wolfssl/ssl.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/internal.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include "wolfssl/openssl/bn.h"
#include "wolfssl/openssl/crypto.h"
#include "wolfssl/openssl/ec.h"
#include "wolfssl/openssl/ecdh.h"
#include "wolfssl/openssl/err.h"
#include "wolfssl/openssl/evp.h"
#include "wolfssl/openssl/objects.h"
#include "wolfssl/openssl/rand.h"
#include "wolfssl/openssl/x509.h"
#include "wolfssl/openssl/x509v3.h"
#include "wolfssl/openssl/ssl.h"
#include "wolfssl/openssl/x509v3.h"

#ifdef NO_INLINE
    #include <wolfssl/wolfcrypt/misc.h>
#else
    #define WOLFSSL_MISC_INCLUDED
    #include <wolfcrypt/src/misc.c>
#endif

#include "picotls_settings.h"
#include "picotls.h"
#include "picotls/wolfcrypt.h"

/* OpenSSL互換がないため */
int EVP_PKEY_CTX_set_rsa_mgf1_md(EVP_PKEY_CTX *ctx, const EVP_MD *md){
    return 0;
}

int EVP_PKEY_CTX_set_rsa_pss_saltlen(EVP_PKEY_CTX *ctx, int len){
    return 0;
}

int EVP_PKEY_up_ref(EVP_PKEY *pkey)
{
    return 0;
}

int X509_STORE_CTX_set_purpose(X509_STORE_CTX *ctx, int purpose)
{
    return 0;
}

int X509_STORE_up_ref(X509_STORE *vfy)
{
    return 0;
}
/* OpenSSL互換がないため */

void ptls_wolfcrypt_random_bytes(void *buf, size_t len)
{
    int ret = wolfSSL_RAND_bytes(buf, (int)len);
    if (ret != 1) {
        WOLFSSL_MSG("RAND_bytes() failed");
    }
}

static X509 *x509_from_pem_buffer(const char *pem)
{
    BIO *bio = BIO_new_mem_buf((void *)pem, (int)strlen(pem));
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    assert(cert != NULL && "failed to load certificate");
    BIO_free(bio);
    return cert;
}

static int setup_certificate_buffer(const char* certbuf, ptls_iovec_t *dst, size_t *nb_objects)
{
    int ret = 0;
    X509 *cert = x509_from_pem_buffer(certbuf);

    dst->base = NULL;
    dst->len = i2d_X509(cert, &dst->base);
    *nb_objects += 1;

    if(dst->base == NULL){
        ret = -1;
    }

    X509_free(cert);
    return ret;
}

static int do_sign(EVP_PKEY *key, ptls_buffer_t *outbuf, ptls_iovec_t input, const EVP_MD *md)
{
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx;
    size_t siglen;
    int ret;

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_DigestSignInit(ctx, &pkey_ctx, md, NULL, key) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
    }
    if (EVP_DigestSignUpdate(ctx, input.base, input.len) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_DigestSignFinal(ctx, NULL, &siglen) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if ((ret = ptls_buffer_reserve(outbuf, siglen)) != 0)
        goto Exit;
    if (EVP_DigestSignFinal(ctx, outbuf->base + outbuf->off, &siglen) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    outbuf->off += siglen;

    ret = 0;
Exit:
    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);
    return ret;
}

static int sign_certificate(ptls_sign_certificate_t *_self, ptls_t *tls, uint16_t *selected_algorithm, ptls_buffer_t *outbuf,
                            ptls_iovec_t input, const uint16_t *algorithms, size_t num_algorithms)
{
    ptls_openssl_sign_certificate_t *self = (ptls_openssl_sign_certificate_t *)_self;
    const struct st_ptls_openssl_signature_scheme_t *scheme;

    /* select the algorithm */
    for (scheme = self->schemes; scheme->scheme_id != UINT16_MAX; ++scheme) {
        size_t i;
        for (i = 0; i != num_algorithms; ++i)
            if (algorithms[i] == scheme->scheme_id)
                goto Found;
    }
    return PTLS_ALERT_HANDSHAKE_FAILURE;

Found:
    *selected_algorithm = scheme->scheme_id;
    return do_sign(self->key, outbuf, input, scheme->scheme_md);
}

static X509 *to_x509(ptls_iovec_t vec)
{
    const uint8_t *p = vec.base;
    return d2i_X509(NULL, &p, (long)vec.len);
}

static int verify_sign(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t signature)
{
    EVP_PKEY *key = verify_ctx;
    EVP_MD_CTX *ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int ret = 0;

    if (data.base == NULL)
        goto Exit;

    if ((ctx = EVP_MD_CTX_create()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (EVP_DigestVerifyInit(ctx, &pkey_ctx, EVP_sha256(), NULL, key) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_PKEY_id(key) == EVP_PKEY_RSA) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, -1) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
        if (EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, EVP_sha256()) != 1) {
            ret = PTLS_ERROR_LIBRARY;
            goto Exit;
        }
    }
    if (EVP_DigestVerifyUpdate(ctx, data.base, data.len) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    if (EVP_DigestVerifyFinal(ctx, signature.base, signature.len) != 1) {
        ret = PTLS_ALERT_DECRYPT_ERROR;
        goto Exit;
    }
    ret = 0;

Exit:
    if (ctx != NULL)
        EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(key);
    return ret;
}

static int verify_cert_chain(X509_STORE *store, X509 *cert, STACK_OF(X509) * chain, int is_server, const char *server_name)
{
    X509_STORE_CTX *verify_ctx;
    int ret;

    assert(server_name != NULL && "ptls_set_server_name MUST be called");

    /* verify certificate chain */
    if ((verify_ctx = X509_STORE_CTX_new()) == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
        goto Exit;
    }
    if (X509_STORE_CTX_init(verify_ctx, store, cert, chain) != 1) {
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
    }
    X509_STORE_CTX_set_purpose(verify_ctx, is_server ? X509_PURPOSE_SSL_SERVER : X509_PURPOSE_SSL_CLIENT);
    if (X509_verify_cert(verify_ctx) != 1) {
        int x509_err = X509_STORE_CTX_get_error(verify_ctx);
        switch (x509_err) {
        case X509_V_ERR_OUT_OF_MEM:
            ret = PTLS_ERROR_NO_MEMORY;
            break;
        case X509_V_ERR_CERT_REVOKED:
            ret = PTLS_ALERT_CERTIFICATE_REVOKED;
            break;
        case X509_V_ERR_CERT_NOT_YET_VALID:
        case X509_V_ERR_CERT_HAS_EXPIRED:
            ret = PTLS_ALERT_CERTIFICATE_EXPIRED;
            break;
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        case X509_V_ERR_CERT_UNTRUSTED:
        case X509_V_ERR_CERT_REJECTED:
            ret = PTLS_ALERT_UNKNOWN_CA;
            break;
        case X509_V_ERR_INVALID_CA:
            ret = PTLS_ALERT_BAD_CERTIFICATE;
            break;
        default:
            ret = PTLS_ALERT_CERTIFICATE_UNKNOWN;
            break;
        }
        goto Exit;
    }

#ifdef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
    /* verify CN */
    if (server_name != NULL) {
        if (ptls_server_name_is_ipaddr(server_name)) {
            ret = X509_check_ip_asc(cert, server_name, 0);
        } else {
            ret = X509_check_host(cert, server_name, strlen(server_name), X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS, NULL);
        }
        if (ret != 1) {
            if (ret == 0) { /* failed match */
                ret = PTLS_ALERT_BAD_CERTIFICATE;
            } else {
                ret = PTLS_ERROR_LIBRARY;
            }
            goto Exit;
        }
    }
#else
#warning "hostname validation is disabled; OpenSSL >= 1.0.2 or LibreSSL >= 2.5.0 is required"
#endif

    ret = 0;

Exit:
    // if (verify_ctx != NULL)
    //     X509_STORE_CTX_free(verify_ctx);
    return ret;
}

static int verify_cert(ptls_verify_certificate_t *_self, ptls_t *tls, int (**verifier)(void *, ptls_iovec_t, ptls_iovec_t),
                       void **verify_data, ptls_iovec_t *certs, size_t num_certs)
{
    ptls_openssl_verify_certificate_t *self = (ptls_openssl_verify_certificate_t *)_self;
    X509 *cert = NULL;
    STACK_OF(X509) *chain = sk_X509_new();
    size_t i;
    int ret = 0;

    assert(num_certs != 0);

    /* convert certificates to OpenSSL representation */
    if ((cert = to_x509(certs[0])) == NULL) {
        ret = PTLS_ALERT_BAD_CERTIFICATE;
        goto Exit;
    }
    for (i = 0; i != num_certs; ++i) {
        X509 *interm = to_x509(certs[i]);
        if (interm == NULL) {
            ret = PTLS_ALERT_BAD_CERTIFICATE;
            goto Exit;
        }
        sk_X509_push(chain, interm);
    }

    /* verify the chain */
    if ((ret = verify_cert_chain(self->cert_store, cert, chain, ptls_is_server(tls), ptls_get_server_name(tls))) != 0)
        goto Exit;

    /* extract public key for verifying the TLS handshake signature */
    if ((*verify_data = X509_get_pubkey(cert)) == NULL) {
        ret = PTLS_ALERT_BAD_CERTIFICATE;
        goto Exit;
    }
    *verifier = verify_sign;

Exit:
    if (chain != NULL)
        sk_X509_pop_free(chain, X509_free);
    if (cert != NULL)
        X509_free(cert);
    return ret;
}

int ptls_openssl_init_verify_certificate(ptls_openssl_verify_certificate_t *self, X509_STORE *store)
{
    *self = (ptls_openssl_verify_certificate_t){{verify_cert}};

    if (store != NULL) {
        X509_STORE_up_ref(store);
        self->cert_store = store;
    } else {
        /* use default store */
        if ((self->cert_store = ptls_openssl_create_default_certificate_store()) == NULL)
            return -1;
    }

    return 0;
}

void ptls_openssl_dispose_verify_certificate(ptls_openssl_verify_certificate_t *self)
{
    X509_STORE_free(self->cert_store);
    free(self);
}

X509_STORE *ptls_openssl_create_default_certificate_store(void)
{
    X509_STORE *store;
    X509_LOOKUP *lookup;

    if ((store = X509_STORE_new()) == NULL)
        goto Error;
    if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file())) == NULL)
        goto Error;
    X509_LOOKUP_load_file(lookup, NULL, X509_FILETYPE_DEFAULT);
    if ((lookup = X509_STORE_add_lookup(store, X509_LOOKUP_hash_dir())) == NULL)
        goto Error;
    X509_LOOKUP_add_dir(lookup, NULL, X509_FILETYPE_DEFAULT);

    return store;
Error:
    if (store != NULL)
        X509_STORE_free(store);
    return NULL;
}

int ptls_openssl_init_sign_certificate(ptls_openssl_sign_certificate_t *self, EVP_PKEY *key)
{
    *self = (ptls_openssl_sign_certificate_t){{sign_certificate}};
    size_t scheme_index = 0;

#define PUSH_SCHEME(id, md)                                                                                                        \
    self->schemes[scheme_index++] = (struct st_ptls_openssl_signature_scheme_t)                                                    \
    {                                                                                                                              \
        id, md                                                                                                                     \
    }

    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA:
        PUSH_SCHEME(PTLS_SIGNATURE_RSA_PSS_RSAE_SHA256, EVP_sha256());
        PUSH_SCHEME(PTLS_SIGNATURE_RSA_PSS_RSAE_SHA384, EVP_sha384());
        PUSH_SCHEME(PTLS_SIGNATURE_RSA_PSS_RSAE_SHA512, EVP_sha512());
        break;
    case EVP_PKEY_EC: {
        //EC_KEY *eckey = EVP_PKEY_get1_EC_KEY(key);
        EC_KEY *eckey = key->ecc;
        switch (EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey))) {
        case NID_X9_62_prime256v1:
            PUSH_SCHEME(PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256, EVP_sha256());
            break;
#if defined(NID_secp384r1) && !OPENSSL_NO_SHA384
        case NID_secp384r1:
            PUSH_SCHEME(PTLS_SIGNATURE_ECDSA_SECP384R1_SHA384, EVP_sha384());
            break;
#endif
#if defined(NID_secp384r1) && !OPENSSL_NO_SHA512
        case NID_secp521r1:
            PUSH_SCHEME(PTLS_SIGNATURE_ECDSA_SECP521R1_SHA512, EVP_sha512());
            break;
#endif
        default:
            EC_KEY_free(eckey);
            return PTLS_ERROR_INCOMPATIBLE_KEY;
        }
        //EC_KEY_free(eckey);
    } break;
    default:
        return PTLS_ERROR_INCOMPATIBLE_KEY;
    }
    PUSH_SCHEME(UINT16_MAX, NULL);
    assert(scheme_index <= sizeof(self->schemes) / sizeof(self->schemes[0]));

#undef PUSH_SCHEME

    EVP_PKEY_up_ref(key);
    self->key = key;

    return 0;
}

void ptls_openssl_dispose_sign_certificate(ptls_openssl_sign_certificate_t *self)
{
    EVP_PKEY_free(self->key);
}

static int serialize_cert(X509 *cert, ptls_iovec_t *dst)
{
    int len = i2d_X509(cert, NULL);
    assert(len > 0);

    if ((dst->base = malloc(len)) == NULL)
        return PTLS_ERROR_NO_MEMORY;
    unsigned char *p = dst->base;
    dst->len = i2d_X509(cert, &p);
    assert(len == dst->len);

    return 0;
}

#define WOLF_MAX_CERTS_IN_CONTEXT 16

#ifdef NO_FILESYSTEM
int wolfcrypt_load_certificates(ptls_context_t *ctx)
{
    int ret = 0;

    ctx->certificates.list = (ptls_iovec_t *)malloc(WOLF_MAX_CERTS_IN_CONTEXT * sizeof(ptls_iovec_t));

    if (ctx->certificates.list == NULL) {
        ret = PTLS_ERROR_NO_MEMORY;
    } else {
        ret = setup_certificate_buffer(TLS_ECDSA_CERT, ctx->certificates.list, &ctx->certificates.count);
    }

    return ret;
}
#endif

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
ptls_key_exchange_algorithm_t ptls_wolfcrypt_x25519 = {PTLS_GROUP_X25519, wc_x25519_create_key_exchange, wc_x25519_key_exchange};

ptls_key_exchange_algorithm_t *ptls_wolfcrypt_key_exchanges[] = {&ptls_wolfcrypt_x25519, &ptls_wolfcrypt_secp256r1, NULL};

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

ptls_cipher_suite_t *ptls_wolfcrypt_cipher_suites[] = {&ptls_wolfcrypt_aes128gcmsha256, &ptls_wolfcrypt_aes256gcmsha384, NULL};
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

