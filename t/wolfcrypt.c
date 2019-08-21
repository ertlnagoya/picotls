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
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <wolfssl/error-ssl.h>
#include <wolfssl/wolfcrypt/logging.h>
#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/curve25519.h>
#include <wolfssl/wolfcrypt/sha256.h>
#include <wolfssl/wolfcrypt/sha512.h>
#include "wolfssl/ssl.h"
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
#include "../deps/picotest/picotest.h"
#include "../lib/wolfcrypt.c"
#include "picotls/wolfcrypt.h"
#include "picotls/minicrypto.h"
#include "picotls/openssl.h"

#include "test.h"

#define ECDSA_PRIVATE_KEY                                                                                            \
"-----BEGIN EC PRIVATE KEY-----\n"                                                                                   \
"MHcCAQEEIEW2aQJznGyFoThbcujox6zEA41TNQT6bCjcNI3hqAmMoAoGCCqGSM49\n"                                                 \
"AwEHoUQDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U6iv6yyAJOSwW6GEC6a9N0wKT\n"                                                 \
"mjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==\n"                                                                             \
"-----END EC PRIVATE KEY-----\n"

#define ECDSA_CERTIFICATE                                                                                        \
"-----BEGIN CERTIFICATE-----\n"                                                                                      \
"MIIDUDCCAvWgAwIBAgICEAAwCgYIKoZIzj0EAwIwgZcxCzAJBgNVBAYTAlVTMRMw\n"                                                 \
"EQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMRAwDgYDVQQKDAd3\n"                                                 \
"b2xmU1NMMRQwEgYDVQQLDAtEZXZlbG9wbWVudDEYMBYGA1UEAwwPd3d3LndvbGZz\n"                                                 \
"c2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tMB4XDTE3MTAy\n"                                                 \
"MDE4MTkwNloXDTI3MTAxODE4MTkwNlowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQI\n"                                                 \
"DApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMRAwDgYDVQQKDAdFbGlwdGlj\n"                                                 \
"MQwwCgYDVQQLDANFQ0MxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqG\n"                                                 \
"SIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"                                                 \
"A0IABLszrEwnUErGSqUEwzzenzbbci3OlOor+ssgCTksFuhhAumvTdMCk5oxW5eS\n"                                                 \
"IX/wzxjakRECNIboIFgzC4A0idijggE1MIIBMTAJBgNVHRMEAjAAMBEGCWCGSAGG\n"                                                 \
"+EIBAQQEAwIGQDAdBgNVHQ4EFgQUXV0m76x+NvmbdhUrSiUCI++yiTAwgcwGA1Ud\n"                                                 \
"IwSBxDCBwYAUVo6aw/BC3hi5RVVu+ZPP6sPzpSGhgZ2kgZowgZcxCzAJBgNVBAYT\n"                                                 \
"AlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMRAwDgYD\n"                                                 \
"VQQKDAd3b2xmU1NMMRQwEgYDVQQLDAtEZXZlbG9wbWVudDEYMBYGA1UEAwwPd3d3\n"                                                 \
"LndvbGZzc2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tggkA\n"                                                 \
"l7S9Fnj4R/IwDgYDVR0PAQH/BAQDAgOoMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoG\n"                                                 \
"CCqGSM49BAMCA0kAMEYCIQC+uFjw5BUBH99wVHNKbEAfd6i061Iev/UNsTPKasR2\n"                                                 \
"uQIhAJcI3iwowUVxtixUh5hjdqghNJCo954//AKw59MJMSfk\n"                                                                 \
"-----END CERTIFICATE-----\n"

static void test_wolf_secp256r1_key_exchange(void)
{
    test_key_exchange(&ptls_wolfcrypt_secp256r1, &ptls_wolfcrypt_secp256r1);
    test_key_exchange(&ptls_wolfcrypt_secp256r1, &ptls_minicrypto_secp256r1);
    test_key_exchange(&ptls_minicrypto_secp256r1, &ptls_wolfcrypt_secp256r1);
}

static void test_wolf_25519_key_exchange(void)
{
    test_key_exchange(&ptls_wolfcrypt_x25519, &ptls_wolfcrypt_x25519);
    test_key_exchange(&ptls_wolfcrypt_x25519, &ptls_minicrypto_x25519);
    test_key_exchange(&ptls_minicrypto_x25519, &ptls_wolfcrypt_x25519);
}

static int test_verify_cert_chain(X509_STORE *store, X509 *cert, STACK_OF(X509) * chain, int is_server, const char *server_name)
{
    X509_STORE_CTX *verify_ctx;
    int ret;
    int x509_err = 0;

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
    if ((x509_err = X509_verify_cert(verify_ctx)) != 1) {
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
        // case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT:
        // case X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY:
        // case X509_V_ERR_CERT_UNTRUSTED:
        // case X509_V_ERR_CERT_REJECTED:
        case ASN_NO_SIGNER_E:
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

static int test_do_sign(EVP_PKEY *key, ptls_buffer_t *outbuf, ptls_iovec_t input, const EVP_MD *md)
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
        printf("Can't use RSA key\n");
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
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

static int test_verify_sign(void *verify_ctx, ptls_iovec_t data, ptls_iovec_t signature)
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
        printf("Can't use RSA key\n");
        ret = PTLS_ERROR_LIBRARY;
        goto Exit;
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
    //EVP_PKEY_free(key);
    return ret;
}

static void test_ecdsa_sign(void)
{
    EVP_PKEY *pkey;

    // { /* create pkey */
    //     EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    //     EC_KEY_generate_key(eckey);
    //     pkey = EVP_PKEY_new();
    //     pkey->pkey.ptr = (char *)eckey;
    //     pkey->type = EVP_PKEY_EC;
    //     //EVP_PKEY_set1_EC_KEY(pkey, eckey);
    //     //EC_KEY_free(eckey);
    // }

    BIO* bio = BIO_new_file("../t/assets/ecc-key.pem", "rb");
    pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    // if (pkey == NULL) {
    //     DBG_PRINTF("%s", "failed to load private key");
    //     ret = -1;
    // }
    // else {
    //     ptls_openssl_sign_certificate_t* signer;

    //     signer = (ptls_openssl_sign_certificate_t*)malloc(sizeof(ptls_openssl_sign_certificate_t));

    //     if (signer == NULL || pkey == NULL) {
    //         ret = -1;
    //     } else {
    //         ret = ptls_openssl_init_sign_certificate(signer, pkey);
    //         ctx->sign_certificate = &signer->super;
    //     }

    //     if (ret != 0 && signer != NULL) {
    //         free(signer);
    //     }
    // }
    BIO_free(bio);

    const char *message = "hello world";
    ptls_buffer_t sigbuf;
    uint8_t sigbuf_small[1024];

    ptls_buffer_init(&sigbuf, sigbuf_small, sizeof(sigbuf_small));
    ok(test_do_sign(pkey, &sigbuf, ptls_iovec_init(message, strlen(message)), EVP_sha256()) == 0);
    //EVP_PKEY_up_ref(pkey);
    ok(test_verify_sign(pkey, ptls_iovec_init(message, strlen(message)), ptls_iovec_init(sigbuf.base, sigbuf.off)) == 0);

    ptls_buffer_dispose(&sigbuf);
    EVP_PKEY_free(pkey);
}

static X509 *x509_from_pem(const char *pem)
{
    BIO *bio = BIO_new_mem_buf((void *)pem, (int)strlen(pem));
    X509 *cert = PEM_read_bio_X509(bio, NULL, NULL, NULL);
    assert(cert != NULL && "failed to load certificate");
    BIO_free(bio);
    return cert;
}

static void test_cert_verify(void)
{
    X509 *cert = x509_from_pem(ECDSA_CERTIFICATE);
    STACK_OF(X509) *chain = sk_X509_new();
    X509_STORE *store = X509_STORE_new();
    int ret;

    /* expect fail when no CA is registered */
    ret = test_verify_cert_chain(store, cert, chain, 0, "test.example.com");
    ok(ret == PTLS_ALERT_UNKNOWN_CA);

    /* expect success after registering the CA */
    X509_LOOKUP *lookup = X509_STORE_add_lookup(store, X509_LOOKUP_file());
    ret = X509_LOOKUP_load_file(lookup, "../t/assets/ca-ecc-cert.pem", X509_FILETYPE_PEM);
    ok(ret==1);
    ret = test_verify_cert_chain(store, cert, chain, 0, "test.example.com");
    ok(ret == 0);

#ifdef X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS
    /* different server_name */
    ret = test_verify_cert_chain(store, cert, chain, 0, "test2.example.com");
    ok(ret == PTLS_ALERT_BAD_CERTIFICATE);
#else
    fprintf(stderr, "**** skipping test for hostname validation failure ***\n");
#endif

    X509_free(cert);
    sk_X509_free(chain);
    X509_STORE_free(store);
}

static void setup_certificate(ptls_iovec_t *dst)
{
    X509 *cert = x509_from_pem(ECDSA_CERTIFICATE);

    dst->base = NULL;
    dst->len = i2d_X509(cert, &dst->base);

    X509_free(cert);
}

static void setup_sign_certificate(ptls_openssl_sign_certificate_t *sc)
{
    BIO *bio = BIO_new_mem_buf(ECDSA_PRIVATE_KEY, (int)strlen(ECDSA_PRIVATE_KEY));
    EVP_PKEY *pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
    assert(pkey != NULL || !"failed to load private key");
    BIO_free(bio);

    ptls_openssl_init_sign_certificate(sc, pkey);

    //EVP_PKEY_free(pkey);
}

#if 0 /* Unimplemented */
static void test_secp256r1_sign(void)
{
    const char *msg = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef";
    ptls_minicrypto_secp256r1sha256_sign_certificate_t signer = {{secp256r1sha256_sign}};
    uint8_t pub[SECP256R1_PUBLIC_KEY_SIZE];
    uint16_t selected;
    ptls_buffer_t sigbuf;
    uint32_t sigbuf_small[128];

    uECC_make_key(pub, signer.key, uECC_secp256r1());
    ptls_buffer_init(&sigbuf, sigbuf_small, sizeof(sigbuf_small));

    ok(secp256r1sha256_sign(&signer.super, NULL, &selected, &sigbuf, ptls_iovec_init(msg, 32),
                            (uint16_t[]){PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256}, 1) == 0);
    ok(selected == PTLS_SIGNATURE_ECDSA_SECP256R1_SHA256);

    /* FIXME verify sign */

    ptls_buffer_dispose(&sigbuf);
}
#endif /* Unimplemented */

static void test_hrr_wolf(void)
{
    ptls_key_exchange_algorithm_t *client_keyex[] = {&ptls_wolfcrypt_x25519, &ptls_wolfcrypt_secp256r1, NULL};
    ptls_context_t client_ctx = {ptls_minicrypto_random_bytes, &ptls_get_time, client_keyex, ptls_wolfcrypt_cipher_suites};
    ptls_t *client, *server;
    ptls_buffer_t cbuf, sbuf, decbuf;
    uint8_t cbuf_small[16384], sbuf_small[16384], decbuf_small[16384];
    size_t consumed;
    int ret;

    assert(ctx_peer->key_exchanges[0] != NULL && ctx_peer->key_exchanges[0]->id == PTLS_GROUP_SECP256R1);
    assert(ctx_peer->key_exchanges[1] == NULL);

    client = ptls_new(&client_ctx, 0);
    server = ptls_new(ctx_peer, 1);
    ptls_buffer_init(&cbuf, cbuf_small, sizeof(cbuf_small));
    ptls_buffer_init(&sbuf, sbuf_small, sizeof(sbuf_small));
    ptls_buffer_init(&decbuf, decbuf_small, sizeof(decbuf_small));

    ret = ptls_handshake(client, &cbuf, NULL, NULL, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(consumed == cbuf.off);
    cbuf.off = 0;

    ok(sbuf.off > 5 + 4);
    ok(sbuf.base[5] == 2 /* PTLS_HANDSHAKE_TYPE_SERVER_HELLO (RETRY_REQUEST) */);

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == PTLS_ERROR_IN_PROGRESS);
    ok(consumed == sbuf.off);
    sbuf.off = 0;

    ok(cbuf.off >= 5 + 4);
    ok(cbuf.base[5] == 1 /* PTLS_HANDSHAKE_TYPE_CLIENT_HELLO */);

    consumed = cbuf.off;
    ret = ptls_handshake(server, &sbuf, cbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(consumed == cbuf.off);
    cbuf.off = 0;

    ok(sbuf.off >= 5 + 4);
    ok(sbuf.base[5] == 2 /* PTLS_HANDSHAKE_TYPE_SERVER_HELLO */);

    consumed = sbuf.off;
    ret = ptls_handshake(client, &cbuf, sbuf.base, &consumed, NULL);
    ok(ret == 0);
    ok(consumed == sbuf.off);
    sbuf.off = 0;

    ret = ptls_send(client, &cbuf, "hello world", 11);
    ok(ret == 0);

    consumed = cbuf.off;
    ret = ptls_receive(server, &decbuf, cbuf.base, &consumed);
    ok(ret == 0);
    ok(consumed == cbuf.off);
    cbuf.off = 0;

    ok(decbuf.off == 11);
    ok(memcmp(decbuf.base, "hello world", 11) == 0);

    ptls_buffer_dispose(&decbuf);
    ptls_buffer_dispose(&sbuf);
    ptls_buffer_dispose(&cbuf);
    ptls_free(client);
    ptls_free(server);
}

DEFINE_FFX_AES128_ALGORITHMS(wolfcrypt);
//DEFINE_FFX_CHACHA20_ALGORITHMS(wolfcrypt);

int main(int argc, char **argv)
{
    subtest("secp256r1", test_wolf_secp256r1_key_exchange);
    subtest("x25519", test_wolf_25519_key_exchange);
    //subtest("secp256r1-sign", test_secp256r1_sign);

    ptls_minicrypto_secp256r1sha256_sign_certificate_t minicrypto_sign_certificate;
    ptls_iovec_t minicrypto_certificate = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);
    ptls_minicrypto_init_secp256r1sha256_sign_certificate(
        &minicrypto_sign_certificate, ptls_iovec_init(SECP256R1_PRIVATE_KEY, sizeof(SECP256R1_PRIVATE_KEY) - 1));
    ptls_context_t minicrypto_ctx = {ptls_minicrypto_random_bytes,
                                     &ptls_get_time,
                                     ptls_minicrypto_key_exchanges,
                                     ptls_minicrypto_cipher_suites,
                                     {&minicrypto_certificate, 1},
                                     NULL,
                                     NULL,
                                     NULL,
                                     &minicrypto_sign_certificate.super};

    ptls_iovec_t cert2 = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);

    ptls_context_t wolfcrypt_ctx2 = {ptls_minicrypto_random_bytes,
                                    &ptls_get_time,
                                    ptls_wolfcrypt_key_exchanges,
                                    ptls_wolfcrypt_cipher_suites,
                                    {&cert2, 1},
                                    NULL,
                                    NULL,
                                    NULL,
                                    &minicrypto_sign_certificate.super};

    ctx = &wolfcrypt_ctx2;
    ctx_peer = &minicrypto_ctx;
    subtest("vs. minicrypto", test_picotls_wolf);

    ctx = &minicrypto_ctx;
    ctx_peer = &wolfcrypt_ctx2;
    subtest("minicrypto vs.", test_picotls_wolf);

    ptls_openssl_sign_certificate_t openssl_sign_certificate;
    ptls_openssl_verify_certificate_t openssl_verify_certificate;
    ptls_iovec_t cert;
    setup_certificate(&cert);
    setup_sign_certificate(&openssl_sign_certificate);
    X509_STORE *cert_store = X509_STORE_new();
    X509_LOOKUP *lookup = X509_STORE_add_lookup(cert_store, X509_LOOKUP_file());
    X509_LOOKUP_load_file(lookup, "../t/assets/ca-ecc-cert.pem", X509_FILETYPE_PEM);

    ptls_openssl_init_verify_certificate(&openssl_verify_certificate, cert_store);

    //ptls_iovec_t cert = ptls_iovec_init(SECP256R1_CERTIFICATE, sizeof(SECP256R1_CERTIFICATE) - 1);

    ptls_context_t wolfcrypt_ctx = {ptls_minicrypto_random_bytes,
                                    &ptls_get_time,
                                    ptls_wolfcrypt_key_exchanges,
                                    ptls_wolfcrypt_cipher_suites,
                                    {&cert, 1},
                                    NULL,
                                    NULL,
                                    NULL,
                                    &openssl_sign_certificate.super};
    ctx = ctx_peer = &wolfcrypt_ctx;
    ADD_FFX_AES128_ALGORITHMS(wolfcrypt);
    verify_certificate = &openssl_verify_certificate.super;
    //ADD_FFX_CHACHA20_ALGORITHMS(wolfcrypt);

    subtest("ecdsa-sign", test_ecdsa_sign);
    subtest("cert-verify", test_cert_verify);
    subtest("picotls", test_picotls_wolf);
    subtest("hrr", test_hrr_wolf);


    return done_testing();
    return done_testing();
}
