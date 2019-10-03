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
#ifndef picotls_wolfcrypt_h
#define picotls_wolfcrypt_h

#ifdef __cplusplus
extern "C" {
#endif

#include "userq_settings.h"
#include "picotls.h"

#if defined(USE_WOLFSSL_AEAD)
extern ptls_cipher_algorithm_t ptls_wolfcrypt_aes128ctr, ptls_wolfcrypt_aes256ctr;
extern ptls_aead_algorithm_t ptls_wolfcrypt_aes128gcm, ptls_wolfcrypt_aes256gcm;
extern ptls_cipher_suite_t ptls_wolfcrypt_aes128gcmsha256, ptls_wolfcrypt_aes256gcmsha384;
extern ptls_cipher_suite_t *ptls_wolfcrypt_cipher_suites[];
#endif /* USE_WOLFSSL_AEAD */

extern ptls_hash_algorithm_t ptls_wolfcrypt_sha256, ptls_wolfcrypt_sha384;

#if defined(USE_WOLFSSL_KX)
#define SECP256R1_PRIVATE_KEY_SIZE 32
#define SECP256R1_PUBLIC_KEY_SIZE 65 /* including the header */
#define SECP256R1_SHARED_SECRET_SIZE 32

extern ptls_key_exchange_algorithm_t ptls_wolfcrypt_x25519, ptls_wolfcrypt_secp256r1;
extern ptls_key_exchange_algorithm_t *ptls_wolfcrypt_key_exchanges[];
#endif /* USE_WOLFSSL_KX */

#ifdef NO_FILESYSTEM
int wolfcrypt_load_certificates(ptls_context_t *ctx); 
#endif
#if 0

typedef struct st_ptls_wolfcrypt_secp256r1sha256_sign_certificate_t {
    ptls_sign_certificate_t super;
    uint8_t key[SECP256R1_PRIVATE_KEY_SIZE];
} ptls_wolfcrypt_secp256r1sha256_sign_certificate_t;

void ptls_wolfcrypt_random_bytes(void *buf, size_t len);

int ptls_wolfcrypt_init_secp256r1sha256_sign_certificate(ptls_wolfcrypt_secp256r1sha256_sign_certificate_t *self,
                                                          ptls_iovec_t key);

extern ptls_cipher_algorithm_t ptls_wolfcrypt_chacha20;
extern ptls_aead_algorithm_t ptls_wolfcrypt_chacha20poly1305;
extern ptls_cipher_suite_t ptls_wolfcrypt_chacha20poly1305sha256;

int ptls_wolfcrypt_load_private_key(ptls_context_t *ctx, char const *pem_fname);
#endif /* if 0 */

#ifdef __cplusplus
}
#endif

#endif /* picotls_wolfcrypt_h */