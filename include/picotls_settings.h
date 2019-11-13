/*
	user settings for picotls crypt library
*/

#define USE_WOLFSSL_KX
#define USE_WOLFSSL_AEAD
#define NO_PICOTLS_FILESYSTEM
#ifdef NO_PICOTLS_FILESYSTEM
#define TLS_ECDSA_CERT																								\
    "-----BEGIN CERTIFICATE-----\n"                                                           						\
    "MIIDUDCCAvWgAwIBAgICEAAwCgYIKoZIzj0EAwIwgZcxCzAJBgNVBAYTAlVTMRMw\n"                                            \
    "EQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMRAwDgYDVQQKDAd3\n"                                            \
    "b2xmU1NMMRQwEgYDVQQLDAtEZXZlbG9wbWVudDEYMBYGA1UEAwwPd3d3LndvbGZz\n"                                            \
    "c2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tMB4XDTE3MTAy\n"	                                        \
    "MDE4MTkwNloXDTI3MTAxODE4MTkwNlowgY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQI\n"                                            \
    "DApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMRAwDgYDVQQKDAdFbGlwdGlj\n"                                            \
    "MQwwCgYDVQQLDANFQ0MxGDAWBgNVBAMMD3d3dy53b2xmc3NsLmNvbTEfMB0GCSqG\n"                                            \
    "SIb3DQEJARYQaW5mb0B3b2xmc3NsLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEH\n"                                            \
    "A0IABLszrEwnUErGSqUEwzzenzbbci3OlOor+ssgCTksFuhhAumvTdMCk5oxW5eS\n"                                            \
    "IX/wzxjakRECNIboIFgzC4A0idijggE1MIIBMTAJBgNVHRMEAjAAMBEGCWCGSAGG\n"                                            \
    "+EIBAQQEAwIGQDAdBgNVHQ4EFgQUXV0m76x+NvmbdhUrSiUCI++yiTAwgcwGA1Ud\n"                                            \
    "IwSBxDCBwYAUVo6aw/BC3hi5RVVu+ZPP6sPzpSGhgZ2kgZowgZcxCzAJBgNVBAYT\n"                                            \
    "AlVTMRMwEQYDVQQIDApXYXNoaW5ndG9uMRAwDgYDVQQHDAdTZWF0dGxlMRAwDgYD\n"                                            \
    "VQQKDAd3b2xmU1NMMRQwEgYDVQQLDAtEZXZlbG9wbWVudDEYMBYGA1UEAwwPd3d3\n"                                            \
    "LndvbGZzc2wuY29tMR8wHQYJKoZIhvcNAQkBFhBpbmZvQHdvbGZzc2wuY29tggkA\n"                                            \
    "l7S9Fnj4R/IwDgYDVR0PAQH/BAQDAgOoMBMGA1UdJQQMMAoGCCsGAQUFBwMBMAoG\n"                                            \
    "CCqGSM49BAMCA0kAMEYCIQC+uFjw5BUBH99wVHNKbEAfd6i061Iev/UNsTPKasR2\n"                                            \
    "uQIhAJcI3iwowUVxtixUh5hjdqghNJCo954//AKw59MJMSfk\n"															\
    "-----END CERTIFICATE-----\n"

#define ECDSA_PRIVATE_KEY \
    "-----BEGIN EC PRIVATE KEY-----\n"                                                                              \
    "MHcCAQEEIEW2aQJznGyFoThbcujox6zEA41TNQT6bCjcNI3hqAmMoAoGCCqGSM49\n"                                            \
    "AwEHoUQDQgAEuzOsTCdQSsZKpQTDPN6fNttyLc6U6iv6yyAJOSwW6GEC6a9N0wKT\n"                                            \
    "mjFbl5Ihf/DPGNqREQI0huggWDMLgDSJ2A==\n"                                                                        \
    "-----END EC PRIVATE KEY-----\n"
#endif /* NO_PICOTLS_FILESYSTEM */

//#define USE_CIFRA
//#define _DEBUG

