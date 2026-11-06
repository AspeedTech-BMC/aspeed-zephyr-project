// #define MBEDTLS_ECDSA_VERIFY_ALT
#define MBEDTLS_ALLOW_PRIVATE_ACCESS

/*
 * libspdm's mbedTLS cryptlib parses X.509 certificates and EC public keys.
 * Zephyr's generic config only derives these from TLS key exchanges, so
 * enable the parsing stack directly instead of pulling in TLS.
 */
#define MBEDTLS_X509_USE_C
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_OID_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C

/*
 * libspdm's ec.c accesses mbedtls_ecdh_context fields (grp, d, Q, Qp, z)
 * directly. mbedTLS 3.6 only keeps that legacy layout when restartable ECP is
 * enabled, which is also what libspdm's own mbedTLS config does.
 *
 * mbedTLS 3.6 rejects ECP_RESTARTABLE together with ECP/ECDSA/ECDH _ALT
 * implementations or PSA-accelerated ECP, so enabling a hardware ECC driver
 * (e.g. through PSA) means revisiting this.
 */
#define MBEDTLS_ECP_RESTARTABLE

/*
 * libspdm's x509.c always compiles its CSR generator (unused here: CSR_CAP is
 * off and the linker drops it), so give it real declarations to build against.
 */
#define MBEDTLS_X509_CREATE_C
#define MBEDTLS_X509_CSR_WRITE_C
#define MBEDTLS_PK_WRITE_C
#define MBEDTLS_RSA_C
#define MBEDTLS_PKCS1_V15
#define MBEDTLS_PKCS1_V21
