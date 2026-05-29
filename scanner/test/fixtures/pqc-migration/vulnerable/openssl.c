#include <openssl/rsa.h>
#include <openssl/evp.h>

int generate_rsa_key() {
  RSA *r = RSA_generate_key(2048, 65537, 0, 0);
  return r != 0;
}

int evp_keygen_rsa() {
  EVP_PKEY *pkey = 0;
  EVP_PKEY_CTX *ctx = 0;
  int type = EVP_PKEY_RSA;
  return type;
}
